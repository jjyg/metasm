require 'metasm/exe_format/coff'
require 'metasm/decode'

module Metasm
class COFF
	class Header
		def decode(coff)
			@machine  = coff.int_to_hash(coff.decode_half, MACHINE)
			@num_sect = coff.decode_half
			@time     = coff.decode_word
			@ptr_sym  = coff.decode_word
			@num_sym  = coff.decode_word
			@size_opthdr = coff.decode_half
			@characteristics = coff.bits_to_hash(coff.decode_half, CHARACTERISTIC_BITS)
			self
		end
	end

	class OptionalHeader
		def decode(coff)
			@sig = coff.int_to_hash(coff.decode_half, SIGNATURE)
			@linkv_maj  = coff.decode_uchar
			@linkv_min  = coff.decode_uchar
			@code_size  = coff.decode_word 
			@data_size  = coff.decode_word 
			@udata_size = coff.decode_word
			@entrypoint = coff.decode_word
			@base_of_code = coff.decode_word
			@base_of_data = coff.decode_word if @sig != 'PE+'
			@imagebase  = coff.decode_xword
			@sect_align = coff.decode_word
			@file_align = coff.decode_word
			@osv_maj    = coff.decode_half   
			@osv_min    = coff.decode_half   
			@imgv_maj   = coff.decode_half  
			@imgv_min   = coff.decode_half  
			@subsys_maj = coff.decode_half
			@subsys_min = coff.decode_half
			@reserved   = coff.decode_word  
			@image_size = coff.decode_word
			@headers_size = coff.decode_word
			@csum       = coff.decode_word
			@subsystem  = coff.int_to_hash(coff.decode_half, SUBSYSTEM)
			@dll_characts = coff.bits_to_hash(coff.decode_half, DLL_CHARACTERISTIC_BITS)
			@stackres_size = coff.decode_xword
			@stackcom_size = coff.decode_xword
			@heapres_size = coff.decode_xword
			@heapcom_size = coff.decode_xword
			@ldrflags   = coff.decode_word
			@numrva     = coff.decode_word

			if @numrva > DIRECTORIES.length
				puts "W: COFF: Invalid directories count #{@numrva}"
				return self
			end

			DIRECTORIES[0, @numrva].each { |dir|
				rva = coff.decode_word
				sz  = coff.decode_word
				if rva != 0 or sz != 0
					coff.directory[dir] = [rva, sz]
				end
			}
			self
		end
	end

	class Section
		def decode(coff)
			@name = coff.encoded.read(8)
			@name = @name[0, @name.index(0)] if @name.index(0)
			@virtsize   = coff.decode_word
			@virtaddr   = coff.decode_word
			@rawsize    = coff.decode_word
			@rawaddr    = coff.decode_word
			@relocaddr  = coff.decode_word
			@linenoaddr = coff.decode_word
			@relocnr    = coff.decode_half
			@linenonr   = coff.decode_half
			@characteristics = coff.bits_to_hash(coff.decode_word, SECTION_CHARACTERISTIC_BITS)
			self
		end
	end

	class ExportDirectory
		def decode(coff)
			@reserved   = coff.decode_word
			@timestamp  = coff.decode_word
			@version_major = coff.decode_half
			@version_minor = coff.decode_half
			dllname     = coff.decode_word
			@ordinal_base  = coff.decode_word
			num_exports = coff.decode_word
			num_names   = coff.decode_word
			addrtable   = coff.decode_word
			namptable   = coff.decode_word
			ord_table   = coff.decode_word

			if off = coff.rva_to_off(dllname)
				@dllname = coff.encoded.data[off...coff.encoded.data.index(0, off)]
			end

			if coff.encoded.ptr = coff.rva_to_off(addrtable)
				@exports = []
				num_exports.times { |i|
					e = Export.new
					e.ordinal = i + @ordinal_base
					addr = coff.decode_word
					if addr >= coff.directory['export_table'][0] and addr < coff.directory['export_table'][0] + coff.directory['export_table'][1]
						name = coff.encoded.data[addr...coff.encoded.data.index(0, addr)]
						e.forwarder_libname, name = name.split('.', 2)
						if name[0] == ?#
							e.forwarder_ordinal = name[1..-1].to_i
						else
							e.forwarder_name = name
						end
					else
						e.target = addr
					end
					@exports << e
				}
			end
			if coff.encoded.ptr = coff.rva_to_off(namptable)
				namep = []
				num_names.times { namep << coff.decode_word }
			end
			if coff.encoded.ptr = coff.rva_to_off(ord_table)
				ords = []
				num_names.times { ords << coff.decode_half }
			end
			if namep and ords
				namep.each_with_index { |np, i|
					if addr = coff.rva_to_off(np)
						@exports[ords[i]].name = coff.encoded.data[addr...coff.encoded.data.index(0, addr)]
					end
				}
			end

			self
		end
	end

	def decode_uchar(edata = @encoded) ; edata.decode_imm(:u8,  @endianness) end
	def decode_half( edata = @encoded) ; edata.decode_imm(:u16, @endianness) end
	def decode_word( edata = @encoded) ; edata.decode_imm(:u32, @endianness) end
	def decode_xword(edata = @encoded) ; edata.decode_imm((@optheader.sig == 'PE+' ? :u64 : :u32), @endianness) end

	def rva_to_off rva
		s = @sections.find { |s| s.virtaddr <= rva and s.virtaddr + s.virtsize > rva } if rva and rva != 0
		rva - s.virtaddr + s.rawaddr if s
	end

	def decode_header
		@header = Header.new.decode(self)
		(@optheader = OptionalHeader.new).decode(self)	# #decode uses decode_xword, which needs @optheader to exist
		@header.num_sect.times { @sections << Section.new.decode(self) }
		if off = rva_to_off(@optheader.entrypoint)
			@encoded.export['entrypoint'] = off
		end
	end

	def decode_exports
		if @directory['export_table'] and @encoded.ptr = rva_to_off(@directory['export_table'][0])
			@export = ExportDirectory.new.decode(self)
			@export.exports.each { |e|
				if e.name and off = rva_to_off(e.target)
					@encoded.export[e.name] = off
				end
			}
		end
	end

	def to_program
		decode_exports

		cpu = \
		case coff.header.machine
		when 'I386': Ia32.new
		end rescue nil
		cpu ||= UnknownCPU.new(32, :little)
		pgm = Program.new cpu

		@sections.each { |s|
			ps = Metasm::Section.new(pgm, s.name)
			ps.encoded << @encoded[s.rawaddr, s.rawsize]
			ps.encoded.virtsize += s.virtsize - s.rawsize
			ps.mprot.concat({
				'MEM_EXECUTE' => :exec, 'MEM_READ' => :read, 'MEM_WRITE' => :write, 'MEM_DISCARDABLE' => :discard, 'MEM_SHARED' => :shared
			}.values_at(*s.characteristics).compact)
			ps.base = s.virtaddr
			pgm.sections << ps
		}
		
		if @imports
			@imports.each { |id|
				pgm.import[id.libname] = []
				id.imports.each { |i|
					pgm.import[id.libname] << [i.name, nil]
				}
			}
		end

		if @export
			@export.exports.each { |e|
				pgm.export[e.name] = e.target if e.name and e.target
			}
		end

		pgm
	end
end

class LoadedCOFF < COFF
	def rva_to_off(rva)
		rva
	end
end
end

__END__
	class ImportDirectory
		def self.encode(coff, ary)
			edata = {}
			ary.each { |i| i.encode(coff, edata) }

			coff.directory['iat'] = [coff.label_at(edata['iat'], 0), edata['iat'].virtsize]
			coff.directory['import_table'] = [coff.label_at(edata['idata'], 0), edata['idata'].virtsize]

			EncodedData.new <<
			edata['idata'] <<
			coff.encode_word(0) <<
			coff.encode_word(0) <<
			coff.encode_word(0) <<
			coff.encode_word(0) <<
			coff.encode_word(0) <<
			edata['iat'] <<
			edata['nametable']
		end

		def encode(coff, edata)
			%w[idata iat nametable].each { |name| edata[name] ||= EncodedData.new }
			label = proc { |n| coff.label_at(edata[n], 0) }
			rva = proc { |n| Expression[label[n], :-, coff.label_at(coff.encoded, 0)] }
			rva_end = proc { |n| Expression[[label[n], :-, coff.label_at(coff.encoded, 0)], :+, edata[n].virtsize] }

			edata['idata'] <<
			coff.encode_word(rva_end['iat']) <<
			coff.encode_word(@timestamp ||= 0) <<
			coff.encode_word(@firstforwarder ||= 0) <<
			coff.encode_word(rva_end['nametable']) <<
			coff.encode_word(rva_end['iat'])

			edata['nametable'] << @libname << 0

			ord_mask = 1 << (coff.optheader.sig == 'PE+' ? 63 : 31)
			@imports.each { |i|
				if i.ordinal
					edata['iat'] << coff.encode_xword(Expression[i.ordinal, :|, ord_mask])
				else
					edata['iat'].export[i.name] = edata['iat'].virtsize

					edata['nametable'].align_size 2
					edata['iat'] << coff.encode_xword(rva_end['nametable'])
					edata['nametable'] << coff.encode_half(i.hint || 0) << i.name << 0
				end
			}
			edata['iat'] << coff.encode_xword(0)
		end
	end

	def self.from_program(program)
		coff = new
		coff.endianness = program.cpu.endianness
		coff.header = Header.new
		coff.optheader = OptionalHeader.new

		coff.header.machine = 'I386' if program.cpu.kind_of? Ia32
		coff.optheader.entrypoint = 'start'

		program.sections.each { |ps|
			s = Section.new
			s.name = ps.name
			s.encoded = ps.encoded
			s.characteristics = {
				:exec => 'MEM_EXECUTE', :read => 'MEM_READ', :write => 'MEM_WRITE', :discard => 'MEM_DISCARDABLE', :shared => 'MEM_SHARED'
			}.values_at(*ps.mprot).compact
			coff.sections << s
		}

		program.import.each { |libname, list|
			coff.imports ||= []
			id = ImportDirectory.new
			id.libname = libname
			list.each { |name, thunk|
				i = ImportDirectory::Import.new
				i.name = name
				id.imports << i
			}
			coff.imports << id
		}

		if not program.export.empty?
			coff.export = ExportDirectory.new
			coff.export.name = 'kikoo'
			program.export.each { |name, label|
				e = ExportDirectory::Export.new
				e.name = name
				e.target = label
				coff.export.exports << e
			}
		end

		coff
	end
end
end

__END__

	def encode_fix_checksum(data, endianness = :little)
		# may not work with overlapping sections

		long, short, shorts = \
		case endianness
		when :little: ['V', 'v', 'v*']
		when :big: ['N', 'n', 'n*']
		end

		# check we have a valid PE
		return if data[0, 2] != 'MZ'
		off = data[0x3c, 4].unpack(long).first
		return if data[off, 4] != "PE\0\0"
		off += 4

		# read some header information
		csumoff = off + 0x14 + 0x40
		secoff  = off + 0x14 + data[off+0x10, 2].unpack(short).first
		secnum  = data[off+2, 2].unpack(short).first

		sum = 0
		flen = 0

		# header
		# patch csum at 0
		data[csumoff, 4] = [0].pack(long)
		curoff  = 0
		cursize = data[off+0x14+0x3c, 4].unpack(long).first
		data[curoff, cursize].unpack(shorts).each { |s|
			sum += s
			sum = (sum & 0xffff) + (sum >> 16) if (sum >> 16) > 0
		}
		flen += cursize

		# sections
		secnum.times { |n|
			cursize, curoff = data[secoff + 0x28*n + 0x10, 8].unpack(long + long)
			data[curoff, cursize].unpack(shorts).each { |s|
				sum += s
				sum = (sum & 0xffff) + (sum >> 16) if (sum >> 16) > 0
			}
			flen += cursize
		}
		sum += flen

		# patch good value
		data[csumoff, 4] = [sum].pack(long)
	end

	# opts:
	# 	'pe_target'         in ['exe', 'dll', 'kmod', 'obj']
	# 	'pe_format'         in ['PE', 'PE+']
	# 	'directories'       hash of directory_name (from Directories) => [start_label, size_in_bytes] (label found in some program.section)
	# 	'pre_header'        EncodedData to be prepended to the Coff header, the RVA of its first byte is 0
	# 	'no_merge_sections' set to true if you don't want sections to be merged (implies no_merge_dirs)
	# 	'strip_base_relocs' set to true to exclude base relocation information
	# 	'resources'         hash to compile as resources directories
	# 	and misc values to initialize most Coff header members
	def xxxencode(program, opts={})
		pe_format = opts.delete('pe_format') || 'PE'
		pe_target = opts.delete('pe_target') || 'exe'
		directories = opts.delete('directories') || {}

		# build initial section list (mutable to allow section merge)
		pe_sections = program.sections.inject([]) { |pe_sections, sect|
			s = Section.new(sect.name.dup)
			s.edata = sect.encoded.dup
			s.base = sect.base
			s.align = sect.align || program.cpu.size/8
			s.characteristics = sect.mprot.map { |prot|
				case prot
				when :exec:    'MEM_EXECUTE'
				when :read:    'MEM_READ'
				when :write:   'MEM_WRITE'
				when :discard: 'MEM_DISCARDABLE'
				when :shared:  'MEM_SHARED'
				end
			}.compact

			pe_sections << s
		}

		canmerge = ! opts.delete('no_merge_sections')

		if canmerge and pe_target != 'obj'
			# merge sections whose name include '$'
			pe_sections.sort_by { |s| s.name }.each { |s|
				if s.name.include? '$'
					newname = s.name[/.*(?=\$)/]
					if ss = pe_sections.find { |ss| ss.name == newname }
						pe_sections.delete s
						ss.edata << s.edata
						s.characteristics.delete 'MEM_DISCARDABLE' unless ss.characteristics.include? 'MEM_DISCARDABLE'
						ss.characteristics |= s.characteristics
					else
						s.name = newname
					end
				end
			}
		end

		# rva of <stuff> = <stuff> - program_start
		program_start = opts.delete('program_start_label') || program.new_unique_label

		# build idata/edata
		pre_encode_imports(program, program_start, pe_format, pe_sections, directories, opts) unless directories.has_key?('import_table') or program.import.empty?
		#pre_encode_delayimports(program, program_start, pe_format, pe_sections, directories, opts) unless directories.has_key?('delay_import') or program.import.empty?
		pre_encode_resources(program, program_start, opts.delete('resources'), pe_sections, directories, opts) unless directories.has_key?('resource_table') or not opts['resources']

		merge_sections(pe_sections, pe_target, opts) if canmerge

		# base relocation table
		# relocs should not work unless sections are page-aligned (unless the dynamic loader accepts non-page-aligned base relocation adresses)
		if not opts.delete('strip_base_relocs') and not directories.has_key?('base_relocation_table')
			pre_encode_relocs(program, program_start, pe_sections, directories, opts)

			# merge section
			if canmerge and d = directories['base_relocation_table'] and d[1] < 0x1000 and
					s = pe_sections[0..-2].find { |s| (s.virtsize + d[1] + 7) / 0x1000 == s.rawsize / 0x1000 }
				s.edata.align_size pe_sections.last.align
				s.edata << pe_sections.pop.edata
			end
		end

		# fix sections characteristics
		pe_sections.each { |s|
			s.characteristics <<
			if s.characteristics.include? 'MEM_EXECUTE': 'CONTAINS_CODE'
			elsif s.edata.data.empty?: 'CONTAINS_UDATA'
			else  'CONTAINS_DATA'
			end
		}

		# encode coff header and section table, prepend its pseudo-section to pe_sections
		# sections raw addresses are pseudo-labels to bind at link time, stored in section.rawoffset
		pre_encode_header(program, program_start, pe_format, pe_target, pe_sections, directories, opts)

		pe_sections.first.edata.export[program_start] = 0

		coff = link pe_sections, opts

		puts "unused COFF options: #{opts.keys.sort_by { |k| k.to_s }.inspect}" unless opts.empty?

		coff
	end

	def link(pe_sections, opts)
		baseaddr = opts.delete('prefered_base_address') || 0x400000

		binding = {}
		rva = rawoff = 0
		pe_sections.each { |s|
			s.edata.export.each { |name, off| binding[name] = baseaddr + rva + off }

			binding[s.rawoffset] = rawoff if s.rawoffset != 0

			rawoff += s.rawsize_align
			rva += s.virtsize_align
			rawoff += s.virtsize_align - s.rawsize_align if rva & 0xfff != 0
		}

		pe_sections.each { |s| s.edata.fixup(binding) }

		unresolved = pe_sections.map { |s| s.edata.reloc.values }.flatten
		raise EncodeError, "Unresolved relocations: #{unresolved.map { |rel| rel.target }.inspect }" unless unresolved.empty?

		pe_sections.inject(EncodedData.new) { |total, s|
			total.fill(binding[s.rawoffset]) if s.rawoffset != 0
			s.edata.fill(s.rawsize_align)
			total << s.edata.data
		}.data
	end

	def merge_sections(pe_sections, pe_target, opts)
		# XXX requested alignment
			
		dc = proc { |s1, s2| (s1.characteristics - s2.characteristics).length }

		mergesections = proc { |sectionlist|
			sectionlist.dup.reverse_each { |cur|
				if cur.rawsize < 0x800 and sectionlist.length >= 2 and not cur.base
					sectionlist.delete cur
					pe_sections.delete cur
					target = sectionlist.sort_by { |s| (dc[s, cur] + dc[cur, s]) * 0x1000 + s.virtsize - s.rawsize }.first
					target.edata.align_size cur.align
					target.align = [target.align, cur.align].max
					target.edata << cur.edata
					cur.characteristics.delete 'MEM_DISCARDABLE' unless target.characteristics.include? 'MEM_DISCARDABLE'
					target.characteristics |= cur.characteristics
				end
			}
		}

		# optimize size by merging sections with compatible mprot
		# do not merge non-shared with shared
		pe_sections.partition { |s| s.characteristics.include? 'MEM_SHARED' }.each { |subsections|
			subsections.partition { |s| s.rawsize == 0 }.each { |subsections|
				# do not merge discardable with non discardable if there is more than 1 page of discardable
				if subsections.find_all { |s| s.characteristics.include? 'MEM_DISCARDABLE' }.map { |s| s.rawsize }.inject(0) { |a, b| a+b } >= 0x1000
					subsections.partition { |s| s.characteristics.include? 'MEM_DISCARDABLE' }.each(&mergesections)
				else
					mergesections[subsections]
				end
			}
		}
	end


	def pre_encode_imports(program, program_start, pe_format, pe_sections, directories, opts)
		# initialize label and encodeddata tables
		edata = {}
		label = {}
		%w[idata iat nametable].each { |name|
			label[name] = program.new_unique_label
			edata[name] = EncodedData.new '', :export => {label[name] => 0}
		}

		# macros
		encode = proc { |name, type, expr|
			edata[name] << Expression[*expr].encode(type, program.cpu.endianness)
		}
		rva = proc { |name| [label[name], :-, program_start] }
		rva_end = proc { |name| [[label[name], :-, program_start], :+, edata[name].virtsize] }
		vlen = (pe_format == 'PE') ? :u32 : :u64

		# build tables
		program.import.each { |libname, importlist|
			encode['idata', :u32, rva_end['iat']]
			encode['idata', :u32, 0]	# timestamp (set by loader)
			encode['idata', :u32, 0]	# first forwarder index (set by loader ?)
			encode['idata', :u32, rva_end['nametable']]
			encode['idata', :u32, rva_end['iat']]
			edata['nametable'] << libname << 0

			importlist.each { |importname, thunkname|
				importname_label = importname
				if thunkname and not pe_sections.find { |s| s.edata.export[thunkname] }
					importname_label = program.new_unique_label if importname == thunkname
					thunk_section = pe_sections.find { |s| s.characteristics.include? 'MEM_EXECUTE' } or
					raise EncodeError, "unable to find an executable section to append import thunks"
					thunk_section.edata.export[thunkname] = thunk_section.virtsize
					thunk_section.edata << program.cpu.encode_thunk(program, importname_label)
				end

				edata['iat'].export[importname_label] = edata['iat'].virtsize
				if importname =~ ORDINAL_REGEX
					# import by ordinal: set high bit to 1 and encode ordinal in low 16bits
					ordnumber = $1.to_i
					ordnumber |= 1 << ((pe_format == 'PE+') ? 63 : 31)
					encode['iat', vlen, ordnumber]
				else
					# import by name: put hint+name rva in low 31bits (even in PE+)
					edata['nametable'].align_size 2
					encode['iat', vlen, rva_end['nametable']]
					encode['nametable', :u16, 0]	# ordinal hint
					edata['nametable'] << importname << 0
				end
			}
			encode['iat', :u32, 0]
		}

		# last entry must be null
		5.times { encode['idata', :u32, 0] }

		# commit
		s = Section.new '.idata'
		s.align = 8
		s.edata = EncodedData.new
		s.characteristics = %w[MEM_READ MEM_WRITE]
		pe_sections << s

		s.edata << edata['iat'] << edata['idata'] << edata['nametable']
		directories['iat'] = [label['iat'], edata['iat'].virtsize]
		directories['import_table'] = [label['idata'], edata['idata'].virtsize]
	end

	def pre_encode_delayimports(program, program_start, pe_format, pe_sections, directories, opts)
		# initialize label and encodeddata tables
		edata = {}
		label = {}
		%w[idata iat nametable].each { |name|
			label[name] = program.new_unique_label
			edata[name] = EncodedData.new '', :export => {label[name] => 0}
		}

		# macros
		encode = proc { |name, type, expr|
			edata[name] << Expression[*expr].encode(type, program.cpu.endianness)
		}
		rva = proc { |name| [label[name], :-, program_start] }
		rva_end = proc { |name| [[label[name], :-, program_start], :+, edata[name].virtsize] }
		vlen = (pe_format == 'PE') ? :u32 : :u64

		# build tables
		program.import.each { |libname, importlist|
			encode['idata', :u32, 0]		# attributes (reserved)
			encode['idata', :u32, rva_end['nametable']]
			edata['nametable'] << libname << 0
			encode['idata', :u32, 0]		# module handle
			encode['idata', :u32, rva_end['iat']]	# iat
			edata['nametable'].align_size 2
			encode['idata', :u32, rva_end['nametable']]	# name table ?
			encode['idata', :u32, 0]		# bound iat
			encode['idata', :u32, 0]		# unload iat (copy of biat)

			importlist.each { |importname, thunkname|
				importname_label = importname
				if thunkname and not pe_sections.find { |s| s.edata.export[thunkname] }
					importname_label = program.new_unique_label if importname == thunkname
					thunk_section = pe_sections.find { |s| s.characteristics.include? 'MEM_EXECUTE' } or
					raise EncodeError, "unable to find an executable section to append import thunks"
					thunk_section.edata.export[thunkname] = thunk_section.virtsize
					thunk_section.edata << program.cpu.encode_thunk(program, importname_label)
				end

				edata['iat'].export[importname_label] = edata['iat'].virtsize
				if importname =~ ORDINAL_REGEX
					# import by ordinal: set high bit to 1 and encode ordinal in low 16bits
					ordnumber = $1.to_i
					ordnumber |= 1 << ((pe_format == 'PE+') ? 63 : 31)
					encode['iat', vlen, ordnumber]
				else
					# import by name: put hint+name rva in low 31bits (even in PE+)
					edata['nametable'].align_size 2
					encode['iat', vlen, rva_end['nametable']]
					encode['nametable', :u16, 0]	# ordinal hint
					edata['nametable'] << importname << 0
				end
			}
			encode['iat', :u32, 0]
		}

		# last entry must be null
		7.times { encode['idata', :u32, 0] }

		# commit
		s = Section.new '.idata'
		s.align = 8
		s.edata = EncodedData.new
		s.characteristics = %w[MEM_READ MEM_WRITE]
		pe_sections << s

		s.edata << edata['iat'] << edata['idata'] << edata['nametable']
		directories['bound_import'] = [label['iat'], edata['iat'].virtsize]
		directories['delay_import'] = [label['idata'], edata['idata'].virtsize]
	end

	def pre_encode_relocs(program, program_start, pe_sections, directories, opts)

		relocs = EncodedData.new

		# create a binding with fake rva for sections (all null)
		binding = pe_sections.inject({}) { |binding, s|
			s.edata.export.inject(binding) { |binding, (name, off)|
				binding.update name => Expression[program_start, :+, off]
			}
		}

		pe_sections.each { |s|
			# find all relocs needing a base relocation entry
			# may miss weird relocs if the fake binding happens to oversimplify the target (ex: (a-b+4)*foo and binding[a] - binding[b] + 4 == 0)
			reloclist = s.edata.reloc.map { |off, rel|
				fakerel = rel.target.bind(binding).reduce
				if fakerel.kind_of? Integer
				elsif fakerel.op == :+ and (
						(fakerel.lexpr == program_start and fakerel.rexpr.kind_of? Integer) or
						(not fakerel.lexpr and fakerel.rexpr == program_start))
					if rel.endianness == program.cpu.endianness
						[off, rel.type]
					else puts "skip bad relocation endianness #{rel.inspect} at #{s.name}:+#{off}"
					end
				else  puts "skip weird relocation #{rel.inspect} ( red to #{fakerel.inspect} ) at #{s.name}:+#{off}"
				end
			}.compact.sort
			next if reloclist.empty?

			label = program.label_at(s.edata, 0)

			# <XXX warn="this is x86 specific">
			reloclist << [0, 0] if reloclist.length % 2 == 1	# align
			relocs << Expression[label, :-, program_start].encode(:u32, program.cpu.endianness)
			relocs << Expression[8, :+, 2*reloclist.length].encode(:u32, program.cpu.endianness)
			reloclist.each { |off, type|
				type = case type
				when :u64, :i64: 10
				when :u32, :i32: 3
				when :u16, :i16: 2	# XXX allowed ?
				when 0: 0	# pad
				else raise EncodeError, "Relocation of unknown type #{type.inspect} at #{s.name}:+#{off}"
				end
				relocs << Expression[[off, :&, 0x0fff], :|, type << 12].encode(:u16, program.cpu.endianness)
			}
			# </XXX>

		}

		return if relocs.virtsize == 0

		s = Section.new '.reloc'
		s.align = 4
		s.edata = relocs
		s.characteristics = %w[MEM_READ MEM_DISCARDABLE]
		pe_sections << s

		directories['base_relocation_table'] = [program.label_at(relocs, 0), relocs.virtsize]
	end

	def pre_encode_header(program, program_start, pe_format, pe_target, pe_sections, directories, opts)

		raise 'COFF obj format not supported yet' if pe_target == 'obj'	 # TODO

		header = EncodedData.new
		header << (opts.delete('pre_header') || '')

		# macros
		encode = proc { |type, expr|
			header << Expression[*expr].encode(type, program.cpu.endianness)
		}
		rva = proc { |label| label == 0 ? 0 : [label, :-, program_start] }
		align = proc { |base, _align| (base + _align - 1) / _align * _align }
		vlen = (pe_format == 'PE') ? :u32 : :u64

		section_align = opts.delete('section_align') || 0x1000
#			if pe_sections.inject(0) { |size, s| size + s.rawsize } > 0x2000: 0x1000
#			elsif pe_target == 'kmod': 0x80
#			else 0x200
#			end
		file_align = opts.delete('file_align') || (pe_target == 'kmod' ? 0x80 : 0x200)

		# section_align = [section_align, *program.sections.map { |s| s.align.to_i }].max	# TODO do not ignore source-specified align
		# labels
		start_optheader = program.new_unique_label
		end_optheader   = program.new_unique_label
		end_header	= program.new_unique_label
		end_image	= program.new_unique_label

			
			# Directories
			DIRECTORIES[0..tmp].each { |dir|
				if tmp = directories[dir]
					encode[:u32, rva[tmp[0]]]
					encode[:u32, tmp[1]]
				else
					encode[:u32, 0]
					encode[:u32, 0]
				end
			}
		end
		header.export[end_optheader] = header.virtsize

		# Section table
		pe_sections.each { |s|
			s.rawoffset = (s.rawsize > 0 ? program.new_unique_label : 0)
			s.rawsize_align = align[s.rawsize, file_align]
			s.virtsize_align = align[s.virtsize, section_align]

			header << s.name[0..7].ljust(8, "\0")
			encode[:u32, s.virtsize]
			tmp = program.label_at(s.edata, 0)
			encode[:u32, rva[tmp]]
			encode[:u32, s.rawsize_align]
			encode[:u32, s.rawoffset]
			encode[:u32, 0]	# relocs rva
			encode[:u32, 0]	# lineno rva
			encode[:u16, 0]	# relocs nr
			encode[:u16, 0]	# lineno nr
			tmp = s.characteristics.inject(0) { |int, char|  int | SECTION_CHARACTERISTIC_BITS.index(char) }
			encode[:u32, tmp]
		}

		s = Section.new nil
		s.edata = header
		s.virtsize_align = align[s.virtsize, section_align]
		s.rawsize_align = align[s.virtsize, file_align]
		pe_sections.unshift s

		pe_sections.first.edata.export[end_header] = pe_sections.first.rawsize_align
		pe_sections.last.edata.export[end_image]   = pe_sections.last.virtsize_align
	end

	module Resource
	# TODO
	# cursor = raw data, cursor_group = header , pareil pour les icons
	class Cursor
		def encode(endianness)	# XXX
			EncodedData.new <<
			Expression[@xhotspot.to_i].encode(:u16, endianness) <<
			Expression[@yhotspot.to_i].encode(:u16, endianness) <<
			Expression[@data.length  ].encode(:u32, endianness) <<
			@data
		end
	end
	end

	# compiles ressource directories
	# rsrc: { 'foo' => { 'bar' => 'baz', 4 => 'lol' }, 'quux' => 'blabla' }
	# keys must be either Strings or Integers, the encoder won't work otherwise
	def pre_encode_resources(program, program_start, rsrc, pe_sections, directories, opts)
		edata = {}
		label = {}
		%w[nametable datatable data].each { |name|
			edata[name] = EncodedData.new
			label[name] = program.label_at(edata[name], 0)
		}
		label['directory'] = program.new_unique_label

		encode  = proc { |name, type, expr| edata[name] << Expression[*expr].encode(type, program.cpu.endianness) }
		encode_ = proc { |edat, type, expr| edat << Expression[*expr].encode(type, program.cpu.endianness) }
		rva_end = proc { |name| [[label[name], :-, program_start], :+, edata[name].virtsize] }
		off_end = proc { |name| [[label[name], :-, label['directory']], :+, edata[name].virtsize] }

		recurs_encode = proc { |dir, curoffset|
			# curoffset is the current length of the directory table
			ed = EncodedData.new
			encode_[ed, :u32, opts['rsrc_characteristics'] || 0]
			encode_[ed, :u32, opts['rsrc_timestamp']       || Time.now.to_i]
			encode_[ed, :u16, opts['rsrc_version_major']   || 0]
			encode_[ed, :u16, opts['rsrc_version_minor']   || 0]
			encode_[ed, :u16, dir.keys.grep(String ).length]
			encode_[ed, :u16, dir.keys.grep(Integer).length]

			curoffset += 4+4+2+2+2+2 + dir.length*8
			nextdirs = []

			(dir.keys.grep(String).sort_by { |name| name.downcase } + dir.keys.grep(Integer).sort).each { |name|
				case name
				when String
					encode_[ed, :u32, [off_end['nametable'], :|, 1<<31]]

					encode['nametable', :u16, name.length]
					name.each_byte { |c| encode['nametable', :u16, c] }	# utf16
				when Integer
					encode_[ed, :u32, name]
				end

				data = dir[name]
				if data.kind_of? Hash
					# subdirectory
					nextdirs << recurs_encode[data, curoffset]
					encode_[ed, :u32, curoffset | (1<<31)]
					curoffset += nextdirs.last.virtsize
				else
					encode_[ed, :u32, off_end['datatable']]
					
					encode['datatable', :u32, rva_end['data']]
					encode['datatable', :u32, data.size]
					encode['datatable', :u32, 0]	# codepage...
					encode['datatable', :u32, 0]	# reserved

					edata['data'] << data
				end
			}
			nextdirs.inject(ed) { |ed, nd| ed << nd }
		}

		s = Section.new '.rsrc'
		s.edata = recurs_encode[rsrc, 0] << edata['nametable'] << edata['datatable'] << edata['data']
		s.edata.export[label['directory']] = 0
		s.characteristics = %w[MEM_READ]
		pe_sections << s

		directories['resource_table'] = [label['directory'], s.edata.virtsize]
	end
end
end
