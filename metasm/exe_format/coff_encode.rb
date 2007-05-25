require 'metasm/exe_format/coff'
require 'metasm/encode'

module Metasm
class COFF
	class Header
		def encode(coff, opth)
			set_default_values coff, opth

			coff.encode_half(coff.int_from_hash(@machine, MACHINE)) <<
			coff.encode_half(@num_sect) <<
			coff.encode_word(@time) <<
			coff.encode_word(@ptr_sym) <<
			coff.encode_word(@num_sym) <<
			coff.encode_half(@size_opthdr) <<
			coff.encode_half(coff.bits_from_hash(@characteristics, CHARACTERISTIC_BITS))
		end

		def set_default_values(coff, opth)
			@machine     ||= 'UNKNOWN'
			@num_sect    ||= coff.sections.length
			@time        ||= Time.now.to_i
			@ptr_sym     ||= 0
			@num_sym     ||= 0
			@size_opthdr ||= opth.virtsize
			@characteristics ||= 0
		end
	end

	class OptionalHeader
		def encode(coff)
			set_default_values coff

			opth = \
			coff.encode_half(coff.int_from_hash(@sig, SIGNATURE)) <<
			coff.encode_uchar(@linkv_maj) <<
			coff.encode_uchar(@linkv_min) <<
			coff.encode_word(@code_size)  <<
			coff.encode_word(@data_size)  <<
			coff.encode_word(@udata_size) <<
			coff.encode_word(@entrypoint) <<
			coff.encode_word(@base_of_code) <<
			(coff.encode_word(@base_of_data) if @sig != 'PE+') <<
			coff.encode_xword(@imagebase) <<
			coff.encode_word(@sect_align) <<
			coff.encode_word(@file_align) <<
			coff.encode_half(@osv_maj)    <<
			coff.encode_half(@osv_min)    <<
			coff.encode_half(@imgv_maj)   <<
			coff.encode_half(@imgv_min)   <<
			coff.encode_half(@subsys_maj) <<
			coff.encode_half(@subsys_min) <<
			coff.encode_word(@reserved)   <<
			coff.encode_word(@image_size) <<
			coff.encode_word(@headers_size) <<
			coff.encode_word(@csum) <<
			coff.encode_half(coff.int_from_hash(@subsystem, SUBSYSTEM)) <<
			coff.encode_half(coff.bits_from_hash(@dll_characts, DLL_CHARACTERISTIC_BITS)) <<
			coff.encode_xword(@stackres_size) <<
			coff.encode_xword(@stackcom_size) <<
			coff.encode_xword(@heapres_size) <<
			coff.encode_xword(@heapcom_size) <<
			coff.encode_word(@ldrflags) <<
			coff.encode_word(@numrva)

			DIRECTORIES[0, @numrva].each { |d|
				if d = coff.directory[d]
					d = d.dup
					d[0] = Expression[d[0], :-, coff.label_at(coff.encoded, 0)] if d[0] != 0
				else
					d = [0, 0]
				end
				opth << coff.encode_word(d[0]) << coff.encode_word(d[1])
			}

			opth
		end

		def set_default_values(coff)
			@sig          ||= 'PE'
			@linkv_maj    ||= 1
			@linkv_min    ||= 0
			@sect_align   ||= 0x1000
			align = proc { |sz| (sz + @sect_align - 1) / @sect_align * @sect_align }
			@code_size    ||= coff.sections.find_all { |s| s.characteristics.include? 'CONTAINS_CODE' }.inject(0) { |sum, s| sum + align[s.virtsize] }
			@data_size    ||= coff.sections.find_all { |s| s.characteristics.include? 'CONTAINS_DATA' }.inject(0) { |sum, s| sum + align[s.virtsize] }
			@udata_size   ||= coff.sections.find_all { |s| s.characteristics.include? 'CONTAINS_UDATA' }.inject(0) { |sum, s| sum + align[s.virtsize] }
			@entrypoint = Expression[@entrypoint, :-, coff.label_at(coff.encoded, 0)] if @entrypoint
			@entrypoint   ||= 0
			@base_of_code ||= (coff.label_at(coff.sections.find { |s| s.characteristics.include? 'CONTAINS_CODE' }.encoded, 0) rescue 0)
			@base_of_data ||= (coff.label_at(coff.sections.find { |s| s.characteristics.include? 'CONTAINS_DATA' }.encoded, 0) rescue 0)
			@imagebase    ||= 0x400000
			@file_align   ||= 0x200
			@osv_maj      ||= 4
			@osv_min      ||= 0
			@imgv_maj     ||= 0
			@imgv_min     ||= 0
			@subsys_maj   ||= 4
			@subsys_min   ||= 0
			@reserved     ||= 0
			@image_size   ||= coff.new_label
			@headers_size ||= coff.new_label
			@csum         ||= 0
			@subsystem    ||= 'WINDOWS_GUI'
			@dll_characts ||= 0
			@stackres_size||= 0x100000
			@stackcom_size||= 0x1000
			@heapres_size ||= 0x100000
			@heapcom_size ||= 0x1000
			@ldrflags     ||= 0
			@numrva       ||= DIRECTORIES.length
		end
	end

	class Section
		def encode(coff)
			set_default_values(coff)

			EncodedData.new(@name[0, 8].ljust(8, "\0")) <<
			coff.encode_word(@virtsize) <<
			coff.encode_word(@virtaddr) <<
			coff.encode_word(@rawsize) <<
			coff.encode_word(@rawaddr) <<
			coff.encode_word(@relocaddr) <<
			coff.encode_word(@linenoaddr) <<
			coff.encode_half(@relocnr) <<
			coff.encode_half(@linenonr) <<
			coff.encode_word(coff.bits_from_hash(@characteristics, SECTION_CHARACTERISTIC_BITS))
		end

		def set_default_values(coff)
			@name ||= ''
			@virtsize ||= @encoded.virtsize
			@virtaddr ||= Expression[coff.label_at(@encoded, 0), :-, coff.label_at(coff.encoded, 0)]
			@rawsize  ||= (@encoded.rawsize + coff.optheader.file_align - 1) / coff.optheader.file_align * coff.optheader.file_align
			@rawaddr  ||= coff.new_label
			@relocaddr ||= 0
			@linenoaddr ||= 0
			@relocnr  ||= 0
			@linenonr ||= 0
			@characteristics ||= 0
		end
	end

	class ExportDirectory
		def encode(coff)
			set_default_values coff

			edata = {}
			%w[edata addrtable namptable ord_table dllname nametable].each { |name|
				edata[name] = EncodedData.new
			}
			label = proc { |n| coff.label_at(edata[n], 0) }
			rva = proc { |n| Expression[label[n], :-, coff.label_at(coff.encoded, 0)] }
			rva_end = proc { |n| Exprennsion[[label[n], :-, coff.label_at(coff.encoded, 0)], :+, edata[n].virtsize] }

			edata['edata'] <<
			coff.encode_word(@reserved) <<
			coff.encode_word(@timestamp) <<
			coff.encode_half(@version_major) <<
			coff.encode_half(@version_minor) <<
			coff.encode_word(rva['dllname']) <<
			coff.encode_word(@ordinal_base) <<
			coff.encode_word(@exports.length) <<
			coff.encode_word(@exports.find_all { |e| e.name }.length) <<
			coff.encode_word(rva['addrtable']) <<
			coff.encode_word(rva['namptable']) <<
			coff.encode_word(rva['ord_table'])

			edata['dllname'] << @dllname << 0

			# TODO handle e.ordinal (force export table order, or invalidate @ordinal)
			@exports.sort_by { |e| e.name.to_s }.each { |e|
				if e.forwarder_lib
					edata['addrtable'] << coff.encode_word(rva_end['nametable'])
					edata['nametable'] << e.forwarder_lib << ?. <<
					if not e.forwarder_name
						"##{e.forwarder_ordinal}"
					else
						e.forwarder_name
					end << 0
				else
					edata['addrtable'] << coff.encode_word(Expression[e.target, :-, coff.label_at(coff.encoded, 0)])
				end
				if e.name
					edata['ord_table'] << coff.encode_half(edata['addrtable'].virtsize/4 - @ordinal_base)
					edata['namptable'] << coff.encode_word(rva_end['nametable'])
					edata['nametable'] << e.name << 0
				end
			}
			
			coff.directory['export_table'] = [coff.label_at(edata, 0), edata.virtsize]

			# sorted by alignment directives
			%w[edata addrtable namptable ord_table dllname nametable].inject(EncodedData.new) { |ed, name| ed << edata[name] }
		end

		def set_default_values(coff)
			@reserved ||= 0
			@timestamp ||= Time.now.to_i
			@version_major ||= 0
			@version_minor ||= 0
			@dllname ||= 'metalib'
			@ordinal_base ||= 1
		end
	end

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


	def encode_uchar(w)  Expression[w].encode(:u8,  @endianness) end
	def encode_half(w)   Expression[w].encode(:u16, @endianness) end
	def encode_word(w)   Expression[w].encode(:u32, @endianness) end
	def encode_xword(w)  Expression[w].encode((@optheader.sig == 'PE+' ? :u64 : :u32), @endianness) end


	# TODO merge sections, base relocations, resources
	def encode(opts = {})
		@encoded ||= EncodedData.new

		pe_target = opts.delete('target') || 'exe'

		if @export
			edata = @export.encode self
			s = Section.new
			s.name = '.edata'
			s.encoded = edata
			s.characteristics = %w[MEM_READ MEM_WRITE]
			@sections << s
		end

		if @imports
			idata = ImportDirectory.encode(self, @imports)
			s = Section.new
			s.name = '.idata'	# XXX .idata discardable, separate from .iat
			s.encoded = idata
			s.characteristics = %w[MEM_READ MEM_WRITE]
			@sections << s
		end

		tmp = %w[LINE_NUMS_STRIPPED LOCAL_SYMS_STRIPPED DEBUG_STRIPPED] +
			case pe_target
			when 'exe':  %w[EXECUTABLE_IMAGE]
			when 'dll':  %w[EXECUTABLE_IMAGE DLL]
			when 'kmod': %w[EXECUTABLE_IMAGE]
			when 'obj':  []
			end
		tmp << "x32BIT_MACHINE"		# XXX
		tmp << 'RELOCS_STRIPPED' if not @directory['base_relocation_table']
		@header.characteristics ||= tmp

		@optheader.subsystem ||= case pe_target
		when 'exe', 'dll': 'WINDOWS_GUI'
		when 'kmod': 'NATIVE'
		end
		@optheader.dll_characts = ['DYNAMIC_BASE'] if @directory['base_relocation_table']
		opth = @optheader.encode(self)

		@encoded << @header.encode(self, opth) << opth

		# encode section table
		@sections.each { |s|
			s.rawaddr = nil if s.rawaddr.kind_of? Integer	# XXX allow to force rawaddr ?
			@encoded << s.encode(self)
		}
		@encoded.align_size @optheader.file_align

		# encode section bodies
		
		baseaddr = @optheader.imagebase		# XXX what if label ?

		# create virtual addresses binding
		binding  = {}
		@encoded.export.each { |label, offset| binding[label] = baseaddr + offset }
		binding[@optheader.headers_size] = @encoded.virtsize if @optheader.headers_size.kind_of? String

		curaddr = (baseaddr + @encoded.virtsize + @optheader.sect_align - 1) / @optheader.sect_align * @optheader.sect_align
		@sections.each { |s|
			if s.virtaddr.kind_of? Integer
				raise "cannot encode section #{s.name}: hardcoded address too short" if curaddr > s.virtaddr
				curaddr = s.virtaddr
			end

			s.encoded.export.each { |label, offset| binding[label] = curaddr + offset }
			binding[s.rawaddr] = @encoded.virtsize if s.rawaddr.kind_of? String

			@encoded << s.encoded[0, s.rawsize]
			@encoded.align_size @optheader.file_align
			curaddr = (curaddr + s.virtsize + @optheader.sect_align - 1) / @optheader.sect_align * @optheader.sect_align
		}
		binding[@optheader.image_size] = curaddr - baseaddr if @optheader.image_size.kind_of? String

		@encoded.fill
		@encoded.fixup binding

		@encoded.data
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
