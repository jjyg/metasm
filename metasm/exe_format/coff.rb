require 'metasm/exe_format/main'
require 'metasm/encode'

module Metasm
class COFF < ExeFormat
	Characteristic_bits = {
		0x0001 => 'RELOCS_STRIPPED',    0x0002 => 'EXECUTABLE_IMAGE',
		0x0004 => 'LINE_NUMS_STRIPPED', 0x0008 => 'LOCAL_SYMS_STRIPPED',
		0x0010 => 'AGGRESSIVE_WS_TRIM', 0x0020 => 'LARGE_ADDRESS_AWARE',
		0x0040 => 'x16BIT_MACHINE',     0x0080 => 'BYTES_REVERSED_LO',
		0x0100 => 'x32BIT_MACHINE',     0x0200 => 'DEBUG_STRIPPED',
		0x0400 => 'REMOVABLE_RUN_FROM_SWAP', 0x0800 => 'NET_RUN_FROM_SWAP',
		0x1000 => 'SYSTEM',             0x2000 => 'DLL',
		0x4000 => 'UP_SYSTEM_ONLY',     0x8000 => 'BYTES_REVERSED_HI'
	}

	Machines = {
		0x0   => 'UNKNOWN',   0x184 => 'ALPHA',   0x1c0 => 'ARM',
		0x1d3 => 'AM33',      0x8664=> 'AMD64',   0xebc => 'EBC',
		0x9041=> 'M32R',      0x1f1 => 'POWERPCFP',
		0x284 => 'ALPHA64',   0x14c => 'I386',    0x200 => 'IA64',
		0x268 => 'M68K',      0x266 => 'MIPS16',  0x366 => 'MIPSFPU',
		0x466 => 'MIPSFPU16', 0x1f0 => 'POWERPC', 0x162 => 'R3000',
		0x166 => 'R4000',     0x168 => 'R10000',  0x1a2 => 'SH3',
		0x1a3 => 'SH3DSP',    0x1a6 => 'SH4',     0x1a8 => 'SH5',
		0x1c2 => 'THUMB',     0x169 => 'WCEMIPSV2'
	}

	Signature = { 0x10b => 'PE', 0x20b => 'PE+' }

	Subsystem = {
		0 => 'UNKNOWN',     1 => 'NATIVE',    2 => 'WINDOWS_GUI',
		3 => 'WINDOWS_CUI', 5 => 'OS/2_CUI',  7 => 'POSIX_CUI',
		8 => 'WIN9X_DRIVER', 9 => 'WINDOWS_CE_GUI',
		10 => 'EFI_APPLICATION',
		11 => 'EFI_BOOT_SERVICE_DRIVER',  12 => 'EFI_RUNTIME_DRIVER',
		13 => 'EFI_ROM', 14 => 'XBOX'
	}

	Dll_Characteristic_bits = {
		0x40 => 'DYNAMIC_BASE', 0x80 => 'FORCE_INTEGRITY', 0x100 => 'NX_COMPAT',
		0x200 => 'NO_ISOLATION', 0x400 => 'NO_SEH', 0x800 => 'NO_BIND',
		0x2000 => 'WDM_DRIVER', 0x8000 => 'TERMINAL_SERVER_AWARE'
	}
	
	Directories = %w[export_table import_table resource_table exception_table certificate_table
			  base_relocation_table debug architecture global_ptr tls_table load_config
			  bound_import iat delay_import com_runtime reserved]

	Section_Characteristic_bits = {
		0x20 => 'CONTAINS_CODE', 0x40 => 'CONTAINS_DATA', 0x80 => 'CONTAINS_UDATA',
		0x100 => 'LNK_OTHER', 0x200 => 'LNK_INFO', 0x800 => 'LNK_REMOVE',
		0x1000 => 'LNK_COMDAT', 0x8000 => 'GPREL',
		0x20000 => 'MEM_PURGEABLE|16BIT', 0x40000 => 'MEM_LOCKED', 0x80000 => 'MEM_PRELOAD',
		0x100000 => 'ALIGN_1BYTES',    0x200000 => 'ALIGN_2BYTES',
		0x300000 => 'ALIGN_4BYTES',    0x400000 => 'ALIGN_8BYTES',
		0x500000 => 'ALIGN_16BYTES',   0x600000 => 'ALIGN_32BYTES',
		0x700000 => 'ALIGN_64BYTES',   0x800000 => 'ALIGN_128BYTES',
		0x900000 => 'ALIGN_256BYTES',  0xA00000 => 'ALIGN_512BYTES',
		0xB00000 => 'ALIGN_1024BYTES', 0xC00000 => 'ALIGN_2048BYTES',
		0xD00000 => 'ALIGN_4096BYTES', 0xE00000 => 'ALIGN_8192BYTES',
		0x01000000 => 'LNK_NRELOC_OVFL', 0x02000000 => 'MEM_DISCARDABLE',
		0x04000000 => 'MEM_NOT_CACHED',  0x08000000 => 'MEM_NOT_PAGED',
		0x10000000 => 'MEM_SHARED',      0x20000000 => 'MEM_EXECUTE',
		0x40000000 => 'MEM_READ',        0x80000000 => 'MEM_WRITE'
	}
	# NRELOC_OVFL means there are more than 0xffff reloc
	# the reloc count must be set to 0xffff, and the real reloc count
	# is the VA of the first relocation

	OrdinalRegex = /^Ordinal_(\d+)$/

	class Section
		attr_accessor :name, :rawoffset, :align, :base,
			:relocsoffset, :linenooffset, :relocsnr, :linenonr,
			:characteristics, :edata, :rawsize_align, :virtsize_align

		def initialize(name)
			@name = name
		end

		def virtsize
			@edata.virtsize
		end

		def rawsize
			[@edata.data.length, *@edata.reloc.map { |off, rel| off + Expression::INT_SIZE[rel.type]/8 } ].max
		end
	end

class << self
	# opts:
	# 	'pe_target'         in ['exe', 'dll', 'kmod', 'obj']
	# 	'pe_format'         in ['PE', 'PE+']
	# 	'directories'       hash of directory_name (from Directories) => [start_label, size_in_bytes] (label found in some program.section)
	# 	'pre_header'        EncodedData to be prepended to the Coff header, the RVA of its first byte is 0
	# 	'no_merge_sections' set to true if you don't want sections to be merged (implies no_merge_dirs)
	# 	'strip_base_relocs' set to true to exclude base relocation information
	# 	'resources'         hash to compile as resources directories
	# 	and misc values to initialize most Coff header members
	def encode(program, opts={})
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
		pre_encode_exports(program, program_start, pe_sections, directories, opts) unless directories.has_key?('export_table') or program.export.empty?
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

	# updates directories with an export_table entry, adds a .edata section
	def pre_encode_exports(program, program_start, pe_sections, directories, opts)
		# initialize label and encodeddata tables
		edata = {}	# edata is the list of EncodedData, 'edata' is the name of the export table
		label = {}
		%w[edata addrtable namptable ord_table dllname nametable].each { |name|
			label[name] = program.new_unique_label
			edata[name] = EncodedData.new '', :export => {label[name] => 0}
		}

		# macros
		encode = proc { |name, type, expr|
			edata[name] << Expression[*expr].encode(type, program.cpu.endianness)
		}
		rva = proc { |name| [label[name], :-, program_start] }
		rva_end = proc { |name| [[label[name], :-, program_start], :+, edata[name].virtsize] }


		ordinal_base = opts.delete('edata_ordinalbase') || 1

		# export table
		encode['edata', :u32, opts.delete('edata_reserved') || 0]
		encode['edata', :u32, opts.delete('edata_timestamp') || Time.now.to_i]
		encode['edata', :u16, opts.delete('edata_version_major') || 0]
		encode['edata', :u16, opts.delete('edata_version_minor') || 0]
		encode['edata', :u32, rva['dllname']]
		encode['edata', :u32, ordinal_base]
		encode['edata', :u32, program.export.size]	# number of exports
		encode['edata', :u32, program.export.size - program.export.keys.grep(OrdinalRegex).size]	# number of names
		encode['edata', :u32, rva['addrtable']]
		encode['edata', :u32, rva['namptable']]
		encode['edata', :u32, rva['ord_table']]
		
		# dll name
		edata['dllname'] << (opts.delete('edata_dllname') || 'METALIB') << 0

		# populate addr/namp/ord/name tables
		ordinal_list = program.export.sort.find_all { |exportname, labelname| exportname =~ OrdinalRegex }
		# TODO
		program.export.sort.each { |exportname, labelname|
			# forwarder
			if labelname =~ /^Forwarder_(\w+?)_(\w+)$/
				# XXX export forwarder as ordinal ? XXX
				libname, funcname = $1, $2
				encode['addrtable', :u32, rva_end['nametable']]
				funcname = '#' << $1 if funcname =~ OrdinalRegex
				edata['nametable'] << "#{libname}.#{funcname}" << 0
			else
				raise EncodeError, "No definition of exported entry #{exportname.inspect} (#{labelname.inspect})" if not pe_sections.find { |s| s.edata.export[labelname] }
				encode['addrtable', :u32, [labelname, :-, program_start]]

				if exportname !~ OrdinalRegex
					encode['ord_table', :u16, edata['addrtable'].virtsize/4 - ordinal_base]
					encode['namptable', :u32, rva_end['nametable']]
					edata['nametable'] << exportname << 0
				end
			end
		}

		# commit
		s = Section.new '.edata'
		s.align = 4
		# coalesce encodeddatas (order does not matter, but ptr tables must be aligned on 4bytes and ord on 2)
		s.edata = %w[edata addrtable namptable ord_table dllname nametable].inject(EncodedData.new) { |ed, name| ed << edata[name] }
		s.characteristics = %w[MEM_READ MEM_WRITE]
		pe_sections << s
		directories['export_table'] = [label['edata'], s.edata.virtsize]
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
				if importname =~ OrdinalRegex
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
				if importname =~ OrdinalRegex
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
		s = Section.new '.didata'
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

		raise 'COFF :obj format not supported yet' if pe_target == 'obj'	 # TODO

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

		# Coff header
		# machine type	# XXX ugly, no support for EM64T
		tmp = opts.delete('machine') || case program.cpu.class.name
			when /ia32/i: 'I386'
			else 'UNKNOWN'
			end
		encode[:u16, Machines.index(tmp)]
		encode[:u16, pe_sections.length]
		encode[:u32, opts.delete('timestamp') || Time.now.to_i]
		encode[:u32, 0]	# raw offset to symbol table
		encode[:u32, 0]	# number of symbols
		encode[:u16, [end_optheader, :-, start_optheader]]

		# image characteristics
		if not tmp = opts.delete('characteristics')
			tmp = %w[LINE_NUMS_STRIPPED LOCAL_SYMS_STRIPPED DEBUG_STRIPPED] +
				case pe_target
				when 'exe':  %w[EXECUTABLE_IMAGE]
				when 'dll':  %w[EXECUTABLE_IMAGE DLL]
				when 'kmod': %w[EXECUTABLE_IMAGE] # SYSTEM absent from all windows PE
				when 'obj':  []
				end
			tmp << "x#{program.cpu.size}BIT_MACHINE"	# XXX EM64T
			tmp << 'RELOCS_STRIPPED' if not directories['base_relocation_table']
		end
		encode[:u16, tmp.inject(0) { |bits, charac|  bits | Characteristic_bits.index(charac) }]


		# Optionnal header
		header.export[start_optheader] = header.virtsize

		# standard fields
		encode[:u16, Signature.index(pe_format)]
		encode[:u8,  opts.delete('linker_major_version') || 1]
		encode[:u8,  opts.delete('linker_minor_version') || 0]

		%w[CONTAINS_CODE CONTAINS_DATA CONTAINS_UDATA].each { |sect_type|
			tmp = pe_sections.find_all { |s| s.characteristics.include? sect_type }
			encode[:u32, tmp.map { |s| align[s.virtsize, section_align] }.inject(0) { |a, b| a+b }]
		} # size of code/idata/udata

		entrypoint = opts.delete('entrypoint') || 'start'
		if entrypoint.kind_of? Integer
			encode[:u32, entrypoint]
		elsif not pe_sections.find { |s| s.edata.export[entrypoint] }
			raise EncodeError, 'No entrypoint defined' if pe_target == 'exe'
			puts 'W: No entrypoint defined'
			encode[:u32, 0]
		else
			encode[:u32, rva[entrypoint]]
		end

		if tmp = pe_sections.find { |s| s.characteristics.include? 'CONTAINS_CODE' }
			tmp = rva[program.label_at(tmp.edata, 0)]
		else tmp = 0
		end
		encode[:u32, tmp]	# base of code

		if pe_format == 'PE'
			if tmp = pe_sections.find { |s| s.characteristics.include? 'CONTAINS_DATA' or s.characteristics.include? 'CONTAINS_UDATA' }
				tmp = rva[program.label_at(tmp.edata, 0)]
			else tmp = 0
			end
			encode[:u32, tmp]	# base of data (not in PE+)
		end


		# NT-Specific fields
		encode[vlen, program_start]	# prefered base address

		encode[:u32, section_align]
		encode[:u32, file_align]

		encode[:u16, opts.delete('os_major_version') || 4]
		encode[:u16, opts.delete('os_minor_version') || 0]
		encode[:u16, opts.delete('image_major_version') || 0]
		encode[:u16, opts.delete('image_minor_version') || 0]
		encode[:u16, opts.delete('subsystem_major_version') || 4]
		encode[:u16, opts.delete('subsystem_minor_version') || 0]
		encode[:u32, opts.delete('reserved') || 0]

		encode[:u32, rva[end_image]]	# sizeof image
		encode[:u32, rva[end_header]]	# sizeof headers

		encode[:u32, opts.delete('checksum') || 0]		# checksum

		tmp = opts.delete('subsystem') || case pe_target
			when :exe, :dll: 'WINDOWS_GUI'
			when :kmod: 'NATIVE'
			else 'UNKNOWN'
			end
		encode[:u16, Subsystem.index(tmp)]

		if not tmp = opts.delete('dllcharacteristics')
			tmp = []
			tmp << 'DYNAMIC_BASE' if not directories['base_relocation_table']
		end
		encode[:u16, tmp.inject(0) { |int, char|  int | Dll_Characteristic_bits.index(char) }]

		encode[vlen, opts.delete('size_of_stack_reserve') || 0x100000]
		encode[vlen, opts.delete('size_of_stack_commit')  || 0x1000]
		encode[vlen, opts.delete('size_of_heap_reserve')  || 0x100000]
		encode[vlen, opts.delete('size_of_heap_commit')   || 0x1000]
		encode[vlen, opts.delete('loader_flags') || 0]

		if directories.empty?
			encode[:u32, 0]
		else
			tmp = directories.keys - Directories
			raise EncodeError, "Unknown directories name #{tmp.inspect}" unless tmp.empty?

			#tmp = directories.keys.map { |dir| Directories.index(dir) }.max
			tmp = Directories.length - 1
			encode[:u32, tmp+1]
			
			# Directories
			Directories[0..tmp].each { |dir|
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
			tmp = s.characteristics.inject(0) { |int, char|  int | Section_Characteristic_bits.index(char) }
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
	Type = {
		1 => 'CURSOR', 2 => 'BITMAP', 3 => 'ICON', 4 => 'MENU',
		5 => 'DIALOG', 6 => 'STRING', 7 => 'FONTDIR', 8 => 'FONT',
		9 => 'ACCELERATOR', 10 => 'RCADATA', 11 => 'MESSAGETABLE',
		12 => 'GROUP_CURSOR', 14 => 'GROUP_ICON', 16 => 'VERSION',
		17 => 'DLGINCLUDE', 19 => 'PLUGPLAY', 20 => 'VXD',
		21 => 'ANICURSOR', 22 => 'ANIICON', 23 => 'HTML',
		24 => 'MANIFEST' # ?
	}

	Accelerator_bits = {
		1 => 'VIRTKEY', 2 => 'NOINVERT', 4 => 'SHIFT', 8 => 'CTRL',
		16 => 'ALT', 128 => 'LAST'
	}

	# TODO
	# cursor = raw data, cursor_group = header , pareil pour les icons
	class Cursor
		attr_accessor :xhotspot, :yhotspot, :data
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
		s.align = 4
		s.edata = recurs_encode[rsrc, 0] << edata['nametable'] << edata['datatable'] << edata['data']
		s.edata.export[label['directory']] = 0
		s.characteristics = %w[MEM_READ]
		pe_sections << s

		directories['resource_table'] = [label['directory'], s.edata.virtsize]
	end

	def check
		# check relocations are all in a mapped section, and not targetting the reloc directory
		# check entrypoint in .text
	end

	def rebase_at(newbase)
		# apply relocs
	end
end
end
end
__END__

class Symbols
	attr_reader :name, :value, :sectionnumber, :type, :storageclass, :nbaux, :aux
# name: if the first 4 bytes are null, the 4 next are the index to the name in the string table

	def initialize(raw, offset)
		@name = raw[offset..offset+7].delete("\0")
		@value = bin(raw[offset+8 ..offset+11])
		@sectionnumber = bin(raw[offset+12..offset+13])
		@type = bin(raw[offset+14..offset+15])
		@storageclass = raw[offset+16]
		@nbaux = raw[offset+17]
		@aux = Array.new
		@nbaux.times { @aux << raw[offset..offset+17] ; offset += 18 }
	end
end

class Strings < Array
	attr_reader :size
	
	def initialize(raw, offset)
		@size = bin(raw[offset..offset+3])
		endoffset = offset + @size
puts "String table: 0x%.8x .. 0x%.8x" % [offset, endoffset]
		curstring = ''
		while (offset < endoffset)
			if raw[offset] != 0
				curstring << raw[offset]
			else
				self << curstring
				curstring = ''
			end
			offset += 1
		end
	end
end
