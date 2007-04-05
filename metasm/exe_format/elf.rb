require 'metasm/exe_format/main'
require 'metasm/decode'

module Metasm
# TODO ELF64
class ELF < ExeFormat
	CLASS = { 0 => 'NONE', 1 => '32', 2 => '64' }
	DATA  = { 0 => 'NONE', 1 => 'LSB', 2 => 'MSB' }
	VERSION = { 0 => 'INVALID', 1 => 'CURRENT' }
	TYPE = { 0 => 'NONE', 1 => 'REL', 2 => 'EXEC', 3 => 'DYN', 4 => 'CORE',
		0xff00 => 'LOPROC', 0xffff => 'HIPROC' }
	MACHINE = { 0 => 'NONE', 1 => 'M32', 2 => 'SPARC', 3 => '386',
		4 => '68K', 5 => '88K', 7 => '860', 8 => 'MIPS' }
	FLAGS = {}

	DYNAMIC_TAG = { 0 => 'NULL', 1 => 'NEEDED', 2 => 'PLTRELSZ', 3 =>
		'PLTGOT', 4 => 'HASH', 5 => 'STRTAB', 6 => 'SYMTAB', 7 => 'RELA',
		8 => 'RELASZ', 9 => 'RELAENT', 10 => 'STRSZ', 11 => 'SYMENT',
		12 => 'INIT', 13 => 'FINI', 14 => 'SONAME', 15 => 'RPATH',
		16 => 'SYMBOLIC', 17 => 'REL', 18 => 'RELSZ', 19 => 'RELENT',
		20 => 'PLTREL', 21 => 'DEBUG', 22 => 'TEXTREL', 23 => 'JMPREL',
		0x7000_0000 => 'LOPROC', 0x7fff_ffff => 'HIPROC' }

	PH_TYPE = { 0 => 'NULL', 1 => 'LOAD', 2 => 'DYNAMIC', 3 => 'INTERP',
		4 => 'NOTE', 5 => 'SHLIB', 6 => 'PHDR',
		0x7000_0000 => 'LOPROC', 0x7fff_ffff => 'HIPROC' }
	PH_FLAGS = { 1 => 'X', 2 => 'W', 4 => 'R' }

	SH_TYPE = { 0 => 'NULL', 1 => 'PROGBITS', 2 => 'SYMTAB', 3 => 'STRTAB',
		4 => 'RELA', 5 => 'HASH', 6 => 'DYNAMIC', 7 => 'NOTE',
		8 => 'NOBITS', 9 => 'REL', 10 => 'SHLIB', 11 => 'DYNSYM',
		0x7000_0000 => 'LOPROC', 0x7fff_ffff => 'HIPROC',
		0x8000_0000 => 'LOUSER', 0xffff_ffff => 'HIUSER' }

	SH_FLAGS = { 1 => 'WRITE', 2 => 'ALLOC', 4 => 'EXECINSTR',
		0xf000_0000 => 'MASKPROC' }

	SH_INDEX = { 0 => 'UNDEF', 0xff00 => 'LORESERVE', 0xff1f => 'HIPROC',		 # LOPROC == LORESERVE
		0xfff1 => 'ABS', 0xfff2 => 'COMMON', 0xffff => 'HIRESERVE' }

	SYMBOL_BIND = { 0 => 'LOCAL', 1 => 'GLOBAL', 2 => 'WEAK',
		13 => 'LOPROC', 15 => 'HIPROC' }
	SYMBOL_TYPE = { 0 => 'NOTYPE', 1 => 'OBJECT', 2 => 'FUNC',
		3 => 'SECTION', 4 => 'FILE', 13 => 'LOPROC', 15 => 'HIPROC' }

	RELOCATION_TYPE = {	# key in MACHINE.values
		'386' => { 0 => 'NONE', 1 => '32', 2 => 'PC32', 3 => 'GOT32',
			4 => 'PLT32', 5 => 'COPY', 6 => 'GLOB_DAT', 7 => 'JMP_SLOT',
			8 => 'RELATIVE', 9 => 'GOTOFF', 10 => 'GOTPC' }
	}

	class Section
		attr_accessor :name, :type, :flags, :addr, :rawoffset, :link, :info, :align, :entsize, :edata
		attr_accessor :virt_gap	# set to true if a virtual address gap is needed with the preceding section (different memory permission needed)
		def initialize
			@flags = []
		end
		
		def rawsize
			[@edata.data.length, *@edata.reloc.map { |off, rel| off + Expression::INT_SIZE[rel.type]/8 } ].max
		end
	end

	class Symbol
		attr_accessor :name, :value, :size, :bind, :type, :other, :section, :info, :name_p
	end

	class Relocation
		attr_accessor :offset, :type, :symbol, :info, :addend
	#	def info ; (@symbol << 8) + @type end
	#	def info=(i) @symbol = i >> 8 ; @type = i & 0xff end
	end

class << self
	# 'elf_target' in ['REL', 'EXEC', 'DYN']
	def encode(program, opts={})
		sections = []

		if interp = opts.delete('elf_interp')
			sections << (s = Section.new)
			s.name = '.interp'
			s.align = 1
			s.edata = EncodedData.new << interp << 0
			s.type = 'PROGBITS'
		end

		program.sections.each { |sect|
			sections << (s = Section.new)
			s.name = sect.name
			s.align = sect.align || 4
			s.addr = sect.base
			s.edata = sect.encoded.dup
			s.type = s.edata.data.empty? ? 'NOBITS' : 'PROGBITS'
			s.flags << 'ALLOC' unless sect.mprot.include? :discard
			s.flags << 'WRITE' if sect.mprot.include? :write
			s.flags << 'EXECINSTR' if sect.mprot.include? :exec
		}

		target = opts.delete('elf_target') || 'EXEC'
		arch   = opts.delete('e_machine') || '386'	# TODO check program.cpu.class or something

		# XXX regroup sections by flag (1 big rw segment, 1 big rx segment)
		# dynamic for exe/so, relocs for obj ?
		if target == 'EXEC' or target == 'DYN'
			pre_encode_dynamic(program, target, arch, sections, opts) unless opts.delete('no_dynamic')
		else
			pre_encode_relocs(program, target, sections, opts)
		end

		pre_encode_secthdr(program, target, sections, opts) unless opts.delete('no_section_header')
		pre_encode_proghdr(program, target, sections, opts) unless opts.delete('no_program_header')	# or elf_target == 'obj'
		pre_encode_header( program, target, arch, sections, opts)

		link(program, target, sections, opts)
	end

	def symbol_hash(name)
		name.unpack('C*').inject(0) { |hash, char|
			break hash if char == 0
			hash <<= 4
			hash += char
			hash ^= (hash >> 24) & 0xf0
			hash &= 0x0fff_ffff
		}
	end

	def pre_encode_dynamic(program, target, arch, sections, opts)
		# TODO add parser support for sym.size / sym.type

		encode = proc { |sect, type, val| sect.edata << Expression[*val].encode(type, program.cpu.endianness) }

		#pre_sections = sections.dup
		
		dynstr = Section.new
		dynstr.name = '.dynstr'
		dynstr.align = 1
		dynstr.edata = EncodedData.new << 0
		dynstr.type = 'STRTAB'
		dynstr.flags << 'ALLOC'
		sections << dynstr

		dynsym = Section.new
		dynsym.name = '.dynsym'
		dynsym.align = 4
		dynsym.edata = EncodedData.new
		dynsym.type = 'DYNSYM'
		dynsym.flags << 'ALLOC'
		dynsym.entsize = 0x10
		dynsym.link = dynstr
		sections << dynsym

		hash = Section.new
		hash.name = '.hash'
		hash.align = 4
		hash.edata = EncodedData.new
		hash.type = 'HASH'
		hash.flags << 'ALLOC'
		hash.entsize = 4
		hash.link = dynsym
		sections << hash

		rel = Section.new
		rel.name = '.rel.dyn'
		rel.align = 4
		rel.edata = EncodedData.new
		rel.type = 'REL'
		rel.flags << 'ALLOC'
		rel.entsize = 8
		rel.link = dynsym
		rel.info = 0
		sections << rel

		dynamic = Section.new
		dynamic.name = '.dynamic'
		dynamic.align = 4
		dynamic.edata = EncodedData.new
		dynamic.type = 'DYNAMIC'
		dynamic.entsize = 8
		dynamic.flags << 'ALLOC'
		dynamic.link = dynstr
		sections << dynamic

		if program.import.find { |lib, ilist| ilist.find { |iname, thunkname| not thunkname } }
		got = Section.new
		got.name = '.got'
		got.align = 4
		got.edata = EncodedData.new
		got.type = 'PROGBITS'
		got.flags << 'ALLOC' << 'WRITE'
		got.entsize = 4
		sections << got
		end

		if program.import.find { |lib, ilist| ilist.find { |iname, thunkname| thunkname } }
		pltgot = Section.new
		pltgot.name = '.plt.got'
		pltgot.align = 4
		pltgot.edata = EncodedData.new
		pltgot.type = 'PROGBITS'
		pltgot.flags << 'ALLOC' << 'WRITE'
		pltgot.entsize = 4
		sections << pltgot

		# the plt does not need to be a table
		plt = Section.new
		plt.name = '.plt'
		plt.align = 4
		plt.edata = EncodedData.new
		plt.type = 'PROGBITS'
		plt.flags << 'ALLOC' << 'EXECINSTR'
		#plt.entsize = 4
		sections << plt

		relplt = Section.new
		relplt.name = '.rel.plt'
		relplt.align = 4
		relplt.edata = EncodedData.new
		relplt.type = 'REL'
		relplt.flags << 'ALLOC'
		relplt.entsize = 8
		relplt.link = dynsym
		relplt.info = plt		# should be pltgot, but gcc uses plt
		sections << relplt

		encode[pltgot, :u32, program.label_at(dynamic.edata, 0)]	# reserved, points to _DYNAMIC
		#if arch == '386'
			encode[pltgot, :u32, 0]	# ptr to dlresolve
			encode[pltgot, :u32, 0]	# ptr to got?
		#end
		end
	
		# group sections by flags
		sections.replace sections.sort_by { |s|
			if s.flags.include? 'ALLOC'
				if s.type == 'PROGBITS'
					if not s.flags.include? 'WRITE'
						if not s.flags.include? 'EXECINSTR'
							0	# R
						else
							1	# RX
						end
					else
						2	# RW / RWX
					end
				else
					3	# NOBITS
				end
			else
				4	# NOALLOC
			end
		}

		# now section indexes are valid (no insertion/reordering allowed)

		dynsym.edata << ("\0"*dynsym.entsize)	# 1st entry reserved for SHN_UNDEF
		dynstrndx = {}	# used in hash definition
		# macros
		new_dynstr = proc { |str|
			ret = dynstr.edata.virtsize
			dynstr.edata << str << 0
			ret
		}
		add_dynsym = proc { |sym|
			if sym.name
				dynstrndx[sym.name] = dynsym.edata.virtsize / dynsym.entsize
				encode[dynsym, :u32, new_dynstr[sym.name]]
			else
				encode[dynsym, :u32, 0]
			end
			encode[dynsym, :u32, sym.value || 0]
			encode[dynsym, :u32, sym.size || 0]
			encode[dynsym, :u8, [[int_from_hash(sym.bind || 'LOCAL', SYMBOL_BIND), :<<, 4], :|, int_from_hash(sym.type || 'NOTYPE', SYMBOL_TYPE)]]
			encode[dynsym, :u8, sym.other || 0]
			sndx = sections.index(sym.section)
			sndx = sndx ? sndx + 1 : int_from_hash(sym.section || 'UNDEF', SH_INDEX)
			encode[dynsym, :u16, sndx]
		}

		if false and target != 'EXEC'
			# XXX ??  not found in gcc's ET_EXEC, from docs: 'used for relocations'
			pre_sections.map { |s|
				sym = Symbol.new
				sym.value = s.rawoffset ||= program.new_unique_label
				sym.bind = 'LOCAL'
				sym.type = 'SECTION'
				sym.section = s
				sym
			}.sort_by { |sym| sections.index sym.section }.each { |sym| add_dynsym[sym] }
		end

		if false and filename = opts.delete('filename')
			# XXX should be related to debug information
			sym = Symbol.new
			sym.name = filename
			sym.bind = 'LOCAL'
			sym.type = 'FILE'
			sym.section = 'ABS'
			add_sym[sym]
		end

		dynsym.info = dynsym.edata.virtsize / dynsym.entsize	# index of the last local sym + 1

		sections.each { |sect|
			sect.edata.export.each { |name, off|
				next unless program.export[name]
				s = Symbol.new
				s.name = name
				s.bind = 'GLOBAL'
				s.section = sect
				s.value = name
				add_dynsym[s]
			}
		}
		program.export.each { |name, label|
			next if name == label	# already done
			s = Symbol.new
			s.name = name
			s.bind = 'GLOBAL'
			s.section = sections.find { |sect| sect.edata.export[label] }
			s.value = label
			add_dynsym[s]
		}
		program.import.each { |lib, ilist|
			ilist.each { |iname, thunkname|
				s = Symbol.new
				s.name = iname
				s.bind = 'GLOBAL'
				s.section = 'UNDEF'
				# s.value = ?
				add_dynsym[s]
			}
		}

		# build dynamic symbols hash table
		#
		# to find a symbol from its name :
		# 1 idx = hash(name)
		# 2 idx = bucket[idx % bucket.size]
		# 3 if idx == 0: return notfound
		# 4 if dynsym[idx].name == name: return found
		# 5 idx = chain[idx] ; goto 3
		hash_bucket = Array.new(dynstrndx.length/4 + 1, 0)
		hash_chain  = Array.new(dynstrndx.values.max.to_i+1, 0)
		dynstrndx.each { |name, index|
			h = symbol_hash(name)
			h_mod = h % hash_bucket.length
			hash_chain[index] = hash_bucket[h_mod]
			hash_bucket[h_mod] = index
		}
		encode[hash, :u32, hash_bucket.length]
		encode[hash, :u32, hash_chain.length]
		hash_bucket.each { |b| encode[hash, :u32, b] }
		hash_chain.each  { |c| encode[hash, :u32, c] }


		encoderel = proc { |s, off, target, type|
			encode[s, :u32, off]
			target = dynstrndx[target] || target
			encode[s, :u32, [[target, :<<, 8], :|, int_from_hash(type, RELOCATION_TYPE[arch])]]
		}

		if pltgot
		# XXX the plt entries need not to follow this model
		# XXX arch-specific, parser-dependant...
		program.parse <<EOPLT
.section metasmintern_plt r x
metasmintern_pltstart:
	push dword ptr [ebx+4]
	jmp  dword ptr [ebx+8]

metasmintern_pltgetgotebx:
	call metasmintern_pltgetgotebx_foo
metasmintern_pltgetgotebx_foo:
	pop ebx
	add ebx, #{program.label_at(pltgot.edata, 0)} - metasmintern_pltgetgotebx_foo
	ret
EOPLT
		pltsec = program.sections.pop
		end

		program.import.each { |lib, ilist|
			ilist.each { |iname, thunkname|
				if thunkname
					uninit = program.new_unique_label
					program.parse <<EOPLTE
#{thunkname}:
	call metasmintern_pltgetgotebx
	jmp [ebx+#{pltgot.edata.virtsize}]
#{uninit}:
	push #{relplt.edata.virtsize}
	jmp metasmintern_pltstart
align 0x10
EOPLTE
					pltgot.edata.export[iname] = pltgot.edata.virtsize if iname != thunkname
					encoderel[relplt, program.label_at(pltgot.edata, pltgot.edata.virtsize), iname, 'JMP_SLOT']
					encode[pltgot, :u32, uninit]
					# no base relocs
				else
					got.edata.export[iname] = got.edata.virtsize
					encoderel[rel, iname, iname, 'GLOB_DAT']
					encode[got, :u32, 0]
				end
			}
		}
		pltsec.encode
		plt.edata << pltsec.encoded


		if opts.delete('unstripped')
			strtab = Section.new
			strtab.name = '.strtab'
			strtab.align = 1
			strtab.edata = EncodedData.new << 0
			strtab.type = 'STRTAB'

			symtab = Section.new
			symtab.name = '.symtab'
			symtab.align = 4
			symtab.edata = EncodedData.new
			symtab.type = 'SYMTAB'
			symtab.entsize = 0x10
			symtab.link = strtab
			symtab.edata << ("\0"*symtab.entsize)

			new_str = proc { |str|
				ret = strtab.edata.virtsize
				strtab.edata << str << 0
				ret
			}

			add_sym = proc { |sym|
				encode[symtab, :u32, sym.name ? new_str[sym.name] : 0]
				encode[symtab, :u32, sym.value || 0]
				encode[symtab, :u32, sym.size || 0]
				encode[symtab, :u8, [[int_from_hash(sym.bind || 'LOCAL', SYMBOL_BIND), :<<, 4], :|, int_from_hash(sym.type || 'NOTYPE', SYMBOL_TYPE)]]
				encode[symtab, :u8, sym.other || 0]
				sndx = sections.index(sym.section)
				sndx = sndx ? sndx + 1 : int_from_hash(sym.section || 'UNDEF', SH_INDEX)
				encode[symtab, :u16, sndx]
			}

			sections.map { |s|	# includes .plt .got etc
				sym = Symbol.new
				sym.value = s.rawoffset ||= program.new_unique_label
				sym.bind = 'LOCAL'
				sym.type = 'SECTION'
				sym.section = s
				add_sym[sym]
			}

			sections << strtab << symtab

			sections.each { |s|
				s.edata.export.each { |name, off|
					next if program.export[name]

					next if name =~ /^metasmintern_uniquelabel_/	# skip autogenerated labels
					sym = Symbol.new
					sym.name = name
					sym.bind = 'LOCAL'
					sym.section = s
					sym.value = name
					add_sym[sym]
				}
			}

			symtab.info = symtab.edata.virtsize / symtab.entsize	# index of the last local sym + 1

			program.export.each { |name, label|
				sym = Symbol.new
				sym.name = name
				sym.bind = 'GLOBAL'
				sym.section = sections.find { |s| s.edata.export[label] }
				sym.value = label
				add_sym[sym]
			}
			
			program.import.each { |lib, ilist|
				ilist.each { |iname, thunkname|
					sym = Symbol.new
					sym.name = iname
					sym.bind = 'GLOBAL'
					sym.section = 'UNDEF'
					add_sym[sym]
				}
			}
		end


		# dynamic tags
		tag = proc { |type, val|
			dynamic.edata <<
			Expression[int_from_hash(type, DYNAMIC_TAG)].encode(:u32, program.cpu.endianness) <<
			Expression[*val].encode(:u32, program.cpu.endianness)
		}

		(program.import.keys + opts.delete('needed').to_a).each { |libname|
			tag['NEEDED', new_dynstr[libname]]
		}

		tmp = nil
		tag['INIT', tmp] if tmp = opts.delete('init')
		tag['FINI', tmp] if tmp = opts.delete('fini')
		tag['SONAME', new_dynstr[tmp]] if tmp = opts.delete('soname')

		tag['HASH',   program.label_at(hash.edata, 0)]
		tag['STRTAB', program.label_at(dynstr.edata, 0)]
		tag['SYMTAB', program.label_at(dynsym.edata, 0)]
		tag['STRSZ',  dynstr.edata.virtsize]
		tag['SYMENT', dynsym.entsize]

		if pltgot
		tag['PLTGOT', program.label_at(pltgot.edata, 0)]
		tag['PLTRELSZ', relplt.edata.virtsize]
		tag['PLTREL', DYNAMIC_TAG.index('REL')]
		tag['JMPREL', program.label_at(relplt.edata, 0)]
		end

		tag['REL',    program.label_at(rel.edata, 0)]
		tag['RELSZ',  rel.edata.virtsize]
		tag['RELENT', rel.entsize]

		tag['NULL', 0]	# end of array

		sections.each { |s|
			s.link = sections.index(s.link) + 1 if s.link.kind_of? Section
			s.info = sections.index(s.info) + 1 if s.info.kind_of? Section
		}
	end

	def pre_encode_secthdr(program, target, sections, opts)
		# section containing section names
		sections << (shnam = Section.new)
		shnam.name = '.shstrtab'
		shnam.align = 1
		shnam.edata = EncodedData.new << 0
		shnam.type = 'STRTAB'

		namidx = []
		sections.each { |s|
			namidx << shnam.edata.virtsize
			shnam.edata << s.name << 0
		}

		shdr = EncodedData.new
		encode = proc { |val| shdr << Expression[*val].encode(:u32, program.cpu.endianness) }

		10.times { encode[0] }	# first entry = undef

		sections.zip(namidx).each { |s, nidx|
			encode[nidx]
			encode[int_from_hash(s.type, SH_TYPE)]
			encode[bits_from_hash(s.flags, SH_FLAGS)]
			encode[program.label_at(s.edata, 0)]
			encode[s.rawoffset ||= program.new_unique_label]
			encode[s.edata.virtsize]
			encode[s.link || 0]
			encode[s.info || 0]
			encode[s.align || 0]
			encode[s.entsize || 0]
		}

		# append the section header to the sections list (for linkage)
		sections.unshift(sh = Section.new)
		sh.name  = :shdr
		sh.align = 4
		sh.edata = shdr
	end

	def pre_encode_proghdr(program, target, sections, opts)
		phdr = EncodedData.new
		sections.unshift(phdr_s = Section.new)
		phdr_s.name = :phdr
		phdr_s.align = 4
		phdr_s.flags << 'ALLOC'
		phdr_s.edata = phdr
		end_phdr = nil

		# macros
		encode = proc { |val| phdr << Expression[*val].encode(:u32, program.cpu.endianness) }
		encode_segm = proc { |type, rawoff, virtoff, rawsz, virtsz, flags, align|
			encode[int_from_hash(type, PH_TYPE)]
			encode[rawoff || 0]
			encode[virtoff || 0]
			encode[virtoff || 0]
			encode[rawsz || 0]
			encode[virtsz ? virtsz : rawsz || 0]
			encode[bits_from_hash(flags || 0, PH_FLAGS)]
			encode[align || 0]
		}


		# create misc segments
		if s = sections.find { |s| s.name == '.interp' }
			encode_segm['INTERP',
				s.rawoffset ||= program.new_unique_label,
				program.label_at(s.edata, 0),
				s.edata.virtsize,
				nil,
				['R'],
				s.align]
		end

		if not opts.delete('no_program_header_segment')
			end_phdr ||= program.new_unique_label
			encode_segm['PHDR',
				phdr_s.rawoffset ||= program.new_unique_label,
				program.label_at(phdr, 0),
				[end_phdr, :-, program.label_at(phdr, 0)],
				nil,
				['R'],
				phdr_s.align
			]
		end


		# create load segments
		# merge sections, try to avoid rwx segment (PaX)
		# TODO enforce noread/nowrite/noexec section specification ?
		# TODO minimize segment with unneeded permissions ? (R R R R R RW R RX R => rw[R R R R R RW R] rx[RX R], could be r[R R R R R] rw[RW] r[R] rx[RX] r[R] (with page-size merges/in-section splitting?))
		aligned = opts.delete('create_aligned_load_segments')
		lastprot = []
		firstsect = lastsect = nil
		encode_load_segment = proc {
			if lastsect.name == :phdr
				# the program header is not complete yet, so we cannot rely on its virtsize/rawsize
				end_phdr ||= program.new_unique_label
				size = virtsize = [end_phdr, :-, program.label_at(firstsect.edata, 0)]
			else
				size = [program.label_at(lastsect.edata, lastsect.rawsize), :-, program.label_at(firstsect.edata, 0)]
				virtsize = [program.label_at(lastsect.edata, lastsect.edata.virtsize), :-, program.label_at(firstsect.edata, 0)]
			end
			if not aligned
				encode_segm['LOAD',
					firstsect.rawoffset ||= program.new_unique_label,
					program.label_at(firstsect.edata, 0),
					size,	# allow virtual data here (will be zeroed on load) XXX check zeroing
					virtsize,
					['R', *{'WRITE' => 'W', 'EXECINSTR' => 'X'}.values_at(*lastprot).compact],
					0x1000
				]
			else
				encode_segm['LOAD',
					[(firstsect.rawoffset ||= program.new_unique_label), :&, 0xffff_f000],
					[program.label_at(firstsect.edata, 0), :&, 0xffff_f000],
					[[[size, :+, [firstsect.rawoffset, :&, 0xfff]], :+, 0xfff], :&, 0xffff_f000],
					[[[virtsize, :+, [firstsect.rawoffset, :&, 0xfff]], :+, 0xfff], :&, 0xffff_f000],
					['R', *{'WRITE' => 'W', 'EXECINSTR' => 'X'}.values_at(*lastprot).compact],
					0x1000
				]
			end
		}
		sections.each { |s|
			xflags = s.flags & %w[EXECINSTR WRITE]	# non mergeable flags
			if not s.flags.include? 'ALLOC'	# ignore
				s.edata.fill
			elsif firstsect and (xflags | lastprot == xflags or xflags.empty?)	# concat for R+RW / RW + R, not for RW+RX (unless last == RWX)
				if lastsect.edata.virtsize > lastsect.rawsize + 0x1000
					# XXX new_seg ?
				end
				lastsect.edata.fill
				lastsect = s
				lastprot |= xflags
			else					# section incompatible with current segment: create new segment (or first section seen)
				if firstsect
					encode_load_segment[]
					s.virt_gap = true
				end
				firstsect = lastsect = s
				lastprot = xflags
			end
		}
		if firstsect	# encode last load segment
			encode_load_segment[]
		end


		# create dynamic segment
		sections.each { |s|
			if s.type == 'DYNAMIC'
				encode_segm['DYNAMIC',
					s.rawoffset ||= program.new_unique_label,
					program.label_at(s.edata, 0),
					s.rawsize, s.edata.virtsize,
					['R', *{'WRITE' => 'W', 'EXECINSTR' => 'X'}.values_at(*s.flags).compact],
					s.align]
			end
		}

		# create misc segments
		# hash with keys in [type offset vaddr paddr filesz memsz flags align], type needed
		(opts.delete('additional_segments') || []).each { |sg| encode_segm[sg['type'], sg['offset'], sg['vaddr'], sg['filesz'], sg['memsz'], sg['flags'], sg['align']] }

		phdr.export[end_phdr] = phdr.virtsize if end_phdr
	end

	def pre_encode_header(program, target, arch, sections, opts)
		hdr = EncodedData.new

		end_hdr = program.new_unique_label

		hdr << 0x7f << 'ELF'
		hdr << CLASS.index(program.cpu.size.to_s)	# 16bits ?
		hdr << DATA.index( {:little => 'LSB', :big => 'MSB'}[program.cpu.endianness] )
	 
		e_version = int_from_hash(opts.delete('e_version') || 'CURRENT', VERSION)
		hdr << e_version
		hdr.fill(16, "\0")

		encode = proc { |type, val| hdr << Expression[*val].encode(type, program.cpu.endianness) }

		encode[:u16, int_from_hash(target, TYPE)]
		encode[:u16, int_from_hash(arch, MACHINE)]
		encode[:u32, e_version]

		entrypoint = opts.delete('entrypoint') || 'start'
		if not entrypoint.kind_of? Integer and not program.sections.find { |s| s.encoded.export[entrypoint] }
			puts 'W: No entrypoint defined'	if target == 'EXEC'
			encode[:u32, 0]
		else
			encode[:u32, entrypoint]
		end

		phdr = sections.find { |s| s.name == :phdr }
		encode[:u32, phdr ? phdr.rawoffset ||= program.new_unique_label : 0]
		shdr = sections.find { |s| s.name == :shdr }
		encode[:u32, shdr ? shdr.rawoffset ||= program.new_unique_label : 0]
		
		encode[:u32, opts.delete('elf_flags') || 0]	# 0 for IA32
		encode[:u16, [end_hdr, :-, program.label_at(hdr, 0)]]
		encode[:u16, 0x20]	# program header entry size
		encode[:u16, phdr ? phdr.edata.virtsize / 0x20 : 0]	# number of program header entries
		encode[:u16, 0x28]	# section header entry size
		encode[:u16, shdr ? shdr.edata.virtsize / 0x28 : 0]	# number of section header entries
		encode[:u16, shdr ? sections.find_all { |s| s.name.kind_of? String }.index(sections.find { |s| s.name == '.shstrtab' }) + 1 : 0]	# index of string table index in section table

		hdr.export[end_hdr] = hdr.virtsize

		sections.unshift(h_s = Section.new)
		h_s.name = :hdr
		h_s.edata = hdr
	end

	def link(program, target, sections, opts)
		virtaddr = opts.delete('prefered_base_adress') || (target == 'EXEC' ? 0x08048000 : 0)
		rawaddr  = 0

		has_segments = sections.find { |s| s.name == :phdr }
		binding = {}
		sections.each { |s|
			if has_segments
				if s.virt_gap
					if virtaddr & 0xfff >= 0xe00
						# small gap: align in file
						virtaddr = (virtaddr + 0xfff) & 0xffff_f000
						rawaddr  = (rawaddr  + 0xfff) & 0xffff_f000
					elsif virtaddr & 0xfff > 0
						# big gap: map page twice
						virtaddr += 0x1000
					end
				end
				if rawaddr & 0xfff != virtaddr & 0xfff
					virtaddr += ((rawaddr & 0xfff) - (virtaddr & 0xfff)) & 0xfff
				end
			end

			if s.align and s.align > 1
				virtaddr = (virtaddr + s.align - 1) / s.align * s.align
				rawaddr  = (rawaddr  + s.align - 1) / s.align * s.align
			end

			s.edata.export.each { |name, off| binding[name] = Expression[virtaddr, :+, off] }
			if s.rawoffset
				binding[s.rawoffset] = rawaddr
			else
				s.rawoffset = rawaddr
			end

			virtaddr += s.edata.virtsize if target != 'REL'
			rawaddr  += s.rawsize
		}

		sections.each { |s| s.edata.fixup binding }
		puts 'Unused ELF options: ' << opts.keys.sort_by { |k| k.to_s }.inspect unless opts.empty?
		raise EncodeError, "unresolved relocations: " + sections.map { |s| s.edata.reloc.map { |o, r| r.target.bind(binding).reduce } }.flatten.inspect if sections.find { |s| not s.edata.reloc.empty? }

		sections.inject(EncodedData.new) { |ed, s|
			ed.fill(binding[s.rawoffset] || s.rawoffset)
			ed << s.edata.data
		}.data
	end


	# 
	# decoder
	#
	
	def decode(str)
		edata = EncodedData.new str
		hdr = pre_decode_header edata
		shdr = pre_decode_sectionheader edata, hdr
		phdr = pre_decode_programheader edata, hdr
		
		case hdr['machine']
		when '386'
			cpu = Ia32.new
		else
			puts "unsupported CPU #{hdr['machine']}"
			cpu = UnknownCPU.new(32, hdr['endianness'])
		end

		pgm = Program.new cpu

		case hdr['type']
		when 'EXEC', 'DYN'
			opts = decode_load_segments(pgm, edata, phdr, hdr['machine'])
			opts['entrypoint'] = pgm.make_label(hdr['entry'], 'entrypoint')
			opts['additional_segments'] = phdr.reject { |ph| ph['type'] == 'LOAD' }
			opts['additional_segments'].delete phdr.find { |ph| ph['type'] == 'DYNAMIC' }	# delete only first
		when 'REL'
			opts = decode_load_sections(pgm, edata, shdr)
		end

		[pgm, opts]
	end

	def decode_load_segments(pgm, edata, phdr, arch)
		raise "no program header" if not phdr

		phdr.find_all { |ph| ph['type'] == 'LOAD' }.each { |ph|
			# create unique name
			name = bname = ph['flags'].include?('X') ? '.text' : ph['flags'].include?('W') ? '.data' : '.rodata'
			ctr = 0
			while pgm.sections.find { |s| s.name == name }
				ctr += 1
				name = bname + ".#{ctr}"
			end

			s = Metasm::Section.new(pgm, name)
			s.encoded << edata.data[ph['offset'], ph['filesz']]
			s.encoded.virtsize += ph['memsz'] - ph['filesz']
			s.base = ph['vaddr']
			pgm.sections << s
		}

		opts = {}
		if dyn = phdr.find { |ph| ph['type'] == 'DYNAMIC' }
			edata.ptr = dyn['offset']
			tags = pre_decode_tags(edata, pgm.cpu.endianness)
			# XXX what does the dynamic loader do with invalid tags ? (eg multiple STRTAB)
			tag_val = proc { |tag| tag = tags.find { |t, v| t == tag } ; tag[1] if tag }

			if strtab_addr = tag_val['STRTAB'] and strtab_s = pgm.sections.find { |s| s.base <= strtab_addr and s.base + s.encoded.virtsize > strtab_addr }
				strtab_off = strtab_addr - strtab_s.base
				read_strz = proc { |off| strtab_s.encoded.data[strtab_off + off...strtab_s.encoded.data.index(0, strtab_off+off)] }
			end

			tags.each { |t, v|
				case t
				when 'SONAME'
					opts['soname'] = read_strz[v]
				when 'NEEDED'
					(opts['needed'] ||= []) << read_strz[v]
				when 'INIT'
					opts['init'] = pgm.make_label(v, 'init')
				when 'FINI'
					opts['fini'] = pgm.make_label(v, 'fini')
				when 'RPATH'
					opts['rpath'] = read_strz[v].split(/[:;]/)
				end
			}

			# symbols XXX check hashed value ?
			if strtab_addr and symtab_addr = tag_val['SYMTAB'] and hash_addr = tag_val['HASH']
				symtab_s = pgm.sections.find { |s| s.base <= symtab_addr and s.base + s.encoded.virtsize > symtab_addr }
				symtab_off = symtab_addr - symtab_s.base if symtab_s
				hash_s = pgm.sections.find { |s| s.base <= hash_addr and s.base + s.encoded.virtsize > hash_addr }
				hash_off = hash_addr - hash_s.base if hash_s
				raise 'cannot find hash/sym/str table' if not strtab_s or not hash_s or not symtab_s
				hash_s.encoded.ptr = hash_off + 4
				symcount = Expression.decode_imm(hash_s.encoded, :u32, pgm.cpu.endianness)

				symtab_s.encoded.ptr = symtab_off
				syms = []
				symcount.times {
					sym = Symbol.new
					sym.name_p= Expression.decode_imm(symtab_s.encoded, :u32, pgm.cpu.endianness)
					sym.name  = read_strz[sym.name_p]
					sym.value = Expression.decode_imm(symtab_s.encoded, :u32, pgm.cpu.endianness)
					sym.size  = Expression.decode_imm(symtab_s.encoded, :u32, pgm.cpu.endianness)
					sym.info  = Expression.decode_imm(symtab_s.encoded,  :u8, pgm.cpu.endianness)
					sym.other = Expression.decode_imm(symtab_s.encoded,  :u8, pgm.cpu.endianness)
					sym.section = Expression.decode_imm(symtab_s.encoded, :u16, pgm.cpu.endianness)
					sym.section = SH_INDEX[sym.section] || sym.section
					sym.bind  = sym.info >> 4
					sym.bind  = SYMBOL_BIND[sym.bind] || sym.bind
					sym.type  = sym.info & 0xf
					sym.type  = SYMBOL_TYPE[sym.type] || sym.type
					syms << sym
				}

				syms[1..-1].each { |sym|
					case sym.bind
					when 'GLOBAL'
						case sym.section
						when 'UNDEF'
							libname = opts['soname'] || opts['needed'].to_a.first || 'any'
							(pgm.import[libname] ||= []) << sym.name
						when 'ABS', 'COMMON'
						#	puts "unhandled symbol #{sym.inspect}"	# used for relocs
						else
							addr = sym.value
							s = pgm.sections.find { |s| s.base <= addr and s.base + s.encoded.virtsize > addr }
							if s
								label = "exported_#{sym.name.gsub(/\W/, '_')}"
								s.encoded.export[label] = addr - s.base
								pgm.export[sym.name] = label
							end
						end
					when 'LOCAL'
						case sym.section
						when 'UNDEF', 'ABS', 'COMMON'
						#	puts "unhandled symbol #{sym.inspect}"	# used for relocs
						else
							addr = sym.value
							s = pgm.sections.find { |s| s.base <= addr and s.base + s.encoded.virtsize > addr }
							if s
								label = "exported_#{sym.name.gsub(/\W/, '_')}"
								s.encoded.export[label] = addr - s.base
							end
						end
					end
				}

			end

			if pltgot = tag_val['PLTGOT']
				type = DYNAMIC_TAG[tag_val['PLTREL']]
				raise 'invalid pltgot relocation type' if type != 'REL' and type != 'RELA'
				rels = pre_decode_relocs(pgm, syms, arch, tag_val['JMPREL'], tag_val[type + 'ENT'], tag_val['PLTRELSZ'], (type == 'RELA'))
				rels.each { |r|
					if r.type != 'JMP_SLOT'
						puts "ignoring plt reloc #{r.inspect}"
						next
					end
					off = r.offset
					s = pgm.sections.find { |s| s.base <= off and s.base + s.encoded.virtsize > off }
					if not s
						puts "ignoring unmapped relocation #{r.inspect}"
						next
					end
puts "reloc #{r.symbol.name} at #{off} (#{'%08x' % off})"
					off -= s.base
					s.encoded.reloc[off] = Metasm::Relocation.new(Expression[r.symbol.name], :u32, pgm.cpu.endianness)
					# TODO backtrack, and rename some label upper 'thunk_to_imported_#{name}'
				}

				off = pltgot
				s = pgm.sections.find { |s| s.base <= off and s.base + s.encoded.virtsize > off }
puts "reloc dlresolv at #{off} (#{'%08x' % off})"
				off -= s.base
				s.encoded.reloc[off] = Metasm::Relocation.new(Expression['dl_resolv_in_got'], :u32, pgm.cpu.endianness)
			end

			if tag_val['REL']
				raise 'invalid rel entsize' if tag_val['RELENT'] != 8
				rels = pre_decode_relocs(pgm, syms, arch, tag_val['REL'], tag_val['RELENT'], tag_val['RELSZ'])
				puts rels.map { |s| s.inspect }, ''
			end

			if tag_val['RELA']
				raise 'invalid rela entsize' if tag_val['RELAENT'] != 12
				rels = pre_decode_relocs(pgm, syms, arch, tag_val['RELA'], tag_val['RELAENT'], tag_val['RELASZ'], true)
				puts rels.map { |s| s.inspect }, ''
			end
		end

		opts
	end

	def pre_decode_tags(edata, endianness)
		tags = []
		tag = nil
		while tag != 'NULL'
			tag = Expression.decode_imm(edata, :u32, endianness)
			tag = DYNAMIC_TAG[tag] || tag
			val = Expression.decode_imm(edata, :u32, endianness)
			tags << [tag, val]
		end
		tags
	end

	def pre_decode_relocs(pgm, syms, arch, off, entsz, size, has_addend = false)
		endianness = pgm.cpu.endianness
		s = pgm.sections.find { |s| s.base <= off and s.base + s.encoded.virtsize > off }
		edata = s.encoded
		edata.ptr = off - s.base
		padlen = (has_addend ? 12 : 8) - entsz
		rels = []
		syms ||= []
		(size / entsz).times {
			rel = Relocation.new
			rel.offset = Expression.decode_imm(edata, :u32, endianness)
			rel.info   = Expression.decode_imm(edata, :u32, endianness)
			rel.addend = Expression.decode_imm(edata, :u32, endianness) if has_addend
			rel.symbol = rel.info >> 8
			rel.symbol = syms[rel.symbol] || rel.symbol
			rel.type   = rel.info & 15
			rel.type   = RELOCATION_TYPE[arch][rel.type] || rel.type
			edata.ptr += padlen
			rels << rel
		}
		rels
	end

	def pre_decode_header(edata)
		edata.ptr = 0
		hdr = {}
		hdr['ident'] = edata.data[edata.ptr, 16]
		edata.ptr += 16
		raise 'invalid ELF signature'   if hdr['ident'][0, 4] != "\x7fELF"
		raise 'ELF64 unsupported'       if hdr['ident'][4] != 1
		hdr['endianness'] = hdr['ident'][5] == 2 ? :big : :little
		raise 'unsupporded ELF version' if hdr['ident'][6] != 1
		# ei_flags ?

		# type, varname, hash
		[[:u16, 'type'], [:u16, 'machine'], [:u32, 'version'], [:u32, 'entry'],
		 [:u32, 'phoff'], [:u32, 'shoff'], [:u32, 'flags'], [:u16, 'ehsize'],
		 [:u16, 'phentsize'], [:u16, 'phnum'], [:u16, 'shentsize'], [:u16, 'shnum'],
		 [:u16, 'shstrndx']].each { |type, varname|
			hdr.update varname => Expression.decode_imm(edata, type, hdr['endianness'])
		}
		hdr['type']    = TYPE[hdr['type']] || hdr['type']
		hdr['machine'] = MACHINE[hdr['machine']] || hdr['machine']
		hdr['version'] = VERSION[hdr['version']] || hdr['version']
		hdr['flags']   = bits_to_hash(hdr['flags'], FLAGS)
		hdr
	end

	def pre_decode_sectionheader(edata, hdr)
		return [] if hdr['shoff'] == 0
		raise 'unhandled section header' if hdr['shentsize'] != 40

		edata.ptr = hdr['shoff']
		shdr = []
		hdr['shnum'].times {
			shdr << %w[name_p type flags addr offset size link info addralign entsize].inject({}) { |hash, varname|
				hash.update varname => Expression.decode_imm(edata, :u32, hdr['endianness'])
			}
		}

		stroff = shdr[hdr['shstrndx']]['offset'] rescue nil
		shdr.each { |sh|
			sh['flags'] = bits_to_hash(sh['flags'], SH_FLAGS)
			sh['type']  = SH_TYPE[sh['type']] || sh['type']
			off = stroff+sh['name_p']
			sh['name'] = edata.data[off...edata.data.index(0, off)] rescue nil
		}
		shdr
	end

	def pre_decode_programheader(edata, hdr)
		return [] if hdr['phoff'] == 0
		raise 'unhandled program header' if hdr['phentsize'] != 32

		edata.ptr = hdr['phoff']
		phdr = []
		hdr['phnum'].times {
			phdr << %w[type offset vaddr paddr filesz memsz flags align].inject({}) { |hash, varname|
				hash.update varname => Expression.decode_imm(edata, :u32, hdr['endianness'])
			}
		}
		phdr.each { |ph|
			ph['flags'] = bits_to_hash(ph['flags'], PH_FLAGS)
			ph['type']  = PH_TYPE[ph['type']] || ph['type']
		}
		phdr
	end
end
end
end

