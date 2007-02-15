require 'metasm/exe_format/main'

module Metasm
	CLASS = { 0 => 'NONE', 1 => '32', 2 => '64' }
	DATA  = { 0 => 'NONE', 1 => 'LSB', 2 => 'MSB' }
	VERSION = { 0 => 'INVALID', 1 => 'CURRENT' }
	TYPE = { 0 => 'NONE', 1 => 'REL', 2 => 'EXEC', 3 => 'DYN', 4 => 'CORE',
		0xff00 => 'LOPROC', 0xffff => 'HIPROC' }
	MACHINE = { 0 => 'NONE', 1 => 'M32', 2 => 'SPARC', 3 => '386',
		4 => '68K', 5 => '88K', 7 => '860', 8 => 'MIPS' }

	# XXX ia32 only
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


class ELF < ExeFormat
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
		attr_accessor :name, :value, :size, :bind, :type, :other, :section
	end

	class Reloc
		attr_accessor :offset, :type, :symbol, :section
	#	def info ; (@symbol << 8) + @type end
	#	def info=(i) @symbol = i >> 8 ; @type = i & 0xff end
	end

class << self
	# options:
	# 'elf_target' in ['REL', 'EXEC', 'DYN']
	# 'no_section_header' bool
	# 'no_program_header' bool
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

		# XXX regroup sections by flag (1 big rw segment, 1 big rx segment)
		# dynamic for exe/so, relocs for obj ?
		pre_encode_dynamic(program, target, sections, opts) unless opts.delete('no_dynamic')

		pre_encode_secthdr(program, target, sections, opts) unless opts.delete('no_section_header')
		pre_encode_proghdr(program, target, sections, opts) unless opts.delete('no_program_header')	# or elf_target == 'obj'
		pre_encode_header( program, target, sections, opts)

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

	def pre_encode_dynamic(program, target, sections, opts)
		encode = proc { |sect, type, val| sect.edata << Expression[*val].encode(type, program.cpu.endianness) }

		use_va = (target == 'EXEC' or target == 'DYN')

		str = Section.new
		str.name = '.dynstr'
		str.align = 1
		str.edata = EncodedData.new << 0
		str.type = 'STRTAB'
		str.flags << 'ALLOC'

		hash = Section.new
		hash.name = '.hash'
		hash.align = 4
		hash.edata = EncodedData.new
		hash.type = 'HASH'
		hash.entsize = 4
		hash.flags << 'ALLOC'

		if use_va
			dynamic = Section.new
			dynamic.name = '.dynamic'
			dynamic.align = 4
			dynamic.edata = EncodedData.new
			dynamic.type = 'DYNAMIC'
			dynamic.entsize = 8
			dynamic.flags << 'ALLOC'
		end

		sym = Section.new
		sym.align = 4
		sym.edata = EncodedData.new
		sym.flags << 'ALLOC'
		sym.entsize = 0x10

		symlist = []

		# TODO add parser support for sym.size / sym.type
		if opts.delete('unstripped')
			sym.name = '.symtab'
			sym.type = 'SYMTAB'
		
			sections.each { |sect|
				sect.edata.export.each { |name, off|
					# next if name =~ new_unique_label
					s = Symbol.new
					s.name = name
					s.bind = program.export[name] ? 'GLOBAL' : 'LOCAL'
					s.section = sect
					s.value = use_va ? name : off
					symlist << s
				}
			}
		else
			sym.name = '.dynsym'
			sym.type = 'DYNSYM'

			program.export.each { |name, label|
				s = Symbol.new
				s.name = name
				s.bind = 'GLOBAL'
				if use_va
					s.value = label
				else
					s.section = sections.find { |sect| s.value = sect.edata.export[label] }
				end
				symlist << s
			}
		end

#pre_sections = sections.dup
		sections.unshift(str, hash, sym)
		if dynamic
			sections.unshift(dynamic)
		# from this point, the section table is complete, and one can use section indexes (XXX indexes start at 1)
			dynamic.link = sections.index(str) + 1
		end
		hash.link = sections.index(sym) + 1
		sym.link = sections.index(str) + 1


		new_string = proc { |string|
			ret = str.edata.virtsize
			str.edata << string << 0
			ret
		}

		# array of name/symbol index, for hash table construction
		stringlist = []

		add_sym = proc { |s|
			if s.name
				stringlist << [s.name, sym.edata.virtsize / sym.entsize]
				encode[sym, :u32, new_string[s.name]]
			else
				encode[sym, :u32, 0]
			end
			encode[sym, :u32, s.value || 0]
			encode[sym, :u32, s.size || 0]
			encode[sym, :u8, [[int_from_hash(s.bind || 'LOCAL', SYMBOL_BIND), :<<, 4], :|, int_from_hash(s.type || 'NOTYPE', SYMBOL_TYPE)]]
			encode[sym, :u8, s.other || 0]
			sndx = sections.index(s.section)
			sndx = sndx ? sndx + 1 : int_from_hash(s.section || 'UNDEF', SH_INDEX)
			encode[sym, :u16, sndx]
		}

		add_sym[Symbol.new]	# 1st entry NULL
#pre_sections.each { |ps| s = Symbol.new ; s.value = ps.rawoffset ; s.bind = 'SECTIONS' ; s.section = ps ; add_sym[s] }	# ??? docs => 'used for relocations', not found in ET_EXEC
		symlist.each { |s| add_sym[s] if s.bind == 'LOCAL' }
		sym.info = sym.edata.virtsize / 0x10	# index of the last local sym + 1
		symlist.each { |s| add_sym[s] if s.bind != 'LOCAL' }


		# to find a symbol from its name :
		# 1 idx = hash(name)
		# 2 idx = bucket[idx % bucket.size]
		# 3 if idx == 0: return notfound
		# 4 if symtable[idx].name == name: return found
		# 5 idx = chain[idx] ; goto 3
		hash_bucket = Array.new(stringlist.length / 4 + 1, 0)
		hash_chain  = Array.new(sym.edata.virtsize / sym.entsize, 0)
		stringlist.each { |name, index|
			h = symbol_hash(name)
			hash_chain[index] = hash_bucket[h % hash_bucket.length]
			hash_bucket[h % hash_bucket.length] = index
		}
		encode[hash, :u32, hash_bucket.length]
		encode[hash, :u32, hash_chain.length]
		hash_bucket.each { |b| encode[hash, :u32, b] }
		hash_chain.each  { |c| encode[hash, :u32, c] }

		# TODO
		relocs = []
		if use_va
			plt = nil
			got = nil
			program.import.values.each { |ilist|
				ilist.each { |importname, thunkname|
					if thunkname
						plt ||= EncodedData.new << "jmp [xx]"
						plt.export[thunkname] = plt.virtsize
						# got in ebx or hardcoded, cpu.encode_thunk(importname), ...
					end
					# got
				}
			}
			# jmprel / .got.rel
		else
			# .*.rel
		end
	


		return if not dynamic


		tag = proc { |type, val|
			dynamic.edata <<
			Expression[int_from_hash(type, DYNAMIC_TAG)].encode(:u32, program.cpu.endianness) <<
			Expression[*val].encode(:u32, program.cpu.endianness)
		}

		(program.import.keys + opts.delete('needed').to_a).each { |libname|
			tag['NEEDED', new_string[libname]]
		}

		tmp = nil
		tag['INIT', tmp] if tmp = opts.delete('init')
		tag['FINI', tmp] if tmp = opts.delete('fini')

		tag['SONAME', new_string[tmp]] if tmp = opts.delete('soname')

		tag['HASH', program.label_at(hash.edata, 0)]
		tag['STRTAB', program.label_at(str.edata, 0)]
		tag['SYMTAB', program.label_at(sym.edata, 0)]
		tag['STRSZ', str.edata.virtsize]
		tag['SYMENT', 16]

#		tag['PLTGOT', program.label_at(got.edata, 0)]
#		tag['PLTRELSZ', got_rels.edata.virtsize]
#		tag['PLTREL', PLT_REL_TYPE.index('REL')]
#		tag['JMPREL', program.label_at(got_rels.edata, 0)]

#		tag['REL', program.label_at(rel, 0)]
#		tag['RELSZ', [end_rel, :-, program.label_at(rel, 0)]]
#		tag['RELENT', 8]

		tag['NULL', 0]	# end of array
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
			encode[rawoff]
			encode[virtoff]
			encode[virtoff]
			encode[rawsz]
			encode[virtsz ? virtsz : rawsz]
			encode[bits_from_hash(flags, PH_FLAGS)]
			encode[align]
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
			elsif firstsect and (xflags | lastprot == xflags or xflags.empty?)	# concat for R+RW / RW + R, not for RW+RX (unless last == RWX)
				if lastsect.edata.virtsize > lastsect.rawsize + 0x1000
					# TODO new_seg
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
		# arrays: [type, rawoff, virtoff/physoff, rawsz, memsz, flags, align]
		(opts.delete('additional_segments') || []).each { |sg| encode_segm[*sg] }


		phdr.export[end_phdr] = phdr.virtsize if end_phdr
	end

	def pre_encode_header(program, target, sections, opts)
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
		encode[:u16, int_from_hash(opts.delete('e_machine') || '386', MACHINE)] # TODO check program.cpu.class or something
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
		# raise Foo if sections.find { |s| not s.reloc.empty? }

		sections.inject(EncodedData.new) { |ed, s|
			ed.fill(binding[s.rawoffset] || s.rawoffset)
			ed << s.edata.data
		}.data
	end
end
end
end

