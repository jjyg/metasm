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
	DYNAMIC_TAG = { 0 => 'NULL', 1 => 'NEEDED', 2 => 'PLTRELSZ', 3 => 'PLTGOT',
		4 => 'HASH', 5 => 'STRTAB', 6 => 'SYMTAB', 7 => 'RELA',
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

	SH_FLAGS = { 1 => 'WRITE', 2 => 'ALLOC', 4 => 'EXECINSTR', 0xf000_0000 => 'MASKPROC' }


class ELF < ExeFormat
	class Section
		attr_accessor :name, :type, :flags, :addr, :rawoffset, :link, :info, :align, :entsize, :edata
		def initialize
			@flags = []
		end
		
		def rawsize
			[@edata.data.length, *@edata.reloc.map { |off, rel| off + Expression::INT_SIZE[rel.type]/8 } ].max
		end
	end

class << self
	# options:
	# elf_target in ['so', 'exe', 'obj']
	# 'no_section_header' = true
	# 'no_program_header' = true
	def encode(program, opts={})
		sections = []
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

		# TODO create sym/d1ynamic/etc sections
		# XXX regroup sections by flag (1 big rw segment, 1 big rx segment)
		pre_encode_relocs( program, sections, opts) unless opts.delete('non_relocatable')
		pre_encode_symbols(program, sections, opts) unless opts.delete('no_full_symbols')
		pre_encode_dynsyms(program, sections, opts) unless opts.delete('static')		# XXX find real option name

		pre_encode_secthdr(program, sections, opts) unless opts.delete('no_section_header')
		pre_encode_proghdr(program, sections, opts) unless opts.delete('no_program_header')	# or elf_target == 'obj'
		pre_encode_header( program, sections, opts)

		link(program, sections, opts)
	end

	def pre_encode_relocs(program, sections, opts)

	end

	def pre_encode_symbols(program, sections, opts)
	end

	def pre_encode_dynsyms(program, sections, opts)
		# TODO on-demand instanciation

		sections << (str = Section.new)
		str.name = '.dynamic.str'	# XXX
		str.align = 1
		str.edata = EncodedData.new << 0
		str.type = 'STRTAB'
		str.flags << 'ALLOC'
		end_str = program.new_unique_label

		sections << (sym = Section.new)
		sym.name = '.symtab'
		sym.align = 4	# XXX
		sym.edata = EncodedData.new
		sym.type = 'SYMTAB'
		sym.flags << 'ALLOC'
		sym.link = sections.index(str)
		#sym.info = index_of_the_last_LOCAL_symbol + 1
		
		sections << (hash = Section.new)
		hash.name = '.hash'
		hash.align = 4
		hash.edata = EncodedData.new
		hash.type = 'HASH'
		hash.flags << 'ALLOC'
		hash.link = sections.index(sym)

		sections << (dynsym = Section.new)
		dynsym.name = '.dynsym'
		dynsym.align = 4
		dynsym.edata = EncodedData.new
		dynsym.type = 'DYNSYM'
		dynsym.flags << 'ALLOC'
		dynsym.link = sections.index(str)
		#dynsym.info = index_of_the_last_LOCAL_symbol + 1

		sections << (dynamic = Section.new)
		dynamic.name = '.dynamic'
		dynamic.align = 4
		dynamic.edata = EncodedData.new
		dynamic.type = 'DYNAMIC'
		dynamic.flags << 'ALLOC'
		dynamic.link = sections.index(str)

		tag = proc { |type, val| dynamic.edata <<
			Expression[int_from_hash(type, DYNAMIC_TAG)].encode(:u32, program.cpu.endianness) <<
			Expression[*val].encode(:u32, program.cpu.endianness)
		}

		tag['STRTAB', program.label_at(str.edata, 0)]
		tag['STRSZ', [end_str, :-, program.label_at(str.edata, 0)]]


		(program.import.keys + (opts.delete('needed') || [])).each { |libname|
			tag['NEEDED', str.edata.virtsize]
			str.edata << libname << 0
		}

		str.edata.export[end_str] = str.edata.virtsize
		tag['NULL', 0]	# end of array
	end

	def pre_encode_secthdr(program, sections, opts)
		# section containing section names
		sections << (shnam = Section.new)
		shnam.name = '.shstrtab'
		shnam.align = 1
		shnam.edata = EncodedData.new << 0
		shnam.type = 'STRTAB'

		# ensure shnam is the last section (a bit ugly, don't you think? Could reuse the existing, and scan/append names..)
		# XXX another thing could be using the old section index ? (or the index of a section after this one, becoming -= 1)
		#if shnamndx = opts.delete('shnamndx')
		#	shnam.name = sections.delete_at(shnamndx).name
		#end

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
		sections << Section.new
		sections.last.name  = :shdr
		sections.last.align = 4
		sections.last.edata = shdr
	end

	def pre_encode_proghdr(program, sections, opts)
		phdr = EncodedData.new
		sections << (phdr_s = Section.new)
		phdr_s.name = :phdr
		phdr_s.align = 4
		phdr_s.flags << 'ALLOC'
		phdr_s.edata = phdr

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


		if interp = opts.delete('elf_interp')
			sections << (s = Section.new)
			s.align = 1
			s.flags << 'ALLOC'
			s.edata = EncodedData.new << interp << 0
			s.rawoffset = program.new_unique_label

			encode_segm['INTERP',
				s.rawoffset,
				program.label_at(s.edata, 0),
				s.edata.virtsize,
				nil,
				['R'],
				s.align]
		end

		if not opts.delete('no_program_header_segment')
			end_hdr = program.new_unique_label
			encode_segm['PHDR',
				phdr_s.rawoffset ||= program.new_unique_label,
				program.label_at(phdr, 0),
				[end_hdr, :-, program.label_at(phdr, 0)],
				nil,
				['R'],
				phdr_s.align]
		end


		# merge sections in segments, try to avoid rwx segment (PaX)
		# TODO enforce noread/nowrite/noexec section specification ?
		lastprot = []
		seg_gap = [false]	# zipped with sections, returns true if a virtual addr gap is needed (rw -> rx)
					# preinit for the elf header pseudosection
		firstsect, rawsz, virtsz = nil
		sections.each { |s|
			xflags = s.flags & %w[EXECINSTR WRITE]
			if not firstsect
				if s.flags.include? 'ALLOC'
					firstsect, rawsz, virtsz = s, s.rawsize, s.edata.virtsize
					lastprot = (s.flags & %w[EXECINSTR WRITE]).sort
				end

				seg_gap << false
			elsif not s.flags.include? 'ALLOC' or xflags | lastprot == xflags or xflags.empty?	# allow R + RW, RW + R but not RW + RX (unless last == RWX)
				lastprot |= xflags if s.flags.include? 'ALLOC'
				rawsz = virtsz if virtsz > rawsz and s.rawsz > 0
				virtsz += s.edata.virtsize
				rawsz += s.rawsize

				seg_gap << false
			else
				encode_segm['LOAD',
					firstsect.rawoffset ||= program.new_unique_label,
					program.label_at(firstsect.edata, 0),
					rawsz, virtsz,
					['R', *{'WRITE' => 'W', 'EXECINSTR' => 'X'}.values_at(*lastprot).compact],
					0x1000
				]

				firstsect, rawsz, virtsz = s, s.rawsize, s.edata.virtsize
				lastprot = xflags

				seg_gap << true
			end
		}
		encode_segm['LOAD',
			firstsect.rawoffset ||= program.new_unique_label,
			program.label_at(firstsect.edata, 0),
			rawsz, virtsz,
			['R', *{'WRITE' => 'W', 'EXECINSTR' => 'X'}.values_at(*lastprot).compact],
			0x1000
		] if firstsect


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

		# arrays: [type, rawoff, virtoff/physoff, rawsz, memsz, flags, align]
		(opts.delete('additional_segments') || []).each { |sg| encode_segm[*sg] }

		phdr.export[end_hdr] = phdr.virtsize if end_hdr

		raise 'reserved metasm internal ELF option "section_virtual_gap" used !' if opts.has_key? 'section_virtual_gap'
		opts['section_virtual_gap'] = seg_gap
	end

	def pre_encode_header(program, sections, opts)
		hdr = EncodedData.new

		end_hdr = program.new_unique_label

		hdr << 0x7f << 'ELF'
		hdr << CLASS.index(program.cpu.size.to_s)	# 16bits ?
		hdr << DATA.index( {:little => 'LSB', :big => 'MSB'}[program.cpu.endianness] )
	 
		e_version = int_from_hash(opts.delete('e_version') || 'CURRENT', VERSION)
		hdr << e_version
		hdr.fill(16, "\0")

		encode = proc { |type, val| hdr << Expression[*val].encode(type, program.cpu.endianness) }

		encode[:u16, int_from_hash(opts.delete('e_type') || 'EXEC', TYPE)]
		encode[:u16, int_from_hash(opts.delete('e_machine') || '386', MACHINE)] # TODO check program.cpu.class or something
		encode[:u32, e_version]

		entrypoint = opts.delete('entrypoint') || 'start'
		if not entrypoint.kind_of? Integer and not program.sections.find { |s| s.encoded.export[entrypoint] }
			puts 'W: No entrypoint defined'	# TODO if e_type == 'ET_DYN' or e_type == 'ET_EXEC'
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
		encode[:u16, shdr ? shdr.edata.virtsize / 0x28 - 1 : 0]	# index of string table index in section table (must be the last as created by pre_encode_section_header, 0 if none)

		hdr.export[end_hdr] = hdr.virtsize

		sections.unshift Section.new
		sections.first.name = :hdr
		sections.first.edata = hdr
	end

	def link(program, sections, opts)
		seg_gap = opts.delete('section_virtual_gap') || []

		virtaddr = opts.delete('prefered_base_adress') || 0x08048000	# TODO case target ...
		rawaddr  = 0
		rawaddrs = []

		binding = {}
		sections.zip(seg_gap).each { |s, gap|
			if rawaddr % 0x1000 != virtaddr % 0x1000 and s.flags.include? 'ALLOC'
				virtaddr += ((rawaddr % 0x1000) - (virtaddr % 0x1000)) % 0x1000
			end
			if gap
				if virtaddr % 0x1000 > 0xf00
					# small gap: align in file to page boundary
					s.align = 0x1000
				elsif virtaddr % 0x1000 > 0
					# big gap: map page twice
					virtaddr += 0x1000
				end
			end
			rawaddr  = (rawaddr  + s.align - 1) / s.align * s.align if s.align and s.align > 1
			virtaddr = (virtaddr + s.align - 1) / s.align * s.align if s.align and s.align > 1

			s.edata.export.each { |name, off| binding[name] = Expression[virtaddr, :+, off] }
			binding[s.rawoffset] = rawaddr if s.rawoffset

			rawaddrs << rawaddr

			virtaddr += s.edata.virtsize
			rawaddr += s.edata.data.size
		}

		sections.each { |s| s.edata.fixup binding }
		# raise Foo if sections.find { |s| not s.reloc.empty? }

		sections.inject(EncodedData.new) { |ed, s| ed.fill rawaddrs.shift ; ed << s.edata.data }.data
	end
end
end
end

