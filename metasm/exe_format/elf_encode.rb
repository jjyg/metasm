#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/encode'
require 'metasm/exe_format/elf'

module Metasm
class ELF
	class Header
		def encode elf
			set_default_values elf

			h = EncodedData.new <<
			"\x7fELF" <<
			case @e_class
			when 32: 1
			when 64: 2
			else raise "E: Elf: unsupported class #@e_class"
			end <<
			case @endianness
			when :little: 1
			when :big: 2
			else raise "E: Elf: unsupported endianness #@endianness"
			end <<
			1 <<
			elf.int_from_hash(@abi, ABI) <<
			@abi_version

			h.align 16

			h <<
			elf.encode_half(elf.int_from_hash(@type, TYPE)) <<
			elf.encode_half(elf.int_from_hash(@machine, MACHINE)) <<
			elf.encode_word(elf.int_from_hash(@version, VERSION)) <<
			elf.encode_addr(@entry) <<
			elf.encode_off( @phoff) <<
			elf.encode_off( @shoff) <<
			elf.encode_word(elf.bits_from_hash(@flags, FLAGS[@machine])) <<
			elf.encode_half(@ehsize) <<
			elf.encode_half(@phentsize) <<
			elf.encode_half(@phnum) <<
			elf.encode_half(@shentsize) <<
			elf.encode_half(@shnum) <<
			elf.encode_half(@shstrndx)
		end

		def set_default_values elf
		#	@e_class   ||= elf.cpu.size			# those are heavily used by all other encode, and must be set long before we get here
		#	@endianness||= elf.cpu.endianness
			@type      ||= 'EXEC'
			@machine   ||= '386'	# TODO			# should probably be set at the same time as class/endianness
			@version   ||= 1
			@abi       ||= 0
			@abi_version ||= 0
			@entry     ||= 'entrypoint'
			@phoff     ||= elf.new_label('phdr')
			@shoff     ||= elf.new_label('shdr')
			@flags     ||= 0
			@ehsize    ||= 52
			@phentsize ||= Segment.size(elf)
			@phnum     ||= elf.segments.to_a.length
			@shentsize ||= Section.size(elf)
			@shnum     ||= elf.sections.to_a.length
			@shstrndx  ||= 0

		end
	end

	class Section
		# needs elf.encoded (for offset)
		def encode elf
			set_default_values elf

			elf.encode_word( @name_p) <<
			elf.encode_word(elf.int_from_hash(@type, SH_TYPE)) <<
			elf.encode_xword(elf.bits_from_hash(@flags, SH_FLAGS)) <<
			elf.encode_addr( @addr) <<
			elf.encode_off(  @offset) <<
			elf.encode_xword(@size) <<
			elf.encode_word( @link.kind_of?(Section) ? elf.sections.index(@link) : @link) <<
			elf.encode_word( @info.kind_of?(Section) ? elf.sections.index(@info) : @info) <<
			elf.encode_xword(@addralign) <<
			elf.encode_xword(@entsize)
		end

		def set_default_values elf
			@name_p ||= default_make_name_p elf	# must occur before @size default initialization, for section[shstrndx]
			@type   ||= 0
			@flags  ||= [0]
			@addr   ||= (@encoded and @flags.include?('ALLOC')) ? elf.label_at(@encoded, 0) : 0
			@offset ||= @encoded ? elf.new_label('section_offset') : 0
			@size   ||= @encoded ? @encoded.length : 0
			@link   ||= 0
			@info   ||= 0
			@addralign ||= @entsize || 0
			@entsize ||= @addralign
		end

		# returns the @name_p field, after adding @name to .shstrndx (creating it if needed)
		def default_make_name_p elf
			return 0 if not @name or @name.empty?
			if elf.header.shstrndx.to_i == 0
				sn = Section.new
				sn.name = '.shstrndx'
				sn.type = 'STRTAB'
				sn.addralign = 1
				sn.encoded = EncodedData.new << 0
				elf.header.shstrndx = elf.sections.length
				elf.sections << sn
			end
			sn = elf.sections[elf.header.shstrndx]
			ptr = sn.encoded.virtsize
			sn.encoded << @name << 0
			ptr
		end
	end

	class Segment
		def encode elf
			set_default_values elf

			elf.encode_word(elf.int_from_hash(@type, PH_TYPE)) <<
			(elf.encode_word(elf.bits_from_hash(@flags, PH_FLAGS)) if elf.header.e_class == 64) <<
			elf.encode_off( @offset) <<
			elf.encode_addr(@vaddr) <<
			elf.encode_addr(@paddr) <<
			elf.encode_xword(@filesz) <<
			elf.encode_xword(@memsz) <<
			(elf.encode_word(elf.bits_from_hash(@flags, PH_FLAGS)) if elf.header.e_class == 32) <<
			elf.encode_xword(@align)
		end

		def set_default_values elf
			@type   ||= 0
			@flags  ||= 0
			@offset ||= @encoded ? elf.new_label('segment_offset') : 0
			@vaddr  ||= @encoded ? elf.label_at(@encoded, 0) : 0
			@paddr  ||= @vaddr
			@filesz ||= @encoded ? @encoded.rawsize : 0
			@memsz  ||= @encoded ? @encoded.virtsize : 0
			@align  ||= 0
		end
	end

	class Symbol
		def encode(elf, strtab=nil)
			set_default_values elf, strtab

			case elf.header.e_class
			when 32
				elf.encode_word(@name_p) <<
				elf.encode_addr(@value) <<
				elf.encode_word(@size) <<
				elf.encode_uchar(@info) <<
				elf.encode_uchar(@other) <<
				elf.encode_half(elf.int_from_hash(@shndx, SH_INDEX))
			when 64
				elf.encode_word(@name_p) <<
				elf.encode_uchar(@info) <<
				elf.encode_uchar(@other) <<
				elf.encode_half(elf.int_from_hash(@shndx, SH_INDEX)) <<
				elf.encode_addr(@value) <<
				elf.encode_xword(@size)
			end
		end

		def set_default_values(elf, strtab)
			@name_p ||= default_make_name_p elf, strtab
			@value  ||= 0
			@size   ||= 0
			@bind  ||= 0
			@type  ||= 0
			@info   ||= ((elf.int_from_hash(@bind, SYMBOL_BIND) & 15) << 4) | (elf.int_from_hash(@type, SYMBOL_TYPE) & 15)
			@other  ||= 0
			@shndx = elf.sections.index(@shndx) if @shndx.kind_of? Section
			@shndx  ||= 0
		end

		# returns the value of @name_p, after adding @name to the symbol string table
		def default_make_name_p(elf, strtab)
			ret = 0
			if @name and not @name.empty?
				raise 'E: Elf: need string table to store symbol names' if not strtab
				if not ret = strtab.data.index(@name + 0.chr)
					ret = strtab.virtsize
					strtab << @name << 0
				end
			end
			ret
		end
	end

	class Relocation
		def encode(elf, ary=nil)
			set_default_values elf, ary

			elf.encode_addr(r, @offset) <<
			elf.encode_xword(r, @info) <<
			(elf.encode_sxword(r, @addend) if @addend)
		end

		def set_default_values(elf, ary)
			@offset ||= 0
			@symbol ||= 0
			@type  ||= 0
			@info   ||= default_make_info elf, ary
		end

		# returns the numeric value of @info from @type and @symbol
		def default_make_info(elf, ary)
			type = elf.int_from_hash(@type, RELOCATION_TYPE.fetch(elf.header.machine, {}))
			symb = @symbol.kind_of?(Symbol) ? ary.index(@symbol) : @symbol
			case elf.header.e_class
			when 32: (type & 0xff) | ((symb & 0xff_ffff) << 8)
			when 64: (type & 0xffff_ffff) | ((symb & 0xffff_ffff) << 32)
			end
		end
	end


	def encode_uchar(w)  Expression[w].encode(:u8,  @header.endianness) end
	def encode_half(w)   Expression[w].encode(:u16, @header.endianness) end
	def encode_word(w)   Expression[w].encode(:u32, @header.endianness) end
	def encode_sword(w)  Expression[w].encode(:i32, @header.endianness) end
	def encode_xword(w)  Expression[w].encode((@header.e_class == 32 ? :u32 : :u64), @header.endianness) end
	def encode_sxword(w) Expression[w].encode((@header.e_class == 32 ? :i32 : :i64), @header.endianness) end
	alias encode_addr encode_xword
	alias encode_off  encode_xword

	def encode_check_section_size(s)
		if s.size and s.encoded.virtsize < s
			puts "W: Elf: preexisting section #{s} has grown, relocating"
			s.addr = s.offset = nil
			s.size = s.encoded.virtsize
		end
	end

	def encode_reorder_symbols
		gnu_hash_bucket_length = 42	# TODO
		@symbols[1..-1] = @symbols[1..-1].sort_by { |s|
			if s.bind != 'GLOBAL'
				-2
			elsif s.shndx == 'UNDEF' or not s.name
				-1
			else
				ELF.gnu_hash_symbol_name(s.name) % gnu_hash_bucket_length
			end
		}
	end

	# adds a new sections to the existing array, insert the new one near other with same permissions (for easier segment merge)
	def encode_add_section s
		# order: r rx rw noalloc
		rank = proc { |sec|
			f = sec.flags
			sec.type == 'NULL' ? -1 :
			f.include?('ALLOC') ? !f.include?('WRITE') ? !f.include?('EXECINSTR') ? 0 : 1 : 2 : 3
		}
		srank = rank[s]
		nexts = @sections.find { |sec| rank[sec] > srank }	# find section with rank superior
		nexts = nexts ? @sections.index(nexts) : -1		# if none, last
		@sections.insert(nexts, s)				# insert section
	end

	# encodes the GNU_HASH table (not implemented)
	def encode_gnu_hash
		return if true

		return if not @symbols

		sortedsyms = @symbols.find_all { |s| s.bind == 'GLOBAL' and s.shndx != 'UNDEF' and s.name }
		bucket = Array.new(42)

		if not gnu_hash = @sections.find { |s| s.type == 'GNU_HASH' }
			gnu_hash = Section.new
			gnu_hash.name = '.gnu.hash'
			gnu_hash.type = 'GNU_HASH'
			gnu_hash.flags = ['ALLOC']
			gnu_hash.entsize = gnu_hash.addralign = 4
			encode_add_section gnu_hash
		end
		gnu_hash.encoded = EncodedData.new

		# "bloomfilter[N] has bit B cleared if there is no M (M > symndx) which satisfies (C = @header.class)
		# ((gnu_hash(sym[M].name) / C) % maskwords) == N	&&
		# ((gnu_hash(sym[M].name) % C) == B			||
		# ((gnu_hash(sym[M].name) >> shift2) % C) == B"
		# bloomfilter may be [~0]
		bloomfilter = []
		
		# bucket[N] contains the lowest M for which
		# gnu_hash(sym[M]) % nbuckets == N
		# or 0 if none
		bucket = []

		gnu_hash.encoded <<
		encode_word(bucket.length) <<
		encode_word(@symbols.length - sortedsyms.length) <<
		encode_word(bloomfilter.length) <<
		encode_word(shift2)
		bloomfilter.each { |bf| gnu_hash.encoded << encode_xword(bf) }
		bucket.each { |bk| gnu_hash.encoded << encode_word(bk) }
		sortedsyms.each { |s|
			# (gnu_hash(sym[N].name) & ~1) | (N == dynsymcount-1 || (gnu_hash(sym[N].name) % nbucket) != (gnu_hash(sym[N+1].name) % nbucket))
			# that's the hash, with its lower bit replaced by the bool [1 if i am the last sym having my hash as hash]
			val = 28
			gnu_hash.encoded << encode_word(val)
		}

		@tag['GNU_HASH'] = label_at(gnu_hash.encoded, 0)

		encode_check_section_size gnu_hash

		gnu_hash
	end

	# encodes the symbol dynamic hash table in the .hash section, updates the HASH tag
	def encode_hash
		return if not @symbols

		if not hash = @sections.find { |s| s.type == 'HASH' }
			hash = Section.new
			hash.name = '.hash'
			hash.type = 'HASH'
			hash.flags = ['ALLOC']
			hash.entsize = hash.addralign = 4
			encode_add_section hash
		end
		hash.encoded = EncodedData.new
		
		# to find a symbol from its name :
		# 1: idx = hash(name)
		# 2: idx = bucket[idx % bucket.size]
		# 3: if idx == 0: return notfound
		# 4: if dynsym[idx].name == name: return found
		# 5: idx = chain[idx] ; goto 3
		bucket = Array.new(@symbols.length/4+1, 0)
		chain =  Array.new(@symbols.length, 0)
		@symbols.each_with_index { |s, i|
			next if s.bind == 'LOCAL' or not s.name or s.shndx == 'UNDEF'
			hash_mod = ELF.hash_symbol_name(s.name) % bucket.length
			chain[i] = bucket[hash_mod]
			bucket[hash_mod] = i
		}

		hash.encoded << encode_word(bucket.length) << encode_word(chain.length)

		bucket.each { |b| hash.encoded << encode_word(b) }
		chain.each { |c| hash.encoded << encode_word(c) }

		@tag['HASH'] = label_at(hash.encoded, 0)

		encode_check_section_size hash

		hash
	end

	# encodes the symbol table
	# should have a stable self.sections array (only append allowed after this step)
	def encode_segments_symbols(strtab)
		return if not @symbols

		if not dynsym = @sections.find { |s| s.type == 'DYNSYM' }
			dynsym = Section.new
			dynsym.name = '.dynsym'
			dynsym.type = 'DYNSYM'
			dynsym.entsize = dynsym.addralign = Symbol.size(self)
			dynsym.flags = ['ALLOC']
			dynsym.info = @symbols.find_all { |s| s.bind == 'LOCAL' }.length
			dynsym.link = strtab
			encode_add_section dynsym
		end
		dynsym.encoded = EncodedData.new
		@symbols.each { |s| dynsym.encoded << s.encode(self, strtab.encoded) }	# needs all section indexes, as will be in the final section header

		@tag['SYMTAB'] = label_at(dynsym.encoded, 0)
		@tag['SYMENT'] = Symbol.size(self)

		encode_check_section_size dynsym

		dynsym
	end

	# encodes the relocation tables
	# needs a complete self.symbols array
	def encode_segments_relocs
		return if not @relocations

		list = @relocations.find_all { |r| r.type == 'JMP_SLOT' }
		if not list.empty?
			list.each { |r| r.addend ||= 0 } if list.find { |r| r.addend }	# ensure list is homogenous
			if not relplt = @sections.find { |s| s.type == 'REL' and s.name == '.rel.plt' } 	# XXX arch-dependant ?
				relplt = Section.new
				relplt.name = '.rel.plt'
				relplt.flags = ['ALLOC']
				encode_add_section relplt
			end
			relplt.encoded = EncodedData.new
			list.each { |r| relplt.encoded << r.encode(self, @symbols) }
			@tag['JMPREL'] = label_at(relplt.encoded, 0)
			@tag['PLTRELSZ'] = relplt.encoded.virtsize
			if not list.first.addend
				@tag['PLTREL'] = relplt.type = 'REL'
				@tag['RELENT']  = relplt.entsize = relplt.addralign = Relocation.size(self)
			else
				@tag['PLTREL'] = relplt.type = 'RELA'
				@tag['RELAENT'] = relplt.entsize = relplt.addralign = Relocation.size_a(self)
			end
			encode_check_section_size relplt
		end

		list = @relocations.find_all { |r| r.type != 'JMP_SLOT' and not r.addend }
		if not list.empty? or @relocations.empty?
			if not rel = @sections.find { |s| s.type == 'REL' and s.name == '.rel.dyn' }
				rel = Section.new
				rel.name = '.rel.dyn'
				rel.type = 'REL'
				rel.flags = ['ALLOC']
				rel.entsize = rel.addralign = Relocation.size(self)
				encode_add_section rel
			end
			rel.encoded = EncodedData.new
			list.each { |r| rel.encoded << r.encode(self, @symbols) }
			@tag['REL'] = label_at(rel.encoded, 0)
			@tag['RELENT'] = Relocation.size(self)
			@tag['RELSZ'] = rel.encoded.virtsize
			encode_check_section_size rel
		end

		list = @relocations.find_all { |r| r.type != 'JMP_SLOT' and r.addend }
		if not list.empty?
			if not rela = @sections.find { |s| s.type == 'RELA' and s.name == '.rela.dyn' }
				rela = Section.new
				rela.name = '.rela.dyn'
				rela.type = 'RELA'
				rela.flags = ['ALLOC']
				rela.entsize = rela.addralign = Relocation.size_a(self)
				encode_add_section rela
			end
			rela.encoded = EncodedData.new
			list.each { |r| rela.encoded << r.encode(self, @symbols) }
			@tag['RELA'] = label_at(rela.encoded, 0)
			@tag['RELAENT'] = Relocation.size(self)
			@tag['RELASZ'] = rela.encoded.virtsize
			encode_check_section_size rela
		end
	end

	# encodes the .dynamic section, creates .hash/.gnu.hash/.rel/.rela/.dynsym/.strtab/.init,*_array as needed
	def encode_segments_dynamic
		if not strtab = @sections.find { |s| s.type == 'STRTAB' and s.flags.include? 'ALLOC' }
			strtab = Section.new
			strtab.name = '.dynstr'
			strtab.addralign = 1
			strtab.type = 'STRTAB'
			strtab.flags = ['ALLOC']
			strtab.encoded = EncodedData.new << 0
			strtab.flags 
			encode_add_section strtab
		end
		@tag['STRTAB'] = label_at(strtab.encoded, 0)

		if not dynamic = @sections.find { |s| s.type == 'DYNAMIC' }
			dynamic = Section.new
			dynamic.name = '.dynamic'
			dynamic.type = 'DYNAMIC'
			dynamic.flags = %w[WRITE ALLOC]		# XXX why write ?
			dynamic.addralign = dynamic.entsize = @header.e_class / 8 * 2
			dynamic.link = strtab
			encode_add_section dynamic
		end
		dynamic.encoded = EncodedData.new

		encode_tag = proc { |k, v|
			dynamic.encoded <<
			encode_sxword(int_from_hash(k, DYNAMIC_TAG)) <<
			encode_xword(v)
		}

		# find or create string in strtab
		add_str = proc { |n|
			if n and not n.empty? and not ret = strtab.encoded.data.index(n + 0.chr)
				ret = strtab.encoded.virtsize
				strtab.encoded << n << 0
			end
			ret || 0
		}
		@tag.keys.each { |k|
			case k
			when 'NEEDED': @tag[k].each { |n| encode_tag[k, add_str[n]] }
			when 'SONAME', 'RPATH', 'RUNPATH': encode_tag[k, add_str[@tag[k]]]
			when 'INIT_ARRAY', 'FINI_ARRAY', 'PREINIT_ARRAY'	# build section containing the array
				if not ar = @sections.find { |s| s.name == '.' + k.downcase }
					ar = Section.new
					ar.name = '.' + k.downcase
					ar.type = k
					ar.addralign = ar.entsize = @header.e_class/8
					ar.flags = %w[WRITE ALLOC]	# why write ? base reloc ?
					encode_add_section ar # insert before encoding syms/relocs (which need section indexes)
				end
				# fill these later
			end
		}

		encode_reorder_symbols
		encode_gnu_hash
		encode_hash
		encode_segments_relocs
		dynsym = encode_segments_symbols(strtab)
		@sections.find_all { |s| %w[HASH GNU_HASH REL RELA].include? s.type }.each { |s| s.link = dynsym }

		encode_check_section_size strtab

		# XXX any order needed ?
		@tag.keys.each { |k|
			case k
			when Integer	# unknown tags = array of values
				@tag[k].each { |n| encode_tag[k, n] }
			when 'PLTREL':     encode_tag[k,  int_from_hash(@tag[k], DYNAMIC_TAG)]
			when 'FLAGS':      encode_tag[k, bits_from_hash(@tag[k], DYNAMIC_FLAGS)]
			when 'FLAGS_1':    encode_tag[k, bits_from_hash(@tag[k], DYNAMIC_FLAGS_1)]
			when 'FEATURES_1': encode_tag[k, bits_from_hash(@tag[k], DYNAMIC_FEATURES_1)]
			when 'NULL'	# keep last
			when 'STRTAB'
				encode_tag[k, @tag[k]]
				encode_tag['STRSZ', strtab.encoded.size]
			when 'INIT_ARRAY', 'FINI_ARRAY', 'PREINIT_ARRAY'	# build section containing the array
				ar = @sections.find { |s| s.name == '.' + k.downcase }
				ar.encoded = EncodedData.new
				@tag[k].each { |p| ar.encoded << encode_addr(p) }
				encode_check_section_size ar
				encode_tag[k, label_at(ar.encoded, 0)]
				encode_tag[k + 'SZ', ar.encoded.virtsize]
			when 'NEEDED', 'SONAME', 'RPATH', 'RUNPATH'	# already handled
			else 
				encode_tag[k, @tag[k]]
			end
		}
		encode_tag['NULL', @tag['NULL'] || 0]

		encode_check_section_size dynamic
	end

	# reads the existing segment/sections.encoded and populate @relocations from the encoded.reloc hash
	def create_relocations
		@relocations = []
	end

	# create the relocations from the sections.encoded.reloc
	# create the dynamic sections
	# put sections/phdr in PT_LOAD segments
	# link
	# TODO support mapped PHDR, obey section-specified base address, handle NOBITS
	def encode
		if @sections.empty? or @sections.first.type != 'NULL'
			s = Section.new
			s.type = 'NULL'
			s.flags = []
			@sections.unshift s
		end

		create_relocations
		encode_segments_dynamic

		prot_match = proc { |seg, sec|
			(sec.include?('WRITE') == seg.include?('W')) # and (sec.include?('EXECINSTR') == seg.include?('X'))
		}

		# put every section in a segment
		@sections.each { |sec|
			if sec.flags.include? 'ALLOC'
				if not seg = @segments.find { |seg| seg.type == 'LOAD' and not seg.memsz and prot_match[seg.flags, sec.flags] }
					seg = Segment.new
					seg.type = 'LOAD'
					seg.flags = ['R']
					seg.flags << 'W' if sec.flags.include? 'WRITE'
					seg.encoded = EncodedData.new
					seg.offset = new_label('segment_offset')
					seg.vaddr = new_label('segment_address')
					@segments << seg
				end
				seg.flags |= ['X'] if sec.flags.include? 'EXECINSTR'
				sec.addr = Expression[seg.vaddr, :+, seg.encoded.length]
				sec.offset = Expression[seg.offset, :+, seg.encoded.length]
				seg.encoded << sec.encoded
			end
		}

		# ensure last PT_LOAD is writeable (used for bss)
		seg = @segments.reverse.find { |seg| seg.type == 'LOAD' }
		if not seg or not seg.flags.include? 'W'
			seg = Segment.new
			seg.type = 'LOAD'
			seg.flags = ['R', 'W']
			@segments << seg
		end

		# add dynamic segment
		if ds = @sections.find { |sec| sec.type == 'DYNAMIC' }
			ds.set_default_values self
			seg = Segment.new
			seg.type = 'DYNAMIC'
			seg.flags = ['R', 'W']
			seg.offset = ds.offset
			seg.vaddr = ds.addr
			seg.memsz = seg.filesz = ds.size
			@segments << seg
		end

		if false
		phdr = Segment.new
		phdr.type = 'PHDR'
		phdr.flags = @segments.find { |seg| seg.type == 'LOAD' }.flags
		@segments.unshift phdr
		end

		st = @sections.inject(EncodedData.new) { |edata, s| edata << s.encode(self) }
		pt = @segments.inject(EncodedData.new) { |edata, s| edata << s.encode(self) }

		@encoded << @header.encode(self)

		addr = @header.type == 'EXEC' ? 0x08048000 : 0
		binding = {}
		binding[@header.phoff] = @encoded.length
		@encoded << pt

		addr += @encoded.length
		@segments.each { |seg|
			next if not seg.encoded
			binding[seg.vaddr] = addr
			binding.update seg.encoded.binding(addr)
			binding[seg.offset] = @encoded.length
			@encoded << seg.encoded
			addr += seg.encoded.length + 0x1000	# 1page gap for memory permission enforcement
		}

		binding[@header.shoff] = @encoded.length
		@encoded << st

		@sections.each { |sec|
			next if not sec.encoded or sec.flags.include? 'ALLOC'	# already in a segment.encoded
			binding[sec.offset] = @encoded.length
			binding.update sec.encoded.binding
			@encoded << sec.encoded
		}

		@encoded.fixup! binding
	end

	def parse_init
		# allow the user to specify a section, falls back to .text if none specified
		if not defined? @cursource or not @cursource
			@cursource = Object.new
			class << @cursource
				attr_accessor :elf
				def <<(*a)
					t = Token.new(nil)
					t.raw = '.text'
					elf.parse_parser_instruction t
					elf.cursource.send(:<<, *a)
				end
			end
			@cursource.elf = self
		end
		@source ||= {}
	end

        # handles elf meta-instructions
	#
	# syntax:
	#   .section "<name>" [<perms>] [base=<base>]
	#     change current section (where normal instruction/data are put)
	#     perms = list of 'w' 'x' 'alloc', may be prefixed by 'no' to remove perm from an existing section
	#     shortcuts: .text .data .rodata .bss
	#     base: immediate expression representing the section base address
	#   .entrypoint [<label>]
	#     defines the program entrypoint to the specified label / current location
	#   .global "<name>" [<label>] [<label_end>] [type=<FUNC|OBJECT|...>] [plt=<plt_label_name>] [undef]
	#   .weak   ...
	#   .local  ...
	#     builds a symbol with specified type/scope/size, type defaults to 'func'
	#     if plt_label_name is specified, the compiler will build an entry in the plt for this symbol, with this label (PIC & on-demand resolution)
	#   .needed "<libpath>"
	#     marks the elf as requiring the specified library (DT_NEEDED)
	#   .soname "<soname>"
	#     defines the current elf DT_SONAME (exported library name)
	#   .interp "<interpreter_path>"
	#     defines the ELF interpreter required (if directive not specified, set to '/lib/ld.so')
	#     use 'nil' to remove interpreter
	#   .pt_gnu_stack rw|rwx
	#     defines the PT_GNU_STACK flag (defaults to rw)
	#   .init/.fini [<label>]
	#     defines the DT_INIT/DT_FINI dynamic tags, same semantic as .entrypoint
	#   .init_array/.fini_array/.preinit_array <label> [, <label>]*
	#     append to the DT_*_ARRAYs
	#
	def parse_parser_instruction(instr)
		readstr = proc {
			@lexer.skip_space
			raise instr, "string expected, found #{t.raw.inspect if t}" if not t = @lexer.readtok or (t.type != :string and t.type != :quoted)
			t.value || t.raw
		}
		check_eol = proc {
			@lexer.skip_space
			raise instr, "eol expected, found #{t.raw.inspect}" if t = @lexer.nexttok and t.type != :eol
		}

		case instr.raw.downcase
		when '.text', '.data', '.rodata', '.bss'
			sname = instr.raw.downcase
			if not @sections.find { |s| s.name == sname }
				s = Section.new
				s.name = sname
				s.encoded = EncodedData.new
				s.flags = case sname
					when '.text': %w[ALLOC EXECINSTR]
					when '.data', '.bss': %w[ALLOC WRITE]
					when '.rodata': %w[ALLOC]
					end
				@sections << s
			end
			@cursource = @source[sname] ||= []
			check_eol[] if instr.backtrace  # special case for magic @cursource
			
		when '.section'
			# .section <section name|"section name"> [(no) w x alloc] [base=<expr>]
			sname = readstr[]
			if not s = @sections.find { |s| s.name == sname }
				s = Section.new
				s.name = sname
				s.encoded = EncodedData.new
				s.flags = []
				@sections << s
			end
			loop do
				@lexer.skip_space
				break if not tok = @lexer.nexttok or tok.type != :string
				case @lexer.readtok.raw.downcase
				when /^(no)?(w)?(x)?(alloc)?$/
					ar = []
					ar << 'WRITE' if $2
					ar << 'EXECINSTR' if $3
					ar << 'ALLOC' if $4
					if $1: s.flags -= ar
					else   s.flags |= ar
					end
				when 'base'
					@lexer.skip_space
					raise instr, 'syntax error' if not tok = @lexer.readtok or tok.type != :punct or tok.raw != '='
					raise instr, 'syntax error' if not s.addr = Expression.parse(@lexer).reduce or not s.addr.kind_of? Integer
				else raise instr, 'unknown parameter'
				end
			end
			@cursource = @source[sname] ||= []
			check_eol[]
			
		when '.entrypoint'
			# ".entrypoint <somelabel/expression>" or ".entrypoint" (here)
			@lexer.skip_space
			if tok = @lexer.nexttok and tok.type == :string
				raise instr, 'syntax error' if not entrypoint = Expression.parse(@lexer)
			else
				entrypoint = new_label('entrypoint')
				@cursource << Label.new(entrypoint, instr.backtrace.dup)
			end
			@header.entry = entrypoint
			check_eol[]

		when '.global', '.weak', '.local'
			s = Symbol.new
			s.name = readstr[]
			s.type = 'FUNC'
			s.bind = instr.raw[1..-1].upcase
			# define s.section ? should check the section exporting s.target, but it may not be defined now
			
			# parse pseudo instruction arguments
			loop do
				@lexer.skip_space
				ntok = @lexer.readtok
				if not ntok or ntok.type == :eol
					@lexer.unreadtok ntok
					break
				end
				raise instr, "syntax error: string expected, found #{ntok.raw.inspect}" if ntok.type != :string
				case ntok.raw
				when 'undef'
					s.shndx = 'UNDEF'
				when 'plt'
					@lexer.skip_space
					ntok = @lexer.readtok
					raise "syntax error: = expected, found #{ntok.raw.inspect if ntok}" if not ntok or ntok.type != :punct or ntok.raw != '='
					@lexer.skip_space
					ntok = @lexer.readtok
					raise "syntax error: label expected, found #{ntok.raw.inspect if ntok}" if not ntok or ntok.type != :string
					s.thunk = ntok.raw
				when 'type'
					@lexer.skip_space
					ntok = @lexer.readtok
					raise "syntax error: = expected, found #{ntok.raw.inspect if ntok}" if not ntok or ntok.type != :punct or ntok.raw != '='
					@lexer.skip_space
					ntok = @lexer.readtok
					raise "syntax error: symbol type expected, found #{ntok.raw.inspect if ntok}" if not ntok or ntok.type != :string or not SYMBOL_TYPE.index(ntok.raw)
					s.type = ntok.raw
				else
					if not s.value
						s.value = ntok.raw
					elsif not s.size
						s.size = Expression[ntok.raw, :-, s.value]
					else
						raise instr, "syntax error: eol expected, found #{ntok.raw.inspect}"
					end
				end
			end
			s.shndx ||= 1 if s.value
			@symbols << s
			
		when '.needed'
			# a required library
			(@tag['NEEDED'] ||= []) << readstr[]
			check_eol[]
			
		when '.soname'
			# exported library name
			@tag['SONAME'] = readstr[]
			check_eol[]

		when '.interp'
			# required ELF interpreter
			interp = readstr[]

			@segments.delete_if { |s| s.type == 'INTERP' }
			seg = Segment.new
			seg.type = 'INTERP'
			seg.encoded = EncodedData.new << interp << 0
			seg.memsz = seg.filesz = seg.encoded.length
			@segments.unshift seg

			check_eol[]

		when '.pt_gnu_stack'
			# PT_GNU_STACK marking
			mode = readstr[]

			@segments.delete_if { |s| s.type == 'PT_GNU_STACK' }
			s = Segment.new
			s.type = 'PT_GNU_STACK'
			s.vaddr = s.paddr = s.offset = s.filesz = s.memsz = 0
			case mode
			when /^rw$/i: s.flags = %w[R W]
			when /^rwx$/i: s.flags = %w[R W X]
			else raise instr, "syntax error: expected rw|rwx, found #{mode.inspect}"
			end
			@segments << s

		when '.init', '.fini'
			# dynamic tag initialization
			@lexer.skip_space
			if tok = @lexer.nexttok and tok.type == :string
				raise instr, 'syntax error' if not init = Expression.parse(@lexer)
			else
				init = new_label(instr.raw[1..-1])
				@cursource << Label.new(init, instr.backtrace.dup)
			end
			@tag[instr.raw[1..-1].upcase] = init
			check_eol[]

		when '.init_array', '.fini_array', '.preinit_array'
			t = @tag[instr.raw[1..-1].upcase] ||= []
			loop do
				raise instr, 'syntax error' if not e = Expression.parse(@lexer)
				t << e
				@lexer.skip_space
				ntok = @lexer.nexttok
				break if not ntok or ntok.type == :eol
				raise instr, "syntax error, ',' expected, found #{ntok.raw.inspect}" if nttok != :punct or ntok.raw != ','
				@lexer.readtok
			end

		else super
		end
	end

	# assembles the hash self.source to a section array
	def assemble
		@source.each { |k, v|
			raise "no section named #{k} ?" if not s = @sections.find { |s| s.name == k }
			s.encoded << assemble_sequence(v, @cpu)
			v.clear
		}
	end
end
end

__END__
elf.assemble Ia32.new, <<EOS
.text				; @sections << Section.new('.text', ['r' 'x'])
.global "foo" foo foo_end	; @symbols ||= [0] << Symbol.new(global, '.foo', addr=foo, size=foo_end - foo)
.global "bla" plt=bla_plt
.needed 'libc.so.6'		; @tag['NEEDED'] ||= [] << 'libc.so.6'
.soname 'lolol'			; @tag['SONAME'] = 'lolol'
.interp nil			; @segments.delete_if { |s| s.type == 'INTERP' } ; @sections.delete_if { |s| s.name == '.interp' && vaddr = seg.vaddr etc }

foo:
	inc eax
	call bla_plt
	ret
foo_end:
EOS

__END__
		encode[pltgot, :u32, program.label_at(dynamic.edata, 0)]	# reserved, points to _DYNAMIC
		#if arch == '386'
			encode[pltgot, :u32, 0]	# ptr to dlresolve
			encode[pltgot, :u32, 0]	# ptr to got?
		#end
		end

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
		if pltgot
		pltsec.encode
		plt.edata << pltsec.encoded
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
				size = [program.label_at(lastsect.edata, lastsect.edata.rawsize), :-, program.label_at(firstsect.edata, 0)]
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
				if lastsect.edata.virtsize > lastsect.edata.rawsize + 0x1000
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


		(opts.delete('additional_segments') || []).each { |sg| encode_segm[sg['type'], sg['offset'], sg['vaddr'], sg['filesz'], sg['memsz'], sg['flags'], sg['align']] }
		phdr.export[end_phdr] = phdr.virtsize if end_phdr

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
				virtaddr = EncodedData.align_size(virtaddr, s.align)
				rawaddr  = EncodedData.align_size(rawaddr,  s.align)
			end

			s.edata.export.each { |name, off| binding[name] = Expression[virtaddr, :+, off] }
			if s.rawoffset
				binding[s.rawoffset] = rawaddr
			else
				s.rawoffset = rawaddr
			end

			virtaddr += s.edata.virtsize if target != 'REL'
			rawaddr  += s.edata.rawsize
		}
