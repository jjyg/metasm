require 'metasm/decode'
require 'metasm/exe_format/elf'

module Metasm
class ELF
	# interprets the string as an ELF, reads header/section_header/program_header
	# does not decode symbol/tags/relocs/etc (that's done in +to_program+)
	def self.decode(str)
		e = new
		e.encoded = EncodedData.new << str
		e.encoded.ptr = 0
		e.decode_header
		if e.header.shoff != 0
			e.encoded.ptr = e.header.shoff
			e.decode_section_header
		end
		if e.header.phoff != 0
			e.encoded.ptr = e.header.phoff
			e.decode_program_header
		end
		e
	end

	class Header
		# decodes the architecture-independant part of an elf header, pointed to by elf.encoded.ptr
		def self.pre_decode elf
			h = new
			h.ident = elf.encoded.read 16

			h.sig = h.ident[0, 4]
			raise "E: ELF: invalid ELF signature #{h.sig.inspect}" if h.sig != "\x7fELF"

			case h.ident[4]
			when 1: h.e_class = 32
			when 2: h.e_class = 64
			when 200: h.e_class = 64
			else raise "E: ELF: unsupported class #{h.ident[4]}"
			end

			case h.ident[5]
			when 1: h.endianness = :little
			when 2: h.endianness = :big
			else raise "E: ELF: unsupported endianness #{h.ident[5]}"
			end

			case h.ident[6]
			when 1
			else raise "E: ELF: unsupported ELF version #{h.ident[6]}"
			end

			h
		end

		# decodes the architecture-dependant part of the header
		def decode(elf)
			@type      = elf.decode_half
			@machine   = elf.decode_half
			@version   = elf.decode_word
			@entry     = elf.decode_addr
			@phoff     = elf.decode_off
			@shoff     = elf.decode_off
			@flags     = elf.decode_word
			@ehsize    = elf.decode_half
			@phentsize = elf.decode_half
			@phnum     = elf.decode_half
			@shentsize = elf.decode_half
			@shnum     = elf.decode_half
			@shstrndx  = elf.decode_half

			@type    = elf.int_to_hash(@type, TYPE)
			@machine = elf.int_to_hash(@machine, MACHINE)
			@version = elf.int_to_hash(@version, VERSION)
			@flags   = elf.bits_to_hash(@flags, FLAGS[@machine])
		end
	end

	class Section
		# decodes the section header pointed to by elf.encoded.ptr
		def self.decode elf
			sh = new

			sh.name_p    = elf.decode_word
			sh.type      = elf.decode_word
			sh.flags     = elf.decode_xword
			sh.addr      = elf.decode_addr
			sh.offset    = elf.decode_off
			sh.size      = elf.decode_xword
			sh.link      = elf.decode_word
			sh.info      = elf.decode_word
			sh.addralign = elf.decode_xword
			sh.entsize   = elf.decode_xword

			sh.type  = elf.int_to_hash(sh.type, SH_TYPE)
			sh.flags = elf.bits_to_hash(sh.flags, SH_FLAGS)

			sh
		end

		# sets name by reading str at offset @name_p
		# avoids invalidation of @name_p by #name=
		def read_name(str)
			@name = str[@name_p...str.index(0, @name_p)]
		end
	end

	class Segment
		# decodes the program header pointed to by elf.encoded.ptr
		def self.decode elf
			ph = new

			ph.type   = elf.decode_word
			ph.flags  = elf.decode_word if elf.header.e_class == 64
			ph.offset = elf.decode_off
			ph.vaddr  = elf.decode_addr
			ph.paddr  = elf.decode_addr
			ph.filesz = elf.decode_xword
			ph.memsz  = elf.decode_xword
			ph.flags  = elf.decode_word if elf.header.e_class == 32
			ph.align  = elf.decode_xword

			ph.type  = elf.int_to_hash(ph.type, PH_TYPE)
			ph.flags = elf.bits_to_hash(ph.flags, PH_FLAGS)

			ph
		end
	end

	class Symbol
		# decodes the symbol pointed to by elf.encoded.ptr
		# does not read the symbol name (here we have no idea where the string table is)
		def self.decode elf
			s = new

			case elf.header.e_class
			when 32
				s.name_p = elf.decode_word
				s.value  = elf.decode_addr
				s.size   = elf.decode_word
				s.info   = elf.decode_uchar
				s.other  = elf.decode_uchar
				s.shndx  = elf.decode_half
			when 64
				s.name_p = elf.decode_word
				s.info   = elf.decode_uchar
				s.other  = elf.decode_uchar
				s.shndx  = elf.decode_half
				s.value  = elf.decode_addr
				s.size   = elf.decode_xword
			end

			s.init_info(elf)
			s.shndx = elf.int_to_hash(s.shndx, SH_INDEX)

			s
		end

		# sets name by reading str at offset @name_p
		# avoids invalidation of @name_p by #name=
		def read_name(str)
			@name = str[@name_p...str.index(0, @name_p)]
		end

		# sets bind and type from info
		# avoids invalidation of @info by accessors
		def init_info(elf)
			@bind = elf.int_to_hash(((@info >> 4) & 15), SYMBOL_BIND)
			@type = elf.int_to_hash((@info & 15), SYMBOL_TYPE)
		end
	end

	class Relocation
		# decodes the relocation with no explicit addend pointed to by elf.encoded.ptr
		# the symbol is taken from elf.symbols if possible, and is set to nil for index 0 (UNDEF)
		def self.decode(elf)
			r = new

			r.offset = elf.decode_addr
			r.info   = elf.decode_xword

			r.init_info(elf)

			r
		end

		# same as +decode+, but with explicit addend (RELA)
		def self.decode_addend(elf)
			r = decode(elf)
			r.addend = elf.decode_sxword
			r
		end

		# sets symbol and type from info
		# avoids invalidation of @info by accessors
		def init_info(elf)
			@type = @info & (elf.header.e_class == 32 ? 0xff : 0xffff_ffff)
			@type = elf.int_to_hash(@type, RELOCATION_TYPE[elf.header.machine])
			@symbol = @info >> (elf.header.e_class == 32 ? 8 : 32)
			if @symbol == 0
				@symbol = nil
			elsif elf.symbols
				@symbol = elf.symbols[@symbol] || @symbol
			end
		end
	end

	# basic immediates decoding functions
	def decode_type(type) @encoded.decode_imm(type, @header.endianness) end
	def decode_uchar ; decode_type(:u8)  end
	def decode_half  ; decode_type(:u16) end
	def decode_word  ; decode_type(:u32) end
	def decode_sword ; decode_type(:i32) end
	def decode_xword ; decode_type(@header.e_class == 32 ? :u32 : :u64) end
	def decode_sxword; decode_type(@header.e_class == 32 ? :i32 : :i64) end
	alias decode_addr decode_xword
	alias decode_off  decode_xword

	# transforms a virtual address to a file offset, from mmaped segments addresses
	def addr_to_off addr
		s = @segments.find { |s| s.type == 'LOAD' and s.vaddr <= addr and s.vaddr + s.memsz > addr } if addr
		addr - s.vaddr + s.offset if s
	end

	# decodes the elf header pointed to by @encoded.ptr
	def decode_header
		@header = Header.pre_decode(self)	# decode arch-agnostic part
		@header.decode self			# uses decode_word & co, so @header.endianness needs to be setup at this point
	end

	# decodes the section header table pointed to by @encoded.ptr
	# section names are read from shstrndx if possible
	def decode_section_header
		@sections = []
		# XXX check @header.shentsize ?
		@header.shnum.times {
			@sections << Section.decode(self)
		}
		
		# read sections name
		if @header.shstrndx != 0 and str = @sections[@header.shstrndx]
			str.encoded = @encoded[str.offset, str.size]
			@sections.each { |s|
				s.read_name(str.encoded.data)
			}
		end
	end

	# decodes the program header table pointed to by @encoded.ptr
	# initializes the @interpreter
	# marks the elf entrypoint as an export of @encoded
	def decode_program_header
		@segments = []
		# XXX check @header.phentsize ?
		@header.phnum.times {
			@segments << Segment.decode(self)
		}

		if s = @segments.find { |s| s.type == 'INTERP' }
			@interpreter = @encoded.data[s.offset, s.filesz].chomp("\0")
		end

		if @header.entry != 0
			if not o = addr_to_off(@header.entry)
				puts "W: Elf: header entrypoints points to unmmaped space #{'0x%08X' % @header.entry}" if $VERBOSE
				return
			end
			@encoded.export['entrypoint'] = o
		end
	end

	# read the dynamic symbols hash table, and checks that every global and named symbol is accessible through it
	def decode_segments_check_hash
		return if not @encoded.ptr = addr_to_off(@tag['HASH'])
		hash_bucket_len = decode_word
		sym_count = decode_word

		hash_bucket = [] ; hash_bucket_len.times { hash_bucket << decode_word }
		hash_table = [] ; sym_count.times { hash_table << decode_word }

		@symbols.each { |s|
			next if not s.name or s.bind != 'GLOBAL'

			found = false
			h = ELF.hash_symbol_name(s.name)
			off = hash_bucket[h % hash_bucket_len]
			sym_count.times {	# to avoid DoS by loop
				break if off == 0
				if ss = @symbols[off] and ss.name == s.name
					found = true
					break
				end
				off = hash_table[off]
			}
			if not found
				puts "W: Elf: Symbol #{s.name.inspect} not found in hash table" if $VERBOSE
			end
		}
	end

	def decode_segments_check_gnu_hash
		return if not @encoded.ptr = addr_to_off(@tag['GNU_HASH'])

		# when present: the symndx first symbols are not sorted (SECTION/LOCAL/FILE/etc) symtable[symndx] is sorted (1st sorted symbol)
		# the sorted symbols are sorted by [gnu_hash_symbol_name(symbol.name) % hash_bucket_len]

		@encoded.ptr = ghash_o
		hash_bucket_len = decode_word
		symndx = decode_word		# index of first sorted symbol in symtab
		maskwords = decode_word		# number of words in the second part of the ghash section (32 or 64 bits)
		shift2 = decode_word		# used in the bloom filter

		bloomfilter = [] ; maskwords.times { bloomfilter << decode_xword }
		# "bloomfilter[N] has bit B cleared if there is no M (M > symndx) which satisfies (C = @header.class)
		# ((gnu_hash(sym[M].name) / C) % maskwords) == N	&&
		# ((gnu_hash(sym[M].name) % C) == B			||
		# ((gnu_hash(sym[M].name) >> shift2) % C) == B"
		# bloomfilter may be [~0]

		hash_bucket = [] ; hash_bucket_len.times { hash_bucket << decode_word }
		# bucket[N] contains the lowest M for which
		# gnu_hash(sym[M]) % nbuckets == N
		# or 0 if none
			
		symcount = 0			# XXX how do we get symcount ?
		part4 = [] ; (symcount - symndx).times { part4 << decode_word }
		# part4[N] contains
		# (gnu_hash(sym[N].name) & ~1) | (N == dynsymcount-1 || (gnu_hash(sym[N].name) % nbucket) != (gnu_hash(sym[N+1].name) % nbucket))
		# that's the hash, with its lower bit replaced by the bool [1 if i am the last sym having my hash as hash]

		# TODO
	end

	# read dynamic tags, mark most of them as exports of @encoded
	def decode_segments_tags
		@encoded.export['dynamic_tags'] = @encoded.ptr

		@tag = {}
		while (tag = decode_sword) != 0
			val = decode_word
			case tag = int_to_hash(tag, DYNAMIC_TAG)
			when Integer
				puts "W: Elf: unknown dynamic tag 0x#{tag.to_s 16}" if $VERBOSE
				@tag[tag] ||= []
				@tag[tag] << val
			when 'NEEDED'
				@tag[tag] ||= []
				@tag[tag] << val
			else
				if @tag[tag]
					puts "W: Elf: re-occurence of dynamic tag #{tag} (value #{'0x%08X' % val})" if $VERBOSE
				else
					@tag[tag] = val
				end
			end
		end

		# need to know @tag['STRTAB'] beforehand
		@tag.keys.each { |k|
			case k
			when Integer
			when 'NEEDED'
				if not strtab = addr_to_off(@tag['STRTAB'])
					puts "W: Elf: no string table, needed for tag #{k}" if $VERBOSE
					next
				end
				@tag[k].map! { |v| @encoded.data[strtab+v...@encoded.data.index(0, strtab+v)] }
			when 'SONAME', 'RPATH', 'RUNPATH'
				if not strtab = addr_to_off(@tag['STRTAB'])
					puts "W: Elf: no string table, needed for tag #{k}" if $VERBOSE
					next
				end
				@tag[k] = @encoded.data[strtab+@tag[k]...@encoded.data.index(0, strtab+@tag[k])]
			when 'INIT', 'FINI', 'PLTGOT', 'HASH', 'STRTAB', 'SYMTAB', 'RELA', 'REL', 'JMPREL'
				if not v = addr_to_off(@tag[k])
					puts "W: Elf: tag #{k} points to unmmaped space #{'0x%08X' % @tag[k]}" if $VERBOSE
					next
				end
				@encoded.export['dynamic_' + k.downcase] = v	# XXX may conflict w/ a symbol or something
			when 'INIT_ARRAY', 'FINI_ARRAY', 'PREINIT_ARRAY'
				if not sz = @tag[k+'SZ']
					puts "W: Elf: tag #{k} has no corresponding size tag" if $VERBOSE
					next
				end
				if not v = addr_to_off(@tag[k])
					puts "W: Elf: tag #{k} points to unmmaped space #{'0x%08X' % @tag[k]}" if $VERBOSE
					next
				end

				ary = []
				vend = v + sz
				@encoded.ptr = v
				while @encoded.ptr < vend
					ary << decode_addr
				end

				ary.map { |v| addr_to_off(v) }.each_with_index { |v, i|
					if not v
						puts "W: Elf: tag #{k} entry #{i} points to unmmaped space (#{'0x%08X' % ary[i]})" if $VERBOSE
						next
					end
					@encoded.export['dynamic_' + k.downcase + "_#{i}"] = v	# XXX may conflict
				}
			when 'FLAGS'
				@tag[k] = bits_to_hash(@tag[k], DYNAMIC_FLAGS)
			when 'PLTREL'
				@tag[k] = int_to_hash(@tag[k], DYNAMIC_TAG)
			end
		}
	end

	# read symbol table, and mark all symbols found as exports of @encoded
	# symbol count is found from the hash table, this may not work with GNU_HASH only binaries
	def decode_segments_symbols
		hash_o = addr_to_off(@tag['HASH'])
		ghash_o = addr_to_off(@tag['GNU_HASH'])
		return unless	str_o = addr_to_off(@tag['STRTAB']) and
				sym_o = addr_to_off(@tag['SYMTAB']) and (hash_o or ghash_o)
			
		raise "E: ELF: unsupported symbol entry size: #{@tag['SYMENT'].inspect}" if @tag['SYMENT'] != 16	# XXX sizeof(elf_word) + sizeof ...
		
		# find number of symbols from the hash table
		if hash_o
			@encoded.ptr = hash_o
			decode_word
			sym_count = decode_word
		elsif ghash_o
			# XXX UNDEF symbols are not hashed here
			@encoded.ptr = ghash_o
			decode_word32
			sym_count = decode_word32	# non hashed symbols
		end
			
		@encoded.ptr = sym_o
		@symbols = []
		sym_count.times { @symbols << Symbol.decode(self) }

		strtab = @encoded.data[str_o..-1]	# TODO
		@symbols.each { |s| s.read_name(strtab)  }

		# use symbols as segments' edata exports
		@symbols.find_all { |s|
			s.name and s.shndx != 'UNDEF' and %w[NOTYPE OBJECT FUNC].include?(s.type)
		}.sort_by { |s| s.value }.each { |s|
			if not o = addr_to_off(s.value)
				if not seg = @segments.find { |seg| seg.type == 'LOAD' and seg.vaddr + seg.memsz == s.value }	# check end
					puts "W: Elf: symbol #{s.name.inspect} points to unmmaped space (#{s.inspect})" if $VERBOSE
					next
				end
				o = s.value - seg.vaddr + seg.offset
			end
			name = s.name.dup
			while @encoded.export[name] and @encoded.export[name] != o
				puts "W: Elf: symbol #{name} already seen at #{@encoded.export[name]} (now #{o})" if $VERBOSE
				name << ?_
			end
			@encoded.export[name] = o
		}
	end

	# decode relocation tables and mark them as relocation of @encoded
	def decode_segments_relocs
		@relocs = []

		if rel_o = addr_to_off(@tag['REL'])
			raise "E: ELF: unsupported rel entry size #{@tag['RELENT']}" if @tag['RELENT'] != 8

			@encoded.ptr = rel_o
			(@tag['RELSZ'] / @tag['RELENT']).times {
				@relocs << Relocation.decode(self)
			}
		end

		if rel_o = addr_to_off(@tag['RELA'])
			raise "E: ELF: unsupported rela entry size #{@tag['RELAENT'].inspect}" if @tag['RELAENT'] != 12

			@encoded.ptr = rel_o
			(@tag['RELASZ'] / @tag['RELAENT']).times {
				@relocs << Relocation.decode_addend(self)
			}
		end

		if rel_o = addr_to_off(@tag['JMPREL'])
			case reltype = @tag['PLTREL']
			when 'REL': msg = :decode
			when 'RELA': msg = :decode_addend
			else raise "E: ELF: unsupported plt rel type #{reltype} (#{@tag['JMPREL']})"
			end

			@encoded.ptr = rel_o
			(@tag['PLTRELSZ'] / @tag[reltype+'ENT']).times {
				@relocs << Relocation.send(msg, self)
			}
		end

		# set segments encoded relocs
		relocproc = "arch_decode_segment_reloc_#{@header.machine}"
		if not respond_to? relocproc
			puts "W: Elf: relocs for arch #{@header.machine} unsupported" if $VERBOSE
			return
		end
		@relocs.each { |r|
			next if r.offset == 0
			if not o = addr_to_off(r.offset)
				puts "W: Elf: relocation in unmmaped space (#{r.inspect})" if $VERBOSE
				next
			end
			if @encoded.reloc[o]	# should check overlapping relocs ?
				puts "W: Elf: not rerelocating address #{'%08X' % r.offset}" if $VERBOSE
				next
			end
			@encoded.ptr = o
			if r = send(relocproc, r)
				@encoded.reloc[o] = r
			end
		}
	end

	# returns the Metasm::Relocation that should be applied for reloc
	# @encoded.ptr must point to the location that will be relocated (for implicit addend)
	def arch_decode_segment_reloc_386(reloc)
		# decode addend if needed
		case reloc.type
		when 'NONE', 'COPY', 'GLOB_DAT', 'JMP_SLOT' # no addend
		else addend = reloc.addend || decode_sword
		end

		target = \
		case reloc.type
		when 'NONE'
		when 'RELATIVE'
			base = @segments.find_all { |s| s.type == 'LOAD' }.map { |s| s.vaddr }.min & 0xffff_f000
			target = base + addend
			if o = addr_to_off(target)
				if not label = @encoded.export.invert[o]
					@encoded.export[label = 'Xref_%X' % target] = o
				end
				label
			else
				puts "W: Elf: relocation pointing out of mmaped space #{reloc.inspect}" if $VERBOSE
				target
			end
		when 'GLOB_DAT', 'JMP_SLOT', '32', 'PC32', 'TLS_TPOFF', 'TLS_TPOFF32'
			# XXX use versionned version
			# lazy jmp_slot ?
			t = 0
			t = reloc.symbol.name if reloc.symbol.kind_of?(Symbol) and reloc.symbol.name
			t = Expression[t, :-, reloc.offset] if reloc.type == 'PC32'
			t = Expression[t, :+, addend] if addend and addend != 0
			t = Expression[t, :+, 'tlsoffset'] if reloc.type == 'TLS_TPOFF'
			t = Expression[:-, [t, :+, 'tlsoffset']] if reloc.type == 'TLS_TPOFF32'
			t
		else
			puts "W: Elf: unhandled 386 reloc #{reloc.inspect}" if $VERBOSE
		end

		Metasm::Relocation.new(Expression[target], :u32, @header.endianness) if target
	end

	def segments_to_program
		case @header.machine
		when '386': cpu = Ia32.new if defined? Ia32	# check @header.e_class for 64bits
		end

		if not cpu
			puts "W: Elf: unsupported CPU #{@header.machine}" if $VERBOSE
			cpu = UnknownCPU.new(@header.e_class, @header.endianness)
		end

		pgm = Program.new cpu

		if dynamic = @segments.find { |s| s.type == 'DYNAMIC' }
			@encoded.ptr = dynamic.offset
			decode_segments_tags
			decode_segments_symbols
			decode_segments_relocs
		end

		@segments.find_all { |s| s.type == 'LOAD' }.each { |s|
			name = bname =
			if    s.flags.include? 'X': '.text'
			elsif s.flags.include? 'W': '.data'
			else  '.rodata'
			end
			i = 0 ; name = "#{bname}_#{i+=1}" while pgm.sections.find { |sec| sec.name == name }

			sec = Metasm::Section.new pgm, name
			sec.mprot = { 'R'=>:r, 'W'=>:w, 'X'=>:x }.values_at(*s.flags).compact
			sec.base = s.vaddr
			sec.align = s.align
			sec.encoded << @encoded[s.offset, s.filesz]
			sec.encoded.virtsize += s.memsz - s.filesz

			pgm.sections << sec
		}

		pgm
	end

	def sections_to_program
		# TODO
		decode_sections

		case @header.machine
		when '386': cpu = Ia32.new	# check @header.e_class for 64bits
		else
			puts "W: Elf: Unknown CPU #{@header.machine}" if $VERBOSE
			cpu = UnknownCpu.new(@header.e_class, @header.endianness)
		end

		pgm = Program.new cpu

		@sections.each { |s|
		}

		pgm
	end

	def to_program
		case @header.type
		when 'DYN', 'EXEC': segments_to_program
		when 'REL': sections_to_program
		end
	end
end
end
