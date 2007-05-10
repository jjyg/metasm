require 'metasm/decode'
require 'metasm/exe_format/elf'

module Metasm
class ELF
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
		def self.decode elf
			h = new
			h.ident = elf.encoded.read 16

			h.sig = h.ident[0, 4]
			raise "E: ELF: invalid ELF signature #{h.sig.inspect}" if h.sig != "\x7fELF"

			case h.ident[4]
			when 1: h.e_class = 32
			#when 2: h.e_class = 64
			else raise "E: ELF: unsupported class #{h.ident[4]}"
			end

			case h.ident[5]
			when 1: h.endianness = :little
			when 2: h.endianness = :big
			else raise "E: ELF: unsupported endianness #{h.ident[5]}"
			end

			raise "E: ELF: unsupported ELF version #{h.ident[6]}" if h.ident[6] != 1

			yield h		# set up elf.header.endianness+class, for elf.decode_word to work

			h.type      = elf.decode_half
			h.machine   = elf.decode_half
			h.version   = elf.decode_word
			h.entry     = elf.decode_addr
			h.phoff     = elf.decode_off
			h.shoff     = elf.decode_off
			h.flags     = elf.decode_word
			h.ehsize    = elf.decode_half
			h.phentsize = elf.decode_half
			h.phnum     = elf.decode_half
			h.shentsize = elf.decode_half
			h.shnum     = elf.decode_half
			h.shstrndx  = elf.decode_half

			h.type    = elf.int_to_hash(h.type, TYPE)
			h.machine = elf.int_to_hash(h.machine, MACHINE)
			h.version = elf.int_to_hash(h.version, VERSION)
			h.flags   = elf.bits_to_hash(h.flags, FLAGS)

			h
		end
	end

	class Section
		def self.decode elf
			raise "E: ELF: unsupported section header: shentsize = #{elf.header.shentsize}" if elf.header.shentsize != 40

			sh = new

			sh.name_p    = elf.decode_word
			sh.type      = elf.decode_word
			sh.flags     = elf.decode_word
			sh.addr      = elf.decode_addr
			sh.offset    = elf.decode_off
			sh.size      = elf.decode_word
			sh.link      = elf.decode_word
			sh.info      = elf.decode_word
			sh.addralign = elf.decode_word
			sh.entsize   = elf.decode_word

			sh.flags = elf.bits_to_hash(sh.flags, SH_FLAGS)
			sh.type  = elf.int_to_hash(sh.type, SH_TYPE)

			sh
		end
	end

	class Segment
		def self.decode elf
			raise "E: ELF: unsupported program header: phentsize = #{elf.header.phentsize}" if elf.header.phentsize != 32

			ph = new

			ph.type   = elf.decode_word
			ph.offset = elf.decode_off
			ph.vaddr  = elf.decode_addr
			ph.paddr  = elf.decode_addr
			ph.filesz = elf.decode_word
			ph.memsz  = elf.decode_word
			ph.flags  = elf.decode_word
			ph.align  = elf.decode_word

			ph.type  = elf.int_to_hash(ph.type, PH_TYPE)
			ph.flags = elf.bits_to_hash(ph.flags, PH_FLAGS)

			ph
		end
	end

	class Symbol
		def self.decode elf
			s = new

			case elf.e_class
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
				s.size   = elf.decode_word
			end

			s.bind = elf.int_to_hash(((s.info >> 4) & 15), SYMBOL_BIND)
			s.type = elf.int_to_hash((s.info & 15), SYMBOL_TYPE)
			s.shndx = elf.int_to_hash(s.shndx, SH_INDEX)

			s
		end
	end

	class Relocation
		def self.decode(elf)
			r = new

			r.offset = elf.decode_addr
			r.info   = elf.decode_word

			r.symbol = r.info >> (elf.e_class == 32 ? 8 : 32)
			r.symbol = nil if r.symbol == 0
			r.symbol = elf.symbols[r.symbol] || r.symbol if r.symbol and elf.symbols
			r.type = elf.int_to_hash((r.info & (elf.e_class == 32 ? 0xff : 0xffff_ffff)), RELOCATION_TYPE.fetch(elf.header.machine, {}))

			r
		end

		def self.decode_addend(elf)
			r = decode(elf)
			r.addend = elf.decode_sword
			r
		end
	end

	# basic immediates decoding functions
	# (may) ease 64bits porting
	def decode_word ; @encoded.decode_imm(:u32, @header.endianness) end
	def decode_word32 ; @encoded.decode_imm(:u32, @header.endianness) end
	alias decode_addr decode_word
	alias decode_off  decode_word
	def decode_sword; @encoded.decode_imm(:i32, @header.endianness) end
	def decode_half ; @encoded.decode_imm(:u16, @header.endianness) end
	def decode_uchar; @encoded.get_byte end


	def addr_to_off addr
		s = @segments.find { |s| s.vaddr <= addr and s.vaddr + s.memsz > addr } if addr
		addr - s.vaddr + s.offset if s
	end

	def decode_header
		Header.decode(self) { |h| @header = h }
	end

	def decode_section_header
		@sections = []
		@header.shnum.times {
			@sections << Section.decode(self)
		}
		
		# read sections name
		if @header.shstrndx != 0 and str = @sections[@header.shstrndx]
			str.encoded = @encoded[str.offset, str.size]
			@sections.each { |s|
				s.name = str.encoded.data[s.name_p...str.encoded.data.index(0, s.name_p)]
			}
		end
	end

	def decode_program_header
		@segments = []
		@header.phnum.times {
			@segments << Segment.decode(self)
		}
	end

	def decode_segments
		@segments.find_all { |s| s.type == 'LOAD' }.each { |s|
			s.encoded = @encoded[s.offset, s.filesz]
			s.encoded.virtsize += s.memsz - s.filesz
			if s.vaddr <= @header.entrypoint and s.vaddr + s.memsz > @header.entrypoint
				s.encoded.export['entrypoint'] = @header.entrypoint - s.vaddr
			end
		}
		if dynamic = @segments.find { |s| s.type == 'DYNAMIC' }
			@encoded.ptr = dynamic.offset
			@tags = {}
			while (tag = decode_sword) != 0
				(@tags[int_to_hash(tag, DYNAMIC_TAG)] ||= []) << decode_word
			end

			decode_segments_symbols
			decode_segments_relocs
		end
	end

	def decode_segments_symbols
		tag = proc { |name| @tags[name].to_a.first }

		return unless	str_o = addr_to_off(tag['STRTAB']) and
				sym_o = addr_to_off(tag['SYMTAB']) and
				(hash_o = addr_to_off(tag['HASH']) or ghash_o = addr_to_off(tag['GNU_HASH']))
				# TODO way to allow user to select HASH or GNU_HASH
			
		raise "E: ELF: unsupported symbol entry size: #{tag['SYMENT'].inspect}" if tag['SYMENT'] != 16	# XXX sizeof(elf_word) + sizeof ...
		
		if hash_o
			@encoded.ptr = hash_o
			hash_bucket_len = decode_word
			sym_count = decode_word

			hash_bucket = [] ; hash_bucket_len.times { hash_bucket << decode_word }
			hash_table = [] ; sym_count.times { hash_table << decode_word }
		elsif ghash_o
			# when present: the symndx first symbols are not sorted (SECTION/LOCAL/FILE/etc) symtable[symndx] is sorted (1st sorted symbol)
			# the sorted symbols are sorted by [gnu_hash_symbol_name(symbol.name) % hash_bucket_len]

			@encoded.ptr = ghash_o
			hash_bucket_len = decode_word32
			symndx = decode_word32		# index of first sorted symbol in symtab
			maskwords = decode_word32	# number of words in the second part of the ghash section (32 or 64 bits)
			shift2 = decode_word32		# used in the bloom filter

			bloomfilter = [] ; maskwords.times { bloomfilter << decode_word }
			# "bloomfilter[N] has bit B cleared if there is no M (M > symndx) which satisfies (C = @header.class)
			# ((gnu_hash(sym[M].name) / C) % maskwords) == N	&&
			# ((gnu_hash(sym[M].name) % C) == B			||
			# ((gnu_hash(sym[M].name) >> shift2) % C) == B"
			# bloomfilter may be [~0]

			hash_bucket = [] ; hash_bucket_len.times { hash_bucket << decode_word32 }
			# bucket[N] contains the lowest M for which
			# gnu_hash(sym[M]) % nbuckets == N
			# or 0 if none
			
			part4 = [] ; (symcount - symndx).times { part4 << decode_word32 }	# XXX how do we get symcount ?
			# part4[N] contains
			# (gnu_hash(sym[N].name) & ~1) | (N == dynsymcount-1 || (gnu_hash(sym[N].name) % nbucket) != (gnu_hash(sym[N+1].name) % nbucket))
			# that's the hash, with its lower bit replaced by the bool [1 if i am the last sym having my hash as hash]

			raise 'TODO Kikoo gcc !'
		end
			
		@encoded.ptr = sym_o
		@symbols = []
		sym_count.times { @symbols << Symbol.decode(self) }

		@encoded.ptr = str_o
		read_strz = proc { |off| @encoded.data[str_o+off ... @encoded.data.index(0, str_o+off)] if off > 0 }
		@symbols.each { |s| s.name = read_strz[s.name_p] }

		# (optional) check hash table consistency
		@symbols.each { |s|
			next if not s.name or s.bind != 'GLOBAL'

			found = false
			if hash_o
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
			else
				h = ELF.gnu_hash_symbol_name(s.name)
			end
			if not found
				puts "W: Elf: Symbol #{s.name.inspect} not found in hash table"
			end
		}

		# use symbols as segments' edata exports
		mapped_segments = @segments.find_all { |seg| seg.type == 'LOAD' }
		return if not curs = mapped_segments.first
		@symbols.find_all { |s|
			s.name and s.shndx != 'UNDEF' and %w[NOTYPE OBJECT FUNC].include?(s.type)
		}.sort_by { |s| s.value }.each { |s|
			addr = s.value
			# find segment
			if curs.vaddr > addr or curs.vaddr + curs.memsz <= addr
				curs = mapped_segments.find { |seg| seg.vaddr <= addr and seg.vaddr + seg.memsz > addr } ||
				       mapped_segments.find { |seg| seg.vaddr + seg.memsz == addr }	# check end
				if not curs
					puts "W: Elf: no segment for symbol #{s.name.inspect} (#{s.inspect})"
					curs = mapped_segments.first
					next
				end
			end
			curs.encoded.export[s.name] = addr - curs.vaddr
		}
	end

	def decode_segments_relocs
		tag = proc { |name| @tags[name].to_a.first }

		@relocs = []

		if rel_o = addr_to_off(tag['REL'])
			raise "E: ELF: unsupported rel entry size #{tag['RELENT'].inspect}" if tag['RELENT'] != 8

			@encoded.ptr = rel_o
			(tag['RELSZ'] / tags['RELENT']).times {
				@relocs << Relocation.decode(self)
			}
		end

		if rel_o = addr_to_off(tag['RELA'])
			raise "E: ELF: unsupported rela entry size #{tag['RELAENT'].inspect}" if tag['RELAENT'] != 12

			@encoded.ptr = rel_o
			(tag['RELASZ'] / tag['RELAENT']).times {
				@relocs << Relocation.decode_addend(self)
			}
		end

		if rel_o = addr_to_off(tag['JMPREL'])
			case reltype = int_to_hash(tag['PLTREL'], DYNAMIC_TAG)
			when 'REL': msg = :decode
			when 'RELA': msg = :decode_addend
			else raise "E: ELF: unsupported plt rel type #{reltype} (#{tag['JMPREL']})"
			end

			@encoded.ptr = rel_o
			(tag[reltype+'SZ'] / tag[reltype+'ENT']).times {
				@relocs << Relocation.send(msg, self)
			}
		end

		# set segments encoded relocs
		relocproc = "arch_decode_reloc_#{@header.machine}"
		return if not respond_to? relocproc
		mapped_segments = @segments.find_all { |seg| seg.type == 'LOAD' }
		return if not curs = mapped_segments.first
		@relocs.sort_by { |r| r.offset }.each { |r|
			addr = r.offset
			next if addr == 0
			if curs.vaddr > addr or curs.vaddr + curs.memsz <= addr
				curs = mapped_segments.find { |seg| seg.vaddr <= addr and seg.vaddr + seg.memsz > addr }
				if not curs
					puts "W: Elf: no segment for reloc (#{r.inspect})"
					curs = mapped_segments.first
					next
				end
			end
			send relocproc, r, curs
		}
	end

	def arch_decode_reloc_386(reloc, curseg)
		case reloc.type
		when 'NONE'
			return
		when 'COPY', 'GLOB_DAT', 'JMP_SLOT'
			# no addend
		else
			if not addend = reloc.addend
				curseg.encoded.ptr = reloc.offset - curseg.vaddr
				addend = curseg.encoded.decode_imm(:i32, @header.endianness)
				if addend.kind_of? Expression
					# XXX the dynamic loader probably handles them in another order, so this may be false
					puts "W: Elf: ignoring relocation using an already relocated addend: #{reloc.inspect}"
					return
				end
			end
		end

		case reloc.type
		when 'RELATIVE'
			base = @segments.find_all { |s| s.type == 'LOAD' }.map { |s| s.vaddr }.min & 0xffff_f000
			target = base + addend

			s = @segments.find { |s| s.type == 'LOAD' and s.vaddr <= target and s.vaddr + s.memsz > target }
			if not s
				puts "W: Elf: ignoring relative relocation outside the mmaped space #{reloc.inspect}"
				return
			end

			if not label = s.encoded.export.invert[target - s.vaddr]
				s.encoded.export[label = 'xref_%x' % target] = target - s.vaddr
			end

			target = Expression[label]

		when '32', 'COPY', 'GLOB_DAT', 'JMP_SLOT'
			# lazy jmp_slot ?
			# copy indirected ?
			if not reloc.symbol or not reloc.symbol.name
				puts "W: Elf: ignoring invalid reloc #{reloc.inspect} (no symbol)"
				return
			end
			if reloc.type == '32' and addend != 0
				target = Expression[reloc.symbol.name, :+, addend]
			else
				target = Expression[reloc.symbol.name]
			end

		else
			puts "W: Elf: ignoring unhandled i386 reloc #{reloc.inspect}"
			return
		end

		curseg.encoded.reloc[reloc.offset - curseg.vaddr] = Metasm::Relocation.new(target, :u32, @header.endianness)
	end

	def segments_to_program
		decode_segments

		case @header.machine
		when '386': cpu = Ia32.new if defined? Ia32	# check @header.e_class for 64bits
		end

		if not cpu
			puts "W: Elf: unsupported CPU #{@header.machine}"
			cpu = UnknownCpu.new(@header.e_class, @header.endianness)
		end

		pgm = Program.new cpu

		@segments.each { |s|
			name = bname =
			if    s.flags.include? 'X': '.text'
			elsif s.flags.include? 'W': '.data'
			else  '.rodata'
			end
			i = 0 ; name = "#{bname}_#{i+=1}" while pgm.sections.find { |sec| sec.name == name }

			sec = Metasm::Section.new pgm, name
			sec.mprot = { 'X' => :x, 'W' => :w, 'R' => :r }.values_at(*s.flags).compact
			sec.base = s.vaddr
			sec.encoded << s.encoded

			pgm.sections << sec
		}

		pgm.export['entrypoint'] = 'entrypoint'

		# TODO import/export, misc opts (interp, soname, needed, init/fini etc)

		pgm
	end

	def sections_to_program
		# TODO
		decode_sections

		case @header.machine
		when '386': cpu = Ia32.new	# check @header.e_class for 64bits
		else
			puts "W: Elf: Unknown CPU #{@header.machine}"
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

__END__
	opts['entrypoint'] = pgm.make_label(hdr.entry, 'entrypoint')
	hdr.phdr.each { |ph|
		case ph.type
		when 'PHDR', 'LOAD', 'DYNAMIC'
		when 'INTERP': opts['interp'] = edata.data[ph.offset, ph.filesz].chomp("\0")
		else (opts['additional_segments'] ||= []) << ph
		end
	}

	def decode_load_segments(pgm, edata, hdr, opts)
			tags.each { |t, v|
				case t
				when 'SONAME': opts['soname'] = read_strz[v]
				when 'NEEDED': (opts['needed'] ||= []) << read_strz[v]
				when 'INIT':   opts['init'] = pgm.make_label(v, 'init')
				when 'FINI':   opts['fini'] = pgm.make_label(v, 'fini')
				when 'RPATH':  opts['rpath'] = read_strz[v].split(/[:;]/)
				end
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

end
end
end

