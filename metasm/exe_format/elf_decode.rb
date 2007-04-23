require 'metasm/decode'
require 'metasm/exe_format/elf'

module Metasm
class ELF
	def self.decode(str)
		e = new
		e.encoded = EncodedData.new << str
		e.decode_header
		e
	end

	class Header
		def self.decode elf
			h = new
			h.ident = elf.encoded.read 16

			h.mag = h.ident[0, 4]
			raise "E: ELF: invalid ELF signature #{h.mag.inspect}" if h.mag != "\x7fELF"

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

			h.type    =    TYPE[h.type]    || h.type
			h.machine = MACHINE[h.machine] || h.machine
			h.version = VERSION[h.version] || h.version
			h.flags   = ExeFormat.bits_to_hash(h.flags, FLAGS)

			h
		end
	end

	class SectionHeader
		def self.decode elf
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

			sh.flags = ExeFormat.bits_to_hash(sh.flags, SH_FLAGS)
			sh.type  = SH_TYPE[sh.type] || sh.type

			sh
		end
	end

	class ProgramHeader
		def self.decode elf
			ph = new

			ph.type   = elf.decode_word
			ph.offset = elf.decode_off
			ph.vaddr  = elf.decode_addr
			ph.paddr  = elf.decode_addr
			ph.filesz = elf.decode_word
			ph.memsz  = elf.decode_word
			ph.flags  = elf.decode_word
			ph.align  = elf.decode_word

			ph.type  = PH_TYPE[ph.type] || ph.type
			ph.flags = ExeFormat.bits_to_hash(ph.flags, PH_FLAGS)

			ph
		end
	end

	class Symbol
		def self.decode elf
			s = new

			s.name_p = elf.decode_word
			s.value  = elf.decode_addr
			s.size   = elf.decode_word
			s.info   = elf.decode_uchar
			s.other  = elf.decode_uchar
			s.shndx  = elf.decode_half

			s.bind = (s.info >> 4) & 15
			s.bind = SYMBOL_BIND[s.bind] || s.bind
			s.type = s.info & 15
			s.type = SYMBOL_TYPE[s.type] || s.type
			s.shndx =  SH_INDEX[s.shndx] || s.shndx

			s
		end
	end

	class Relocation
		def self.decode(elf, has_addend = false)
			r = new

			r.offset = elf.decode_addr
			r.info   = elf.decode_word
			r.addend = elf.decode_sword if has_addend

			r.symbol = r.info >> 8
			r.symbol = nil if r.symbol == 0
			r.type = r.info & 255
			r.type = RELOCATION_TYPE.fetch(elf.header.machine, {})[r.type] || r.type

			r
		end
	end

	attr_accessor :encoded
	attr_reader :header, :program_header, :section_header, :segments, :sections, :tags, :symbols, :relocs

	# basic immediates decoding functions
	# (may) ease 64bits porting
	def decode_word ; Expression.decode_imm(@encoded, :u32, @header.endianness) end
	alias decode_addr decode_word
	alias decode_off  decode_word
	def decode_sword; Expression.decode_imm(@encoded, :i32, @header.endianness) end
	def decode_half ; Expression.decode_imm(@encoded, :u16, @header.endianness) end
	def decode_uchar; @encoded.get_byte end


	def decode_header
		@encoded.ptr = 0
		Header.decode(self) { |h| @header = h }
	end

	def decode_section_header
		decode_header if not defined? @header
		if @header.shoff == 0
			@section_header = nil
		else
			raise "E: ELF: unsupported section header: shentsize = #{@header.shentsize}" if @header.shentsize != 40
			@encoded.ptr = @header.shoff
			@section_header = []
			@header.shnum.times {
				@section_header << SectionHeader.decode(self)
			}
			
			# read sections name
			if @header.shstrndx != 0 and @section_header[@header.shstrndx]
				stroff = @section_header[@header.shstrndx].offset
				@section_header.each { |sh|
					off = stroff+sh.name_p
					sh.name = @encoded.data[off...@encoded.data.index(0, off)]
				}
			end
		end
	end

	def decode_program_header
		decode_header if not defined? @header
		if @header.phoff == 0
			@program_header = nil
		else
			raise "E: ELF: unsupported program header: phentsize = #{@header.phentsize}" if @header.phentsize != 32
			@encoded.ptr = @header.phoff
			@program_header = []
			@header.phnum.times {
				@program_header << ProgramHeader.decode(self)
			}
		end
	end

	def decode_segments
		decode_program_header if not defined? @program_header
		if not @program_header
			@segments = nil
		else
			@segments = []
			dynamic = nil
			@program_header.each { |ph|
				dynamic = ph if ph.type == 'DYNAMIC'
				next if ph.type != 'LOAD'
				s = Segment.new
				s.header = ph
				s.encoded = @encoded[ph.offset, ph.filesz]
				s.encoded.virtsize += ph.memsz - ph.filesz
				@segments << s
			}
			decode_segment_dynamic dynamic
			if @tags
				decode_segments_symbols
				decode_segments_relocs
			end
		end
	end

	def decode_segment_dynamic dynamic
		if not dynamic
			@tags = nil
		else
			@tags = {}
			@encoded.ptr = dynamic.offset
			while (tag = decode_sword) != 0
				tag = DYNAMIC_TAG[tag] || tag
				(@tags[tag] ||= []) << decode_word	# really 'union { elf32_word ; elf32_addr }'
			end
		end
	end

	def addr_to_off addr
		s = @segments.find { |s| s.header.vaddr <= addr and s.header.vaddr + s.header.memsz > addr }
		addr - s.header.vaddr + s.header.offset if s
	end

	def decode_segments_symbols
		return unless @tags['STRTAB'] and @tags['SYMTAB'] and @tags['HASH'] and
				str_o = addr_to_off(@tags['STRTAB'].first) and
				sym_o = addr_to_off(@tags['SYMTAB'].first) and
				hash_o = addr_to_off(@tags['HASH'].first)
			
		raise "E: ELF: unsupported symbol entry size: #{@tags['SYMENT'].inspect}" if @tags['SYMENT'].first != 16	# XXX sizeof(elf_word) + sizeof ...
		
		@encoded.ptr = hash_o
		hash_bucket_len = decode_word
		sym_count = decode_word

		hash_bucket = [] ; hash_bucket_len.times { hash_bucket << decode_word }
		hash_table = [] ; sym_count.times { hash_table << decode_word }
			
		@symbols = []
		@encoded.ptr = sym_o
		sym_count.times {
			@symbols << Symbol.decode(self)
		}

		@encoded.ptr = str_o
		read_strz = proc { |off| @encoded.data[str_o+off ... @encoded.data.index(0, str_o+off)] }
		@symbols.each { |s|
			next if s.name_p == 0
			s.name = read_strz[s.name_p]
		}

		# check hash table consistency
		@symbols.each { |s|
			next if not s.name or s.bind != 'GLOBAL'
			h = ELF.hash_symbol_name(s.name)
			off = hash_bucket[h % hash_bucket_len]
			found = false
			sym_count.times {	# to avoid DoS
				break if off == 0
				if ss = @symbols[off] and ss.name == s.name
					found = true
					break
				end
				off = hash_table[off]
			}
			if not found
				puts "W: Elf: Symbol #{s.name.inspect} not found in hash table"
			end
		}

		# use symbols as segments' edata exports
		return if not curs = @segments.first
		@symbols.each { |s|
			next if not s.name or s.shndx == 'UNDEF' or not %w[NOTYPE OBJECT FUNC].include?(s.type)
			addr = s.value
			# find segment
			if curs.header.vaddr > addr or curs.header.vaddr + curs.header.memsz <= addr
				curs = @segments.find { |seg| seg.header.vaddr <= addr and seg.header.vaddr + seg.header.memsz > addr }
				if not curs and not curs = @segments.find { |seg| seg.header.vaddr <= addr and seg.header.vaddr + seg.header.memsz >= addr }	# include end
					puts "W: Elf: no segment for symbol #{s.name.inspect} (#{s.inspect})"
					curs = @segments.first
					next
				end
			end
			curs.encoded.export[s.name] = addr - curs.header.vaddr
		}
	end

	def decode_segments_relocs
		# single table in exec/dyn
		@relocs = []

		if @tags['REL'] and rel_o = addr_to_off(@tags['REL'].first)
			raise "E: ELF: unsupported rel entry size #{@tags['RELENT'].inspect}" if @tags['RELENT'].first != 8

			@encoded.ptr = rel_o
			(@tags['RELSZ'].first / @tags['RELENT'].first).times {
				@relocs << Relocation.decode(self)
			}
		end

		if @tags['RELA'] and rel_o = addr_to_off(@tags['RELA'].first)
			raise "E: ELF: unsupported rela entry size #{@tags['RELAENT'].inspect}" if @tags['RELAENT'].first != 12

			@encoded.ptr = rel_o
			(@tags['RELASZ'].first / @tags['RELAENT'].first).times {
				@relocs << Relocation.decode(self, true)
			}
		end

		if @tags['JMPREL'] and rel_o = addr_to_off(@tags['JMPREL'].first)
			reltype = DYNAMIC_TAG[@tags['PLTREL'].first]
			raise "E: ELF: unsupported plt rel type #{reltype} (#{@tags['JMPREL'].inspect})" unless reltype == 'REL' or reltype == 'RELA'

			@encoded.ptr = rel_o
			(@tags[reltype+'SZ'].first / @tags[reltype+'ENT'].first).times {
				@relocs << Relocation.decode(self, (reltype == 'RELA'))
			}
		end

		@relocs.each { |r| r.symbol = @symbols[r.symbol] || r.symbol if r.symbol } if @symbols

		# set segments encoded relocs
		return if not curs = @segments.first
		@relocs.sort_by { |r| r.offset }.each { |r|
			addr = r.offset
			next if addr == 0
			if curs.header.vaddr > addr or curs.header.vaddr + curs.header.memsz <= addr
				curs = @segments.find { |seg| seg.header.vaddr <= addr and seg.header.vaddr + seg.header.memsz > addr }
				if not curs
					puts "W: Elf: no segment for reloc (#{r.inspect})"
					curs = @segments.first
					next
				end
			end
			arch_decode_reloc r, curs
		}
	end

	def arch_decode_reloc(reloc, curseg)
		case @header.machine
		when '386'
			case reloc.type
			when 'NONE', 'COPY', 'GLOB_DAT', 'JMP_SLOT'
			else
				if not addend = reloc.addend
					curseg.encoded.ptr = reloc.offset - curseg.header.vaddr
					addend = Expression.decode_imm(curseg.encoded, :u32, @header.endianness)	# XXX what if already reloced ?
				end
			end

			target = \
			case reloc.type
			when 'NONE'
			when 'RELATIVE'
				base = @segments.map { |s| s.header.vaddr }.min & 0xffff_f000
				target = base + addend

				s = @segments.find { |s| s.header.vaddr <= target and s.header.vaddr + s.header.memsz > target }
				if not s
					puts "W: Elf: relative reloc outside of mmaped space #{reloc.inspect}"
					return
				end

				if not label = s.encoded.export.invert[target - s.header.vaddr]
					s.encoded.export[label = 'xref_%x' % target] = target - s.header.vaddr
				end
				Expression[label]

			when '32'
				if not reloc.symbol or not reloc.symbol.name
					puts "W: Elf: invalid 32 reloc: no symbol #{reloc.inspect}"
					return
				end
				if addend != 0
					Expression[reloc.symbol.name, :+, addend]
				else
					Expression[reloc.symbol.name]
				end

			when 'GLOB_DAT'
				Expression[reloc.symbol.name]

			when 'JMP_SLOT'	# XXX lazy !
				Expression[reloc.symbol.name]

			when 'COPY'
				Expression[reloc.symbol.name]	# indirected ?

			else puts "W: Elf: unhandled i386 reloc #{reloc.inspect}"
			end

			curseg.encoded.reloc[reloc.offset - curseg.header.vaddr] = Metasm::Relocation.new(target, :u32, @header.endianness) if target
		end
	end

	def segments_to_program
		decode_segments if not @segments
		case @header.machine
		when '386': cpu = Ia32.new	# check @header.e_class for 64bits
		else
			puts "W: Elf: unsupported CPU #{@header.machine}"
			cpu = UnknownCpu.new(@header.e_class, @header.endianness)
		end

		pgm = Program.new cpu

		@segments.each { |s|
			name = bname =
			if    s.header.flags.include? 'X': '.text'
			elsif s.header.flags.include? 'W': '.data'
			else  '.rodata'
			end
			i = 0 ; name = "#{bname}_#{i+=1}" while pgm.sections.find { |sec| sec.name == name }

			sec = Metasm::Section.new pgm, name
			sec.mprot = { 'X' => :x, 'W' => :w, 'R' => :r }.values_at(s.header.flags).compact
			sec.base = s.header.vaddr
			sec.encoded << s.encoded

			pgm.sections << sec
		}

		# TODO import/export, misc opts (interp, soname, needed, init/fini etc)

		pgm
	end

	def sections_to_program
		decode_sections
		case @header.machine
		when '386': cpu = Ia32.new	# check @header.e_class for 64bits
		else
			puts "W: Elf: Unknown CPU #{@header.machine}"
			cpu = UnknownCpu.new(@header.e_class, @header.endianness)
		end

		pgm = Program.new cpu

		@sections.each { |s|
			# TODO
		}

		pgm
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

