require 'metasm/ia32/opcodes'
require 'metasm/decode'

module Metasm
class Ia32
	class ModRM
		def self.decode
		end
	end

	class Farptr
		def self.decode
		end
	end

	def build_opcode_bin_mask(op)
		# bit = 0 if can be mutated by an field value, 1 if fixed by opcode
		op.bin_mask = Array.new(op.bin.length, 0)
		op.fields.each { |f, (oct, off)|
			op.bin_mask[oct] |= (@fields_mask[f] << off)
		}
		op.fields.map! { |v| 255 ^ v }
	end

	def build_bin_lookaside
		# sets up a hash byte value => list of opcodes that may match
		# opcode.bin_mask is built here
		lookaside = Array.new(256) { [] }
		@opcode_list.each { |op|

			build_opcode_bin_mask op

			b   = op.bin[0]
			msk = op.bin_mask[0]
			
			for i in b..(b | (255^msk))
				next if i & msk != b & msk
				lookaside[i] << o
			end
		}
		lookaside
	end

	def decode_prefix(program, instr, byte)
		# XXX check multiple occurences ?
		(instr.pfx[:list] ||= []) << byte
		case byte
		when 0x66: instr.pfx[:opsz] = true
		when 0x67: instr.pfx[:adsz] = true
		when 0xF0: instr.pfx[:lock] = true
		when 0xF2: instr.pfx[:rep]  = :nz
		when 0xF3: instr.pfx[:rep]  = :z
		when 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65
			if byte & 0x40 == 0
				v = (byte >> 3) & 3
			else
				v = byte & 7
			end
			instr.pfx[:seg] = SegReg.new(v)
			
			instr.pfx[:jmphint] = ((pfx & 0x10) == 0x10)	
		else
			raise InvalidOpcode, "unknown opcode byte #{byte}"
		end
	end

	def decode_findopcode(program, edata, di)
		# tries to find the opcode encoded at edata.ptr
		# tries to match a prefix if no match, updates di.instruction.pfx
		# on match, edata.ptr points to the first byte of the opcode (after prefixes)
		loop do
			return if di.opcode = @bin_lookaside[edata.data[edata.ptr]].find { |op|
				# fetch the relevant bytes from edata
				bseq = edata.data[edata.ptr, op.bin.length].unpack('C*')

				# check against full opcode mask
				bseq.zip(op.bin, op.bin_mask).all? { |b1, b2, m| b1 & m == b2 & m rescue false } and
				# check special cases
				!(
				  # fail if any of those is true
				  (fld = op.fields[:seg2A]  and (bseq[fld[0]] >> fld[1]) & @fields_mask[:seg2A] == 1) or		# field byte outside of edata.data is handled in the above #all
				  (fld = op.fields[:modrmA] and (bseq[fld[0]] >> fld[1]) & 0xC0 == 0xC0) or
				  (sz  = op.props[:opsz]    and ((di.instr.pfx[:opsz] and @size != 48-sz) or (not di.instr.pfx[:opsz] and @size != sz))) or
				  (pfx = op.props[:needpfx] and not (di.instr.pfx[:list] || []).include? pfx
				 )
			}

			decode_pfx(program, di.instruction, edata.get_byte)
		end
	end

	def decode_instr(program, edata, di)
		op = di.opcode
		di.instr.opname = op.name
		bseq = op.bin.inject([]) { |ar, bin| ar << edata.get_byte }

		field_val = proc { |f|
			if fld = op.fields[f]
				(bseq[fld[0]] >> fld[1]) & @fields_mask[f]
			end
		}

		# TODO
		if field_val[:s] == 1
			imm32s = true
		end
	end
end
end

__END__
module Metasm
class Ia32
	class ModRM
		def self.decode(mrm, ss, adsz, sz, seg=nil, regclass = Reg)
			m = (mrm >> 6) & 3
			rm = mrm & 7
	
			if m == 3
				return new_direct(regclass.new(rm, sz))
			end
			
			sum = ModrmSum[adsz][m][rm]
			
			s, i, b, imm = nil
			sum.each { |a|
				case a
				when Integer
					if not b
						b = Reg.new(a, adsz)
					else
						s = 1
						i = Reg.new(a, adsz)
					end
				
				when :sib
					sib = ss.get_byte[0]
	
					ii = ((sib >> 3) & 7)
					if ii != 4
						s = 1 << ((sib >> 6) & 3)
						i = Reg.new(ii, instr.adsz)
					end
					
					bb = sib & 7
					if bb == 5 and m == 0
						imm = Immediate.decode(ss, adsz)	# em64t => 32 or 64 ?
					else
						b = Reg.new(bb, adsz)
					end

				when :i8, :i16, :i32
					ilen = {:i8 => 8, :i16 => 16, :i32 => 32}[a]
					imm = Immediate.decode(ss, ilen, :signed => false)
				end
			}
			
			new adsz, sz, s, i, b, imm, seg
		end
	end
	
	class Farptr
		def self.decode(ss, sz)
			# swap ?
			seg  = Immediate.decode ss, 16
			addr = Immediate.decode ss, adsz
			new seg, addr
		end
	end

	class Instruction
		private
		
		# decode the instruction using @opcode
		def do_decode(ss)
			bin = ss.peek(@op.bin.length).unpack('C*')
			ss.pos += @op.bin.length

			if @op.fields[:s] and fieldval(bin, :s) == 1
				@imm32s = true
			end

			if @op.fields[:w] and fieldval(bin, :w) == 0
				@no_w_opsz = @opsz
				@opsz = 8
			end

			@op.args.each { |a|
				@args << case a
				when :reg:    Reg.new     fieldval(bin, a), @opsz
				when :eeec:   CtrlReg.new fieldval(bin, a)
				when :eeed:   DbgReg.new  fieldval(bin, a)
				when :seg2, :seg2A: SegReg.new fieldval(bin, :seg2)
				when :seg3:   SegReg.new  fieldval(bin, :seg3)
				when :regfp:  FpReg.new   fieldval(bin, a)
				when :regmmx: SimdReg.new fieldval(bin, a), 64
				when :regxmm: SimdReg.new fieldval(bin, a), 128
				when :reg_no_w: Reg.new fieldval(bin, :reg), (@no_w_opsz || @opsz)

				# modrmA != Reg if dec_valid_op? was called
				when :modrm, :modrmA: ModRM.decode fieldval(bin, :modrm), ss, @adsz, (@op.props[:argsz] || @opsz), @pfx[:seg]
				when :modrmmmx: ModRM.decode fieldval(bin, :modrm), ss, @adsz, 64,   @pfx[:seg], SimdReg
				when :modrmxmm: ModRM.decode fieldval(bin, :modrm), ss, @adsz, 128,  @pfx[:seg], SimdReg
				when :modrm16:  ModRM.decode fieldval(bin, :modrm), ss, @adsz, [@opsz,16].min, @pfx[:seg]

				when :mrm_imm:  ModRM.new @adsz, @opsz, nil, nil, nil, Immediate.decode(ss, @adsz), @pfx[:seg]

				when :farptr: Farptr.decode ss, @adsz

				when :i8:  Immediate.decode ss, 8
				when :i16: Immediate.decode ss, 16
				when :i32: Immediate.decode ss, 32
				when :ia:  Immediate.decode ss, @adsz
				when :i:   Immediate.decode ss, (@imm32s ? 8 : @opsz)

				when :imm_val1: Immediate.new 1
				when :reg_cl:   Reg.new 1, 8
				when :reg_eax:  Reg.new 0, @opsz
				when :reg_dx:   Reg.new 2, 16	# implicit
				when :regfp0:   FpReg.new nil	# implicit

				else raise SyntaxError, "Invalid argument #{a} in #{@op.name}"
				end
			}

			if @op.fields[:d] and fieldval(bin, :d) == 0
				@args_reversed = true
				@args.reverse!
			end
		end

		def decode_pfx(ss)
			# TODO detect invalid pfx sequence
			pfx = ss.get_byte[0]
			(@pfxlist ||= []) << pfx
			super if @pfxlist.length > 12	# some ppl say that 12 is the real limit on intels, need tests
		
			case pfx
			when 0x66:
				@pfx[:opsz] = true
				@opsz = 48 - @opsz	# 32 => 16, 16 => 32     # TODO 0x66 0x66 0x90 => 16 or 32 ?
			when 0x67:
				@pfx[:adsz] = true
				@adsz = 48 - @adsz
			when 0xF0: @pfx[:lock] = true
			when 0xF2: @pfx[:rep]  = :nz
			when 0xF3: @pfx[:rep]  = :z
			when 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65
				if pfx & 0x40 == 0
					v = (pfx >> 3) & 3
				else
					v = pfx & 7
				end
				@pfx[:seg] = SegReg.new(v)
	
				@pfx[:jmphint] = ((pfx & 0x10) == 0x10)
				
			else
				super
			end
		end
	
		# Checks if the opcode o is a valid candidate for the current instruction
		# Binary masking is done by the caller, we just care of special cases here
		def dec_valid_op?(bseq)
			!(
			  (@op.args.include?(:seg2A)  and (fieldval(bseq, :seg2) == 1 rescue false)) or
			  (@op.args.include?(:modrmA) and (fieldval(bseq, :modrm) & 0xC0 == 0xC0 rescue false)) or
			  (x = @op.props[:opsz]    and @opsz != x) or
			  (x = @op.props[:needpfx] and not (@pfxlist ||= []).include? x)
			)
		end
	end
end
end
