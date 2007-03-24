require 'metasm/ia32/opcodes'
require 'metasm/decode'

module Metasm
class Ia32
	class ModRM
		def self.decode(edata, byte, endianness, adsz, opsz, seg=nil, regclass=Reg)
			m = (byte >> 6) & 3
			rm = byte & 7
	
			if m == 3
				return regclass.new(rm, opsz)
			end
			
			sum = Sum[adsz][m][rm]
			
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
					sib = edata.get_byte
	
					ii = ((sib >> 3) & 7)
					if ii != 4
						s = 1 << ((sib >> 6) & 3)
						i = Reg.new(ii, adsz)
					end
					
					bb = sib & 7
					if bb == 5 and m == 0
						imm = Expresion.decode(edata, "i#{adsz}".to_sym, endianness)
					else
						b = Reg.new(bb, adsz)
					end

				when :i8, :i16, :i32
					imm = Expression.decode(edata, a, endianness)

				end
			}
			
			new adsz, opsz, s, i, b, imm, seg
		end
	end

	class Farptr
		def self.decode(edata, endianness, adsz)
			addr = Expression.decode(edata, "u#{adsz}".to_sym, endianness)
			seg = Expression.decode(edata, :u16, endianness)
			new seg, addr
		end
	end

	def build_opcode_bin_mask(op)
		# bit = 0 if can be mutated by an field value, 1 if fixed by opcode
		op.bin_mask = Array.new(op.bin.length, 0)
		op.fields.each { |f, (oct, off)|
			op.bin_mask[oct] |= (@fields_mask[f] << off)
		}
		op.bin_mask.map! { |v| 255 ^ v }
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
				lookaside[i] << op
			end
		}
		lookaside
	end

	def decode_prefix(program, instr, byte)
		# XXX check multiple occurences ?
		(instr.prefix[:list] ||= []) << byte

		case byte
		when 0x66: instr.prefix[:opsz] = true
		when 0x67: instr.prefix[:adsz] = true
		when 0xF0: instr.prefix[:lock] = true
		when 0xF2: instr.prefix[:rep]  = :nz
		when 0xF3: instr.prefix[:rep]  = :z
		when 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65
			if byte & 0x40 == 0
				v = (byte >> 3) & 3
			else
				v = byte & 7
			end
			instr.prefix[:seg] = SegReg.new(v)
			
			instr.prefix[:jmphint] = ((pfx & 0x10) == 0x10)	
		else
			raise InvalidOpcode, "unknown opcode byte #{byte}"
		end
	end

	def decode_findopcode(program, edata, di)
		# tries to find the opcode encoded at edata.ptr
		# tries to match a prefix if no match, updates di.instruction.prefix
		# on match, edata.ptr points to the first byte of the opcode (after prefixes)
		loop do
			return if di.opcode = @bin_lookaside[edata.data[edata.ptr]].find { |op|
				# fetch the relevant bytes from edata
				bseq = edata.data[edata.ptr, op.bin.length].unpack('C*')

				# check against full opcode mask
				op.bin.zip(bseq, op.bin_mask).all? { |b1, b2, m| b2 and ((b1 & m) == (b2 & m)) } and
				# check special cases
				!(
				  # fail if any of those is true
				  (fld = op.fields[:seg2A]  and (bseq[fld[0]] >> fld[1]) & @fields_mask[:seg2A] == 1) or		# field byte outside of edata.data is handled in the above #all
				  (fld = op.fields[:modrmA] and (bseq[fld[0]] >> fld[1]) & 0xC0 == 0xC0) or
				  (sz  = op.props[:opsz]    and ((di.instruction.prefix[:opsz] and @size != 48-sz) or (not di.instruction.prefix[:opsz] and @size != sz))) or
				  (pfx = op.props[:needpfx] and not (di.instruction.prefix[:list] || []).include? pfx)
				 )
			}

			decode_prefix(program, di.instruction, edata.get_byte)
		end
	end

	def decode_instruction(program, edata, di)
		op = di.opcode
		di.instruction.opname = op.name
		bseq = op.bin.inject([]) { |ar, bin| ar << edata.get_byte }

		field_val = proc { |f|
			if fld = op.fields[f]
				(bseq[fld[0]] >> fld[1]) & @fields_mask[f]
			end
		}

		if field_val[:s] == 1
			imm32s = true
		end

		if field_val[:w] == 0
			opsz = 8
		elsif di.instruction.prefix[:opsz]
			opsz = 48 - @size
		else
			opsz = @size
		end

		if di.instruction.prefix[:adsz]
			adsz = 48 - @size
		else
			adsz = @size
		end
		
		op.args.each { |a|
			di.instruction.args << case a
			when :reg:    Reg.new     field_val[a], opsz
			when :eeec:   CtrlReg.new field_val[a]
			when :eeed:   DbgReg.new  field_val[a]
			when :seg2, :seg2A, :seg3: SegReg.new field_val[a]
			when :regfp:  FpReg.new   field_val[a]
			when :regmmx: SimdReg.new field_val[a], 64
			when :regxmm: SimdReg.new field_val[a], 128

			when :farptr: Farptr.decode edata, @endianness, adsz
			when :i8, :u8, :u16: Expression.decode edata, a, @endianness
			when :i:   Expression.decode edata, (imm32s ? :i8 : "i#{opsz}".to_sym), @endianness

			when :mrm_imm:  ModRM.decode edata, (adsz == 16 ? 6 : 5), @endianness, adsz, opsz, di.instruction.prefix[:seg]
			when :modrm, :modrmA: ModRM.decode edata, field_val[a], @endianness, adsz, (op.props[:argsz] || opsz), di.instruction.prefix[:seg]
			when :modrmmmx: ModRM.decode edata, field_val[a], @endianness, adsz, 64, di.instruction.prefix[:seg], SimdReg
			when :modrmxmm: ModRM.decode edata, field_val[a], @endianness, adsz,128, di.instruction.prefix[:seg], SimdReg

			when :imm_val1: Expression[1]
			when :imm_val3: Expression[3]
			when :reg_cl:   Reg.new 1, 8
			when :reg_eax:  Reg.new 0, opsz
			when :reg_dx:   Reg.new 2, 16
			when :regfp0:   FpReg.new nil	# implicit?
			else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
			end
		}

		if op.name == 'movsx' or op.name == 'movzx'
			# TODO
			#di.instruction.arg[0].sz = 28
		end

		di.instruction.prefix.delete :opsz
		di.instruction.prefix.delete :adsz
		di.instruction.prefix.delete :seg
		case r = di.instruction.prefix.delete(:rep)
		when :z
			if di.opcode.props[:strop]
				di.instruction.prefix[:rep] = 'rep'
			elsif di.opcode.props[:stropz]
				di.instruction.prefix[:rep] = 'repz'
			end
		when :nz
			if di.opcode.props[:stropz]
				di.instruction.prefix[:rep] = 'repnz'
			end
		end
	end

	def emu_backtrace(di, off, value)
		symify = proc { |tg|
			case tg
			when ModRM
				e = nil
				e = Expression[e, :+, tg.b.to_s.to_sym] if tg.b
				e = Expression[e, :+, tg.s == 1 ? tg.i.to_s.to_sym : [tg.s, :*, tg.i.to_s.to_sym]] if tg.i
				e = Expression[e, :+, tg.imm] if tg.imm
				Indirection.new(e, "u#{tg.sz || @size}".to_sym)
			when Reg
				tg.to_s.to_sym
			else
				tg
			end
		}

		a = di.instruction.args.map { |arg| symify[arg] }
		case di.opcode.name
		when 'mov'
			value.bind a[0] => a[1]
		when 'add', 'sub'
			value.bind a[0] => Expression[a[0], (di.opcode.name == 'add' ? :+ : :-), a[1]]
		when 'push'
			if value.kind_of? Indirection and value.target.reduce == Expression[:esp]
				a[0]
			else
				value.bind :esp, Expression[:esp, :-, @size/8]
			end
		when 'pop'
			if value.reduce == Expression[a[0]].reduce
				Indirection.new(Expression[:esp], "u#@size".to_sym)
			else
				value.bind :esp, Expression[:esp, :+, @size/8]
			end
		when 'call'
			if value.kind_of? Indirection and value.target.reduce == Expression[:esp]
				Expression[off + di.bin_length]
			else
				value.bind :esp, Expression[:esp, :-, @size/8]
			end
		when 'jmp', 'jz', 'jnz', 'nop'	# etc etc
		end

	end

	def get_jump_targets(pgm, di, off)
		if di.opcode.name == 'ret'
			tg = Indirection.new(Expression[:esp], "u#@size".to_sym)
		elsif (tg = di.instruction.args.first).kind_of? Expression
			delta = tg.reduce
			if delta.kind_of? Integer
				tg = off + di.bin_length + delta
				labelpfx = di.opcode.name[0..3] == 'call' ? 'func' : 'label'
				di.instruction.args[0] = Expression[pgm.make_label(tg, labelpfx), :-, pgm.make_label(off + di.bin_length)]
				tg = Expression[tg]
			end
		elsif tg.kind_of? ModRM
			e = nil
			e = Expression[e, :+, tg.b.to_s.to_sym] if tg.b
			e = Expression[e, :+, tg.s == 1 ? tg.i.to_s.to_sym : [tg.s, :*, tg.i.to_s.to_sym]] if tg.i
			e = Expression[e, :+, tg.imm] if tg.imm
			tg = Indirection.new(e, "u#{tg.sz || @size}".to_sym)
		elsif tg.kind_of? Reg
			tg = tg.to_s.to_sym
		end
		[tg].compact
	end
end
end
