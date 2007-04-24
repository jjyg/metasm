require 'metasm/mips/opcodes'
require 'metasm/decode'

module Metasm
class MIPS
	def build_opcode_bin_mask(op)
		# bit = 0 if can be mutated by an field value, 1 if fixed by opcode
		op.bin_mask = 0
		op.args.each { |f|
			op.bin_mask |= @fields_mask[f] << @fields_shift[f]
		}
		op.bin_mask = 0xffffffff ^ op.bin_mask
	end

	def build_bin_lookaside
		lookaside = Array.new(256) { [] }
		@opcode_list.each { |op|
			build_opcode_bin_mask op

			b   = op.bin >> 24
			msk = op.bin_mask >> 24
			
			for i in b..(b | (255^msk))
				next if i & msk != b & msk
				lookaside[i] << op
			end
		}
		lookaside
	end

	def decode_findopcode(program, edata, di)
		# TODO relocations !!
		oldptr = edata.ptr
		val = Expression.decode_imm(edata, :u32, @endianness)
		edata.ptr = oldptr
		if not di.opcode = @bin_lookaside[val >> 24].find { |op|
			(op.bin & op.bin_mask) == (val & op.bin_mask)
		}
			raise "unknown opcode byte #{byte}"
		end
	end

	def decode_instruction(program, edata, di)
		# TODO relocations !!
		op = di.opcode
		di.instruction.opname = op.name
		val = Expression.decode_imm(edata, :u32, @endianness)

		field_val = proc { |f|
			(val >> @fields_shift[f]) & @fields_mask[f]
		}

		op.args.each { |a|
			di.instruction.args << case a
			when :rs, :rt, :rd: Reg.new field_val[a]
			when :sa, :i16, :i26, :it: Expression[field_val[a]]
			when :rs_i16: Memref.new field_val[:rs], field_val[:i16]
			when :ft: FpReg.new field_val[a]
			when :idm1, :idb: Expression['unsupported']
			else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
			end
		}
	end

	def emu_backtrace(di, off, value)
		symify = proc { |tg|
			case tg
			when Memref
				Indirection.new(Expression[tg.base.to_s.to_sym, :+, tg.offset], :u32)
			when Reg
				tg.to_s.to_sym
			else
				tg
			end
		}

		a = di.instruction.args.map { |arg| symify[arg] }

		case op = di.opcode.name
		when :TODO
		else nil
		end

	end

	def get_jump_targets(pgm, di, off)
		case di.opcode.name
		when :TODO
			tg = off + di.bin_length + delta
			di.instruction.args[0] = Expression[pgm.make_label(tg, 'label'), :-, pgm.make_label(off + di.bin_length)]
			[Expression[tg]]
		else []
		end
	end
end
end
