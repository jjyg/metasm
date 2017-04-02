#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/openrisc/opcodes'
require 'metasm/decode'

module Metasm
class OpenRisc
	def build_bin_lookaside
		bl = Array.new(255) { [] }
		opcode_list.each { |op|
			((op.bin >> 24) .. ((op.bin | op.bin_mask) >> 24)).each { |b|
				if (b | (op.bin_mask >> 24)) == ((op.bin | op.bin_mask) >> 24)
					bl[b] << op
				end
			}
		}
		bl
	end

	# tries to find the opcode encoded at edata.ptr
	def decode_findopcode(edata)
		return if edata.ptr > edata.data.length-4
		di = DecodedInstruction.new self
		val = edata.decode_imm(:u32, @endianness)
		di.misc = val
		return di if di.opcode = @bin_lookaside[val >> 24].find { |op|
			(op.bin | op.bin_mask) == (val | op.bin_mask)
		}
	end

	def decode_instr_op(edata, di)
		op = di.opcode
		di.instruction.opname = op.name
		di.bin_length = 4
		val = di.misc
		fld = lambda { |f|
			(val >> @fields_off[f]) & @fields_mask[f]
		}
		sign_fld = lambda { |f, sz|
			Expression.make_signed(Expression[fld[f]], sz).reduce
		}
		fld_smoo = lambda {
			Expression[Expression.make_signed((val & 0x7ff) | ((val >> 10) & 0xF800), 16)]
		}

		op.args.each { |a|
			di.instruction.args << case a
			when :rA, :rB, :rD; Reg.new(fld[a])
			when :fA; FpReg.new(fld[:rA])
			when :fB; FpReg.new(fld[:rB])
			when :fD; FpReg.new(fld[:rD])
			when :disp26; Expression[sign_fld[a, 26]]
			when :uimm5, :uimm16; Expression[fld[a]]
			when :simm16; Expression[sign_fld[a, 16]]
			when :rA_simm16; MemRef.new(Reg.new(fld[:rA]), Expression[sign_fld[:simm16, 16]], di.opcode.props[:memsz])
			when :rA_smoo; MemRef.new(Reg.new(fld[:rA]), fld_smoo[], di.opcode.props[:memsz])
			else raise "unhandled arg #{a}"
			end
		}

		di
	end

	def decode_instr_interpret(di, addr)
		if di.opcode.props[:setip]
			case di.opcode.name
			when 'j', 'jal', 'bf', 'bnf'
				# abs26 is not absolute, duh
				arg = Expression[addr, :+, [di.instruction.args[-1], :<<, 2]].reduce
				di.instruction.args[-1] = Expression[arg]
			end
		end

		di
	end

	# populate the @backtrace_binding hash with default values
	def init_backtrace_binding
		@backtrace_binding ||= {}

		opcode_list.map { |ol| ol.basename }.uniq.sort.each { |op|
			binding = case op
			when 'movhi'; lambda { |di, a0, a1| { a0 => Expression[a1, :<<, 16] } }
			when 'add'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :+, a2] } }
			when 'sub'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :-, a2] } }
			when 'mul'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :*, a2] } }
			when 'div'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :/, a2] } }
			when 'and'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :&, a2] } }
			when 'or';  lambda { |di, a0, a1, a2| { a0 => Expression[a1, :|, a2] } }
			when 'xor'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :^, a2] } }
			when 'lwz', 'lbz', 'lhz'; lambda { |di, a0, a1| { a0 => Expression[a1] } }
			when 'lbs'; lambda { |di, a0, a1| { a0 => Expression[Expression.make_signed(a1, 8)] } }
			when 'lhs'; lambda { |di, a0, a1| { a0 => Expression[Expression.make_signed(a1, 16)] } }
			when 'sw', 'sh', 'sb';  lambda { |di, a0, a1| { a0 => Expression[a1] } }
			when 'jal', 'jalr'; lambda { |di, a0| { :r9 => Expression[di.next_addr + delay_slot(di)*4] } }
			when 'jr', 'j', 'be', 'bne'; lambda { |di, *a| {} }
			end
			@backtrace_binding[op] ||= binding if binding
		}

		@backtrace_binding
	end
end
end
