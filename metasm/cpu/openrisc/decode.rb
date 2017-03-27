#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/openrisc/opcodes'
require 'metasm/decode'

module Metasm
class OpenRisc
	def build_bin_lookaside
		bl = Hash.new(255) { [] }
		opcode_list.each { |op|
			op.bin_mask = 0
			op.args.each { |a|
				@valid_args[a].each { |f|
					mask |= @fields_mask[f] << @fields_off[f]
				}
			}
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

		op.args.each { |a|
			di.instruction.args << case a
			when :rA, :rB, :rD; Reg.new(fld[a])
			else raise "unhandled arg #{a}"
			end
		}

		di
	end

	def decode_instr_interpret(di, addr)
		if di.opcode.props[:setip]
		end

		di
	end

	# populate the @backtrace_binding hash with default values
	def init_backtrace_binding
		@backtrace_binding ||= {}

		opcode_list.map { |ol| ol.basename }.uniq.sort.each { |op|
			binding = case op
			when 'add'; lambda { |di, a0, a1| { a0 => Expression[a0, :+, a1] } }
			end
			@backtrace_binding[op] ||= binding if binding
		}

		@backtrace_binding
	end
end
end
