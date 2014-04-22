#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/arm64/opcodes'
require 'metasm/decode'

module Metasm
class ARM64
	# create the bin_mask for a given opcode
	def build_opcode_bin_mask(op)
		# bit = 0 if can be mutated by an field value, 1 if fixed by opcode
		op.bin_mask = 0
		op.fields.each { |k, (m, s)|
			op.bin_mask |= m << s
		}
		op.bin_mask = 0xffffffff ^ op.bin_mask
	end

	# create the lookaside hash from the first byte of the opcode
	def build_bin_lookaside
		lookaside = Array.new(256) { [] }

		opcode_list.each { |op|
			build_opcode_bin_mask op

			b   = (op.bin >> 24) & 0xff
			msk = (op.bin_mask >> 24) & 0xff
			b &= msk

			for i in b..(b | (255^msk))
				lookaside[i] << op if i & msk == b
			end
		}

		lookaside
	end

	def decode_findopcode(edata)
		return if edata.ptr+4 > edata.length
		di = DecodedInstruction.new(self)
		val = edata.decode_imm(:u32, @endianness)
		di.raw_data = val
		di if di.opcode = @bin_lookaside[(val >> 24) & 0xff].find { |op|
			(op.bin & op.bin_mask) == (val & op.bin_mask)
		}
	end

	def disassembler_default_func
		df = DecodedFunction.new
		df
	end

	def decode_instr_op(edata, di)
		op = di.opcode
		di.instruction.opname = op.name
		val = di.raw_data

		field_val = lambda { |f|
			(val >> @fields_shift[f]) & @fields_mask[f]
		}

		op.args.each { |a|
			di.instruction.args << case a
			when :rd, :rn, :rm, :rt
				nr = field_val[a]
				nr = 32 if nr == 31 and op.props[:r_z]
				Reg.new nr, (op.props[:r_32] ? 32 : 64)
			when :i16_5; Expression[field_val[a]]
			when :i24_0; Expression[field_val[a]]
			when :i12_10_s1
				f = field_val[a]
				f = (f & 0xfff) << 12 if (f >> 12) & 1 == 1
				Expression[f]
			else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
			end
		}

		di.bin_length = 4
		di
	end

	def decode_instr_interpret(di, addr)
		if di.opcode.args[-1] == :i24
			di.instruction.args[-1] = Expression[di.instruction.args[-1] + addr + 8]
		end
		di
	end

	def backtrace_binding
		@backtrace_binding ||= init_backtrace_binding
	end

	def init_backtrace_binding
		@backtrace_binding ||= {}
	end

	def get_backtrace_binding(di)
		a = di.instruction.args.map { |arg|
			case arg
			when Reg; arg.symbolic
			when Memref; arg.symbolic(di.address)
			else arg
			end
		}

		if binding = backtrace_binding[di.opcode.name]
			binding[di, *a]
		else
			puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
			# assume nothing except the 1st arg is modified
			case a[0]
			when Indirection, Symbol; { a[0] => Expression::Unknown }
			when Expression; (x = a[0].externals.first) ? { x => Expression::Unknown } : {}
			else {}
			end.update(:incomplete_binding => Expression[1])
		end

	end

	def get_xrefs_x(dasm, di)
		if di.opcode.props[:setip]
			[di.instruction.args.last]
		else
			# TODO ldr pc, ..
			[]
		end
	end
end
end
