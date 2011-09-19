#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/python/opcodes'
require 'metasm/decode'

module Metasm
class Python
	def build_bin_lookaside
		opcode_list.inject({}) { |la, op| la.update op.bin => op }
	end

	def decode_findopcode(edata)
		return if edata.ptr >= edata.data.length
		di = DecodedInstruction.new(self)

		byte = edata.decode_imm(:u8, :little)

		di if di.opcode = @bin_lookaside[byte]
	end

	def decode_instr_op(edata, di)
		di.bin_length = 1

		di.instruction.opname = di.opcode.name

		di.opcode.args.each { |a|
			case a
			when :i16
				di.bin_length += 2
				di.instruction.args << edata.decode_imm(:u16, @endianness)
			else
				raise "unsupported arg #{a.inspect}"
			end
		}

		di
	end

	def backtrace_binding
		@backtrace_binding ||= init_backtrace_binding
	end

	def init_backtrace_binding
		@backtrace_binding ||= {}

		opcode_list.each { |op|
			binding = case op
				  when 'nop'; lambda { |*a| {} }
				  end
			@backtrace_binding[op] ||= binding if binding
		}

		@backtrace_binding
	end

	def get_backtrace_binding(di)
		a = di.instruction.args.map { |arg|
			case arg
			when Var; arg.symbolic
			else arg
			end
		}

		if binding = backtrace_binding[di.opcode.basename]
			bd = binding[di, *a]
		else
			puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
			{ :incomplete_binding => Expression[1] }
		end
	end

	def get_xrefs_x(dasm, di)
		return [] if not di.opcode.props[:setip]

		arg = case di.opcode.name
		      when 'brainfuck'
			      di.instruction.args.last
		      else di.instruction.args.last
		      end

		[Expression[(arg.kind_of?(Var) ? arg.symbolic : arg)]]
	end

	def backtrace_is_function_return(expr, di=nil)
		#Expression[expr].reduce == Expression['wtf']
	end
end
end
