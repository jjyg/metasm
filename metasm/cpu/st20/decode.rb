#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/st20/opcodes'
require 'metasm/decode'

module Metasm
class ST20
	# decodes the instruction at edata.ptr, mapped at virtual address off
	def decode_instruction(edata, addr)
		return if edata.ptr >= edata.length
		di = DecodedInstruction.new self
		di.address = addr
		di = decode_instr_op(edata, di)
		decode_instr_interpret(di, addr)
	end

	def decode_instr_op(edata, di, pfx=0)
		# decode one byte from the bitstream, recurse if the byte is a prefix

		if edata.ptr >= edata.length or di.bin_length >= 4
			di.instruction.args << Expression[pfx]
			return di
		end

		# bytestream structure :
		# sequence of prefixes, which build a word 4 bits at a time
		# last element = function code
		# 'opr' is a special function, means use the prefix word as an opcode number from 'operate'
		byte = edata.read(1).unpack('C')[0]
		fcode = byte & 0xf0
		arg   = byte & 0x0f
		pfx = (pfx << 4) | arg
		di.opcode = @opcode_list[fcode >> 4]
		di.instruction.opname = di.opcode.name
		di.bin_length += 1

		case di.instruction.opname
		when 'pfix'
			return decode_instr_op(edata, di, pfx)

		when 'nfix'
			pfx ^= -1
			di.instruction.opname = 'pfix'	# will be displayed on EOS, and we cannot represent the whole decoded pfx with 'nfix'
			return decode_instr_op(edata, di, pfx)

		when 'opr'
			if op = @op_operate[pfx]
				# operands have no arg (they work on the implicit 3-register stack A B C)
				di.instruction.opname = op
				di.opcode = @opc_operate[op] || di.opcode
			else
				# unknown operand, keep the generic form
				di.instruction.args << Expression[pfx]
			end
		else
			di.instruction.args << Expression[pfx]
		end

		di
	end

	def decode_instr_interpret(di, addr)
		case di.instruction.opname
		when 'j', 'cj', 'fcall'
			delta = di.instruction.args.last.reduce
			arg = Expression[[addr, :+, di.bin_length], :+, delta].reduce
			di.instruction.args[-1] = Expression[arg]
		end

		di
	end

	def get_backtrace_binding(di)
		arg = di.instruction.args[0]
		case di.instruction.opname
		when 'nop'
			{}
		else
			puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
			{ :incomplete_binding => Expression[1] }
		end
	end

	def fix_fwdemu_binding(di, fbd)
	end

	def get_xrefs_x(dasm, di)
		return [] if not di.opcode.props[:setip]

		case di.opcode.basename
		when 'j', 'cj'
			[Expression[di.instruction.args.first]]
		#when 'ret'
			#[Indirection[:sp, 2, di.address]]
		else
			[]
		end
	end

	# checks if expr is a valid return expression matching the :saveip instruction
	def backtrace_is_function_return(expr, di=nil)
		expr = Expression[expr].reduce_rec
		expr.kind_of?(Indirection) and expr.len == 2 and expr.target == Expression[:sp]
	end

	# updates the function backtrace_binding
	def backtrace_update_function_binding(dasm, faddr, f, retaddrlist, *wantregs)
		b = f.backtrace_binding

		bt_val = lambda { |r|
			next if not retaddrlist
			b[r] = Expression::Unknown
			bt = []
			retaddrlist.each { |retaddr|
				bt |= dasm.backtrace(Expression[r], retaddr, :include_start => true,
					     :snapshot_addr => faddr, :origin => retaddr)
			}
			if bt.length != 1
				b[r] = Expression::Unknown
			else
				b[r] = bt.first
			end
		}

		wantregs.each(&bt_val)

		b
	end

	# returns true if the expression is an address on the stack
	def backtrace_is_stack_address(expr)
		Expression[expr].expr_externals.include?(:sp)
	end

	# updates an instruction's argument replacing an expression with another (eg label renamed)
	def replace_instr_arg_immediate(i, old, new)
		i.args.map! { |a|
			a == old ? new : Expression[a.bind(old => new).reduce]
		}
	end
end
end
