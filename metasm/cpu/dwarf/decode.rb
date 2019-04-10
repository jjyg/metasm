#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/dwarf/opcodes'
require 'metasm/decode'

module Metasm
class Dwarf
	def build_bin_lookaside
		lookaside = (0..0xff).inject({}) { |h, i| h.update i => [] }
		opcode_list.each { |op|
			lookaside[op.bin] << op
		}
		lookaside
	end

	def decode_findopcode(edata)
		di = DecodedInstruction.new(self)
		val = edata.get_byte
		di if di.opcode = bin_lookaside[val].first
	end

	def decode_instr_op(edata, di)
		before_ptr = edata.ptr
		op = di.opcode
		di.instruction.opname = op.name

		op.args.each { |a|
			di.instruction.args << case a
			when :i8, :u8, :i16, :u16, :i32, :u32, :i64, :u64; Expression[edata.decode_imm(a, @endianness)]
			when :addr; Expression[edata.decode_imm("u#@size".to_sym, @endianness)]
			when :uleb; Expression[edata.decode_leb(false)]
			when :sleb; Expression[edata.decode_leb(true)]
			when :imm; Expression[op.props[:imm]]
			when :reg; di.instruction.args[0] = Reg.new(di.instruction.args[0].reduce) ; next
			when :gnu; len = edata.get_byte; len = @size/8 if len == 0 ; Expression[edata.decode_imm("u#{len*8}", @endianness)]
			else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
			end
		}

		di.bin_length = 1 + edata.ptr - before_ptr
		di
	end

	def decode_instr_interpret(di, addr)
		if di.opcode.props[:setip]
			delta = di.instruction.args.first.reduce
			di.instruction.args[0] = Expression[addr + delta + di.bin_length]
		end
		di
	end

	def init_backtrace_binding
		@backtrace_binding ||= {}

		sz = @size/8
		opstack = lambda { |off| Indirection[Expression[:opstack, :-, off*sz].reduce, sz] }
		push_opstack = lambda { |val| { :opstack => Expression[:opstack, :+, sz], opstack[0] => Expression[val] } }
		push_op2 = lambda { |op| { :opstack => Expression[:opstack, :-, sz],
			opstack[0] => Expression[[opstack[1], op, opstack[0]], :&, (1<<@size)-1] } }

		opcode_list.map { |ol| ol.name }.uniq.each { |opname|
			@backtrace_binding[opname] ||= case opname
			when 'addr', 'lit'; lambda { |di, a1| push_opstack[a1] }
			when 'dup';  lambda { |di| push_opstack[opstack[0]] }
			when 'drop'; lambda { |di| { :opstack => Expression[:opstack, :-, sz] } }
			when 'over'; lambda { |di| push_opstack[opstack[1]] }
			when 'pick'; lambda { |di, a1| push_opstack[opstack[-a1.reduce]] }	# 0 => dup
			when 'swap'; lambda { |di| { opstack[0] => Expression[opstack[1]], opstack[1] => Expression[opstack[0]] } }
			# backtrace order
			when 'rot'; lambda { |di| { opstack[0] => Expression[opstack[2]], opstack[1] => Expression[opstack[0]], opstack[2] => Expression[opstack[1]] } }
			#when 'xderef';
			when 'deref'; lambda { |di| { opstack[0] => Expression[Indirection[opstack[0], sz]] } }
			when 'abs'; lambda { |di| { opstack[0] => Expression[opstack[0], :-, [[[opstack[0], :>>, sz-1], :&, 1], :*, [2, :*, opstack[0]]]] } }
			when 'neg'; lambda { |di| { opstack[0] => Expression[:-, opstack[0]] } }
			when 'not'; lambda { |di| { opstack[0] => Expression[:~, opstack[0]] } }
			when 'add_u'; lambda { |di, a1| { opstack[0] => Expression[opstack[0], :+, a1] } }
			when 'deref_size'; lambda { |di, a1| { opstack[0] => Expression[Indirection[opstack[0], a1.reduce]] } }
			when 'and', 'div', 'sub', 'mod', 'mul', 'or', 'add', 'shl', 'shr', 'shra', 'xor', 'eq', 'ge', 'gt', 'le', 'lt', 'ne'
				o = { 'and' => :&, 'div' => :/, 'sub' => :-, 'mod' => :%, 'mul' => :*, 'or' => :|,
					'add' => :+, 'shl' => :<<, 'shr' => :>>, 'shra' => :>>, 'xor' => :^,
					'eq' => :'==', 'ne' => :'!=', 'le' => :'<=', 'lt' => :<, 'ge' => :'>=', 'gt' => :> }[opname]
				lambda { |di| push_op2[o] }
			when 'reg'; lambda { |di, a1| push_opstack[a1] }
			when 'breg'; lambda { |di, a1, a2| push_opstack[Expression[a1, :+, a2]] }
			when 'bra'; lambda { |di, a| { :opstack => Expression[:opstack, :-, sz] } }
			when 'skip'; lambda { |di, a| {} }
			when 'nop'; lambda { |di| {} }
			end
		}

		@backtrace_binding
	end

	def get_backtrace_binding(di)
		if binding = backtrace_binding[di.opcode.name]
			a = di.instruction.args.map { |arg| symbolic(arg, di) }
			binding[di, *a] || {}
		else
			puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
			{:incomplete_binding => Expression[1]}
		end
	end

	# TODO real forwardbind/backwardbind
	#def fix_fwdemu_binding(di, fbd)
	#end

	def get_xrefs_x(dasm, di)
		return [] if not di.opcode.props[:setip]
		[di.instruction.args.first]
	end

	def backtrace_is_function_return(expr, di=nil)
		false
	end

	def backtrace_is_stack_address(expr)
		Expression[expr].expr_externals.include?(:opstack)
	end
end
end
