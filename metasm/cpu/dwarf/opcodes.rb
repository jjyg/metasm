#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/dwarf/main'

module Metasm
class Dwarf
	def addop(name, bin, *args)
		o = Opcode.new name, bin

		args.each { |a|
			if a.kind_of?(::Symbol)
				o.args << a
			elsif a.kind_of?(::Hash)
				o.props.update a
			else
				raise "Internal error #{a.inspect}"
			end
		}

		@opcode_list << o
	end

	def addop_20(name, bin, *args)
		0x20.times { |i|
			addop name, bin+i, :imm, *args, :imm => i
		}
	end

	def init
		@opcode_list = []
		@valid_props = { :setip => true, :stopexec => true, :imm => true }

		addop 'addr', 0x03, :addr

		addop 'lit', 0x08, :u8
		addop 'lit', 0x09, :i8
		addop 'lit', 0x0A, :u16
		addop 'lit', 0x0B, :i16
		addop 'lit', 0x0C, :u32
		addop 'lit', 0x0D, :i32
		addop 'lit', 0x0E, :u64
		addop 'lit', 0x0F, :i64
		addop 'lit', 0x10, :uleb
		addop 'lit', 0x11, :sleb
		addop 'dup', 0x12
		addop 'drop', 0x13
		addop 'over', 0x14
		addop 'pick', 0x15, :u8
		addop 'swap', 0x16
		addop 'rot', 0x17
		addop 'xderef', 0x18

		# push(op(pop()))
		addop 'deref', 0x06
		addop 'abs', 0x19
		addop 'neg', 0x1F
		addop 'not', 0x20
		addop 'add_u', 0x23, :uleb	# real name plus_u
		addop 'plus_u', 0x23, :uleb
		addop 'deref_size', 0x94, :u8

		# push(op(stk[-2], stk[-1])))	pop args
		addop 'and', 0x1A
		addop 'div', 0x1B
		addop 'sub', 0x1C	# real name is 'minus'
		addop 'minus', 0x1C
		addop 'mod', 0x1D
		addop 'mul', 0x1E
		addop 'or', 0x21
		addop 'add', 0x22
		addop 'plus', 0x22
		addop 'shl', 0x24
		addop 'shr', 0x25
		addop 'shra', 0x26
		addop 'xor', 0x27

		addop 'bra', 0x28, :i16, :setip	# branch if top of stack not null

		# pop(op(stk[-1], stk[-2]))	pop args
		addop 'eq', 0x29
		addop 'ge', 0x2A
		addop 'gt', 0x2B
		addop 'le', 0x2C
		addop 'lt', 0x2D
		addop 'ne', 0x2E

		addop 'skip', 0x2F, :i16, :setip, :stopexec
		
		addop_20 'lit', 0x30
		addop_20 'reg', 0x50, :reg
		addop_20 'breg', 0x70, :sleb, :reg

		addop 'reg', 0x90, :uleb, :reg
		addop 'fbreg', 0x91, :uleb
		addop 'breg', 0x92, :uleb, :sleb, :reg
		addop 'piece', 0x93
		addop 'xderef_size', 0x95
		addop 'nop', 0x96
	end
end
end
