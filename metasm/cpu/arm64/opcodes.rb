#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/arm64/main'

module Metasm
class ARM64
	private

	def addop(name, bin, *args)
		o = Opcode.new name, bin
		args.each { |a|
			o.args << a if @valid_args[a]
			o.props[a] = true if @valid_props[a]
		}

		args.each { |a| o.fields[a] = [@fields_mask[a], @fields_shift[a]] if @fields_mask[a] }

		@opcode_list << o
	end

	def addop_cc(n, bin, *args)
		%w[eq ne cs cc  mi pl vs vc  hi ls ge lt  gt le al al2].each_with_index { |e, i|
			args << :stopexec if e == 'al' and args.include?(:setip)
			addop n+e, bin | i, *args
		}
	end

	public
	# ARMv8 64-bits instruction set, aka AArch64
	def init_arm_v8
		@opcode_list = []

		[:sf, :stopexec, :setip, :saveip
		].each { |p| @valid_props[p] = true }

		[:rn, :rt,
   		 :i16_5, :i26_0,
		].each { |p| @valid_args[p] = true }

		@fields_mask.update :sf => 1, :rn => 0x1f, :rt => 0x1f,
			:i16_5 => 0xffff, :i26_0 => 0x3ffffff

		@fields_shift.update :sf => 31, :rn => 5, :rt => 0,
			:i16_5 => 5, :i26_0 => 0

		addop 'cbz',  0b0110100 << 24, :boff, :rt, :setip, :sf
		addop 'cbnz', 0b0110101 << 24, :boff, :rt, :setip, :sf
		addop_cc 'b', 0b0101010 << 25, :boff, :setip

		addop 'svc',   (0b11010100 << 24) | (0b000 << 21) | (0b00001), :i16_5, :stopexec
		addop 'hvc',   (0b11010100 << 24) | (0b000 << 21) | (0b00010), :i16_5, :stopexec
		addop 'smc',   (0b11010100 << 24) | (0b000 << 21) | (0b00011), :i16_5, :stopexec
		addop 'brk',   (0b11010100 << 24) | (0b001 << 21) | (0b00000), :i16_5, :stopexec
		addop 'hlt',   (0b11010100 << 24) | (0b010 << 21) | (0b00000), :i16_5, :stopexec
		addop 'dcps1', (0b11010100 << 24) | (0b101 << 21) | (0b00001), :i16_5, :stopexec
		addop 'dcps2', (0b11010100 << 24) | (0b101 << 21) | (0b00010), :i16_5, :stopexec
		addop 'dcps3', (0b11010100 << 24) | (0b101 << 21) | (0b00011), :i16_5, :stopexec

		addop 'tbz', (0b0110110 << 24), :i14_5, :rt, :sf

		addop 'b',   (0b000101 << 26), :i26_0, :setip, :stopexec
		addop 'bl',  (0b100101 << 26), :i26_0, :setip, :stopexec, :saveip
		addop 'br',  (0b1101011 << 25) | (0b0000 << 21) | (0b1111 << 16), :rn, :setip, :stopexec
		addop 'blr', (0b1101011 << 25) | (0b0001 << 21) | (0b1111 << 16), :rn, :setip, :stopexec
		addop 'ret', (0b1101011 << 25) | (0b0010 << 21) | (0b1111 << 16), :rn, :setip, :stopexec
		addop 'eret',(0b1101011 << 25) | (0b0100 << 21) | (0b1111 << 16) | (0b11111 << 5), :setip, :stopexec
		addop 'drps',(0b1101011 << 25) | (0b0101 << 21) | (0b1111 << 16) | (0b11111 << 5), :setip, :stopexec
	end

	alias init_latest init_arm_v8
end
end
