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

	def addop_sf(n, bin, *args)
		addop n, bin, :r_32, *args
		addop n, (1 << 31) | bin, *args
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

		[:r_32, :stopexec, :setip, :saveip, :r31_z
		].each { |p| @valid_props[p] = true }

		[:rn, :rt,
		 :i14_5, :i16_5, :i26_0, :i12_10_s1
		].each { |p| @valid_args[p] = true }

		@fields_mask.update :rn => 0x1f, :rt => 0x1f,
			:i14_5 => 0x3fff, :i16_5 => 0xffff, :i26_0 => 0x3ffffff,
			:i12_10_s1 => 0x1fff

		@fields_shift.update :rn => 5, :rt => 0,
			:i14_5 => 5, :i16_5 => 5, :i26_0 => 0,
			:i12_10_s1 => 10

		addop_sf 'cbz',  0b0110100 << 24, :rt, :boff, :setip
		addop_sf 'cbnz', 0b0110101 << 24, :rt, :boff, :setip
		addop_cc 'b', 0b0101010 << 25, :boff, :setip

		addop 'svc',   (0b11010100 << 24) | (0b000 << 21) | (0b00001), :i16_5, :stopexec
		addop 'hvc',   (0b11010100 << 24) | (0b000 << 21) | (0b00010), :i16_5, :stopexec
		addop 'smc',   (0b11010100 << 24) | (0b000 << 21) | (0b00011), :i16_5, :stopexec
		addop 'brk',   (0b11010100 << 24) | (0b001 << 21) | (0b00000), :i16_5, :stopexec
		addop 'hlt',   (0b11010100 << 24) | (0b010 << 21) | (0b00000), :i16_5, :stopexec
		addop 'dcps1', (0b11010100 << 24) | (0b101 << 21) | (0b00001), :i16_5, :stopexec
		addop 'dcps2', (0b11010100 << 24) | (0b101 << 21) | (0b00010), :i16_5, :stopexec
		addop 'dcps3', (0b11010100 << 24) | (0b101 << 21) | (0b00011), :i16_5, :stopexec

		addop_sf 'tbz', (0b0110110 << 24), :rt, :i14_5

		addop 'b',   (0b000101 << 26), :i26_0, :setip, :stopexec
		addop 'bl',  (0b100101 << 26), :i26_0, :setip, :stopexec, :saveip
		addop 'br',  (0b1101011 << 25) | (0b0000 << 21) | (0b1111 << 16), :rn, :setip, :stopexec
		addop 'blr', (0b1101011 << 25) | (0b0001 << 21) | (0b1111 << 16), :rn, :setip, :stopexec
		addop 'ret', (0b1101011 << 25) | (0b0010 << 21) | (0b1111 << 16), :rn, :setip, :stopexec
		addop 'eret',(0b1101011 << 25) | (0b0100 << 21) | (0b1111 << 16) | (0b11111 << 5), :setip, :stopexec
		addop 'drps',(0b1101011 << 25) | (0b0101 << 21) | (0b1111 << 16) | (0b11111 << 5), :setip, :stopexec

		addop_sf 'mov',  (0b0010001 << 24), :rt, :rn			# add a, b, 0 alias mov a, b
		addop_sf 'add',  (0b0010001 << 24), :rt, :rn, :i12_10_s1
		addop_sf 'adds', (0b0110001 << 24), :rt, :rn, :i12_10_s1
		addop_sf 'sub',  (0b1010001 << 24), :rt, :rn, :i12_10_s1
		addop_sf 'subs', (0b1110001 << 24), :rt, :rn, :i12_10_s1

		addop_sf 'movn', (0b00100101 << 23), :rt, :i16_5
		addop_sf 'movz', (0b10100101 << 23), :rt, :i16_5
		addop_sf 'movk', (0b11100101 << 23), :rt, :i16_5
	end

	alias init_latest init_arm_v8
end
end
