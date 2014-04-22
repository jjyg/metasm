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
			o.props.update a if a.kind_of?(::Hash)
		}

		args.each { |a| o.fields[a] = [@fields_mask[a], @fields_shift[a]] if @fields_mask[a] }

		@opcode_list << o
	end

	def addop_s31(n, bin, *args)
		addop n, bin, :r_32, *args
		addop n, (1 << 31) | bin, *args
	end

	def addop_s30(n, bin, *args)
		addop n, bin, :r_32, *args
		addop n, (1 << 30) | bin, *args
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

		[:stopexec, :setip, :saveip,
		 :r31_z,	# reg nr31 = flag ? zero : sp
		 :r_32,		# reg size == 32bit
		 :mem_incr,	# mem dereference is pre/post-increment
		 :mem_sz,	# point to uint32 => 4
		].each { |p| @valid_props[p] = true }

		[:rn, :rt, :rt2,
		 :i14_5, :i16_5, :i26_0, :i12_10_s1,
		 :m_rn_s7, :m_rn_s9, :m_rn_u12,
		].each { |p| @valid_args[p] = true }

		@fields_mask.update :rn => 0x1f, :rt => 0x1f, :rt2 => 0x1f,
			:i14_5 => 0x3fff, :i16_5 => 0xffff, :i26_0 => 0x3ffffff,
			:i12_10_s1 => 0x1fff,
			:s7_15 => 0x7f, :s9_12 => 0x1ff, :u12_10 => 0xfff,
			:m_rn_s7  => ((0x7f << 10) | 0x1f),
			:m_rn_s9  => ((0x1ff << 7) | 0x1f),
			:m_rn_u12 => ((0xfff << 5) | 0x1f)

		@fields_shift.update :rn => 5, :rt => 0, :rt2 => 10,
			:i14_5 => 5, :i16_5 => 5, :i26_0 => 0,
			:i12_10_s1 => 10,
			:s7_15 => 15, :s9_12 => 12, :u12_10 => 10,
			:m_rn_s7 => 5, :m_rn_s9 => 5, :m_rn_u12 => 5

		addop_s31 'cbz',  0b0110100 << 24, :rt, :boff, :setip
		addop_s31 'cbnz', 0b0110101 << 24, :rt, :boff, :setip
		addop_cc 'b', 0b0101010 << 25, :boff, :setip

		addop 'svc',   (0b11010100 << 24) | (0b000 << 21) | (0b00001), :i16_5, :stopexec
		addop 'hvc',   (0b11010100 << 24) | (0b000 << 21) | (0b00010), :i16_5, :stopexec
		addop 'smc',   (0b11010100 << 24) | (0b000 << 21) | (0b00011), :i16_5, :stopexec
		addop 'brk',   (0b11010100 << 24) | (0b001 << 21) | (0b00000), :i16_5, :stopexec
		addop 'hlt',   (0b11010100 << 24) | (0b010 << 21) | (0b00000), :i16_5, :stopexec
		addop 'dcps1', (0b11010100 << 24) | (0b101 << 21) | (0b00001), :i16_5, :stopexec
		addop 'dcps2', (0b11010100 << 24) | (0b101 << 21) | (0b00010), :i16_5, :stopexec
		addop 'dcps3', (0b11010100 << 24) | (0b101 << 21) | (0b00011), :i16_5, :stopexec

		addop_s31 'tbz', (0b0110110 << 24), :rt, :i14_5

		addop 'b',   (0b000101 << 26), :i26_0, :setip, :stopexec
		addop 'bl',  (0b100101 << 26), :i26_0, :setip, :stopexec, :saveip
		addop 'br',  (0b1101011 << 25) | (0b0000 << 21) | (0b1111 << 16), :rn, :setip, :stopexec
		addop 'blr', (0b1101011 << 25) | (0b0001 << 21) | (0b1111 << 16), :rn, :setip, :stopexec
		addop 'ret', (0b1101011 << 25) | (0b0010 << 21) | (0b1111 << 16), :rn, :setip, :stopexec
		addop 'eret',(0b1101011 << 25) | (0b0100 << 21) | (0b1111 << 16) | (0b11111 << 5), :setip, :stopexec
		addop 'drps',(0b1101011 << 25) | (0b0101 << 21) | (0b1111 << 16) | (0b11111 << 5), :setip, :stopexec

		addop_s31 'mov',  (0b0010001 << 24), :rt, :rn			# add a, b, 0 alias mov a, b
		addop_s31 'add',  (0b0010001 << 24), :rt, :rn, :i12_10_s1
		addop_s31 'adds', (0b0110001 << 24), :rt, :rn, :i12_10_s1
		addop_s31 'sub',  (0b1010001 << 24), :rt, :rn, :i12_10_s1
		addop_s31 'subs', (0b1110001 << 24), :rt, :rn, :i12_10_s1

		addop_s31 'movn', (0b00100101 << 23), :rt, :i16_5
		addop_s31 'movz', (0b10100101 << 23), :rt, :i16_5
		addop_s31 'movk', (0b11100101 << 23), :rt, :i16_5

		addop_s30 'ldr', (0b10_111_0_00_01_0 << 21) | (0b01 << 10), :rt, :m_rn_s9, :mem_incr => :post
		addop_s30 'ldr', (0b10_111_0_00_01_0 << 21) | (0b11 << 10), :rt, :m_rn_s9, :mem_incr => :pre
		addop_s30 'ldr',  0b10_111_0_01_01_0 << 21, :rt, :m_rn_u12

		addop_s31 'stp',  0b00_101_0_001_0 << 22, :rt, :rt2, :m_rn_s7, :mem_incr => :post
		addop_s31 'stp',  0b00_101_0_011_0 << 22, :rt, :rt2, :m_rn_s7, :mem_incr => :pre
		addop_s31 'stp',  0b00_101_0_010_0 << 22, :rt, :rt2, :m_rn_s7
	end

	alias init_latest init_arm_v8
end
end
