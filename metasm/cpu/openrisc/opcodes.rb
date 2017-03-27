#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/openrisc/main'

module Metasm

# https://sourceware.org/cgen/gen-doc/openrisc-insn.html
# metasm/misc/openrisc-parser.rb
# fix sb/sh/sw
class OpenRisc
	def addop(name, bin, *args)
		o = Opcode.new name, bin
		args.each { |a|
			o.args << a if @valid_args[a]
			o.props.update a if a.kind_of?(::Hash)
		}
		@opcode_list << o
	end

	def init_or1300
		@opcode_list = []
		@valid_args = { :rD => [:rD], :rA => [:rA], :rB => [:rB], :lo16 => [:lo16], :disp26 => [:disp26], :uimm16 => [:uimm16], :abs26 => [:abs26], :rA_simm16 => [:rA, :simm16], :hi16 => [:hi16], :uimm5 => [:uimm5], :rA_ui16nc => [:rA, :ui16nc], :simm16 => [:simm16] }
		@fields_off = { :rD => 21, :rA => 16, :rB => 11, :lo16 => 0, :disp26 => 0, :uimm16 => 0, :rA_ign => 16, :abs26 => 0, :uimm16_ign => 0, :simm16 => 0, :hi16 => 0, :rD_ign => 21, :uimm5 => 0, :ui16nc => 0 }
		@fields_mask = { :rD => 0x1F, :rA => 0x1F, :rB => 0x1F, :lo16 => 0xFFFF, :disp26 => 0x3FFFFFF, :uimm16 => 0xFFFF, :rA_ign => 0x1F, :abs26 => 0x3FFFFFF, :uimm16_ign => 0xFFFF, :simm16 => 0xFFFF, :hi16 => 0xFFFF, :rD_ign => 0x1F, :uimm5 => 0x1F, :ui16nc => 0xFFFF }

		addop 'add', 0xE0000000, :rD, :rA, :rB
		addop 'addi', 0x94000000, :rD, :rA, :lo16
		addop 'and', 0xE0000003, :rD, :rA, :rB
		addop 'andi', 0xA0000000, :rD, :rA, :lo16
		addop 'bal', 0x08000000, :disp26
		addop 'bf', 0x10000000, :disp26
		addop 'bnf', 0x0C000000, :disp26
		addop 'brk', 0x17000000, :uimm16, :rA_ign
		addop 'div', 0xE0000009, :rD, :rA, :rB
		addop 'divu', 0xE000000A, :rD, :rA, :rB
		addop 'j', 0x00000000, :abs26
		addop 'jal', 0x04000000, :abs26
		addop 'jalr', 0x14200000, :rA, :uimm16_ign
		addop 'jr', 0x14000000, :rA, :uimm16_ign
		addop 'lbs', 0x88000000, :rD, :rA_simm16
		addop 'lbz', 0x84000000, :rD, :rA_simm16
		addop 'lhs', 0x90000000, :rD, :rA_simm16
		addop 'lhz', 0x8C000000, :rD, :rA_simm16
		addop 'lw', 0x80000000, :rD, :rA_simm16
		addop 'mfsr', 0x1C000000, :rD, :rA, :uimm16_ign
		addop 'movhi', 0x18000000, :rD, :hi16, :rA_ign
		addop 'mtsr', 0x40000000, :rA, :rB, :rD_ign
		addop 'mul', 0xE0000006, :rD, :rA, :rB
		addop 'muli', 0xAC000000, :rD, :rA, :lo16
		addop 'nop', 0x15000000, :rA_ign, :uimm16_ign
		addop 'or', 0xE0000004, :rD, :rA, :rB
		addop 'ori', 0xA4000000, :rD, :rA, :lo16
		addop 'rfe', 0x14400000, :rA, :uimm16_ign
		addop 'ror', 0xE0000088, :rD, :rA, :rB
		addop 'rori', 0xB4000080, :rD, :rA, :uimm5
		addop 'sb', 0xD8000000, :rA_ui16nc, :rD
		addop 'sfeq', 0xE4000000, :rA, :rB
		addop 'sfeqi', 0xB8000000, :rA, :simm16
		addop 'sfges', 0xE4E00000, :rA, :rB
		addop 'sfgesi', 0xB8E00000, :rA, :simm16
		addop 'sfgeu', 0xE4600000, :rA, :rB
		addop 'sfgeui', 0xB8600000, :rA, :uimm16
		addop 'sfgts', 0xE4C00000, :rA, :rB
		addop 'sfgtsi', 0xB8C00000, :rA, :simm16
		addop 'sfgtu', 0xE4400000, :rA, :rB
		addop 'sfgtui', 0xB8400000, :rA, :uimm16
		addop 'sfles', 0xE5200000, :rA, :rB
		addop 'sflesi', 0xB9200000, :rA, :simm16
		addop 'sfleu', 0xE4A00000, :rA, :rB
		addop 'sfleui', 0xB8A00000, :rA, :uimm16
		addop 'sflts', 0xE5000000, :rA, :rB
		addop 'sfltsi', 0xB9000000, :rA, :simm16
		addop 'sfltu', 0xE4800000, :rA, :rB
		addop 'sfltui', 0xB8800000, :rA, :uimm16
		addop 'sfne', 0xE4200000, :rA, :rB
		addop 'sfnei', 0xB8200000, :rA, :simm16
		addop 'sh', 0xDC000000, :rA_ui16nc, :rD
		addop 'sll', 0xE0000008, :rD, :rA, :rB
		addop 'slli', 0xB4000000, :rD, :rA, :uimm5
		addop 'sra', 0xE0000048, :rD, :rA, :rB
		addop 'srai', 0xB4000040, :rD, :rA, :uimm5
		addop 'srl', 0xE0000028, :rD, :rA, :rB
		addop 'srli', 0xB4000020, :rD, :rA, :uimm5
		addop 'sub', 0xE0000002, :rD, :rA, :rB
		addop 'subi', 0x9C000000, :rD, :rA, :lo16
		addop 'sw', 0xD4000000, :rA_ui16nc, :rD
		addop 'sys', 0x16000000, :uimm16, :rA_ign
		addop 'xor', 0xE0000005, :rD, :rA, :rB
		addop 'xori', 0xA8000000, :rD, :rA, :lo16
	end

	alias init_latest init_or1300
end
end
