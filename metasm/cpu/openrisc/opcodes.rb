#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/openrisc/main'

module Metasm

# https://github.com/s-macke/jor1k/blob/master/js/worker/or1k/safecpu.js
class OpenRisc
	def addop(name, bin, *args)
		o = Opcode.new name, bin
		args.each { |a|
			o.bin_mask = a if a.kind_of?(Integer)
			o.args << a if @valid_args[a]
			o.props.update a if a.kind_of?(::Hash)
		}
		@opcode_list << o
	end

	def init_or1k
		@opcode_list = []
		@valid_args = [ :rA, :rB, :rD, :fA, :fB, :fD, :disp26, :uimm16, :simm16, :uimm5, :rA_simm16, :rA_smoo ].inject({}) { |h, a| h.update a => true }
		@fields_off = { :rD => 21, :rA => 16, :rB => 11, :disp26 => 0, :uimm16 => 0, :simm16 => 0, :uimm5 => 0, :smoo => 0 }
		@fields_mask = { :rD => 0x1F, :rA => 0x1F, :rB => 0x1F, :disp26 => 0x3FFFFFF, :simm16 => 0xFFFF, :uimm16 => 0xFFFF, :uimm5 => 0x1F, :smoo => 0x3E007FF }

		addop 'j',     0x0000_0000, 0x03FF_FFFF, :disp26, :setip => true, :stopexec => true
		addop 'jal',   0x0400_0000, 0x03FF_FFFF, :disp26, :setip => true, :stopexec => true, :saveip => true
		addop 'bnf',   0x0C00_0000, 0x03FF_FFFF, :disp26, :setip => true	# branch if not flag
		addop 'bf',    0x1000_0000, 0x03FF_FFFF, :disp26, :setip => true
		addop 'nop',   0x1400_0000, 0x03FF_FFFF
		addop 'movhi', 0x1800_0000, 0x03FE_FFFF, :rD, :uimm16
		addop 'macrc', 0x1801_0000, 0x03FE_FFFF
		addop 'trap',  0x2100_0000, 0x0000_FFFF
		addop 'sys',   0x2000_0000, 0x03FF_FFFF		# args ?
		addop 'rfe',   0x2400_0000, 0x03FF_FFFF
		addop 'jr',    0x4400_0000, 0x03FF_FFFF, :rB, :setip => true, :stopexec => true
		addop 'jalr',  0x4800_0000, 0x03FF_FFFF, :rB, :setip => true, :stopexec => true, :saveip => true
		addop 'lwa',   0x6C00_0000, 0x03FF_FFFF, :rD, :rA_simm16
		addop 'lwz',   0x8400_0000, 0x03FF_FFFF, :rD, :rA_simm16, :memsz => 4
		addop 'lbz',   0x8C00_0000, 0x03FF_FFFF, :rD, :rA_simm16, :memsz => 1
		addop 'lbs',   0x9000_0000, 0x03FF_FFFF, :rD, :rA_simm16, :memsz => 1	# lbz + sign-expand byte
		addop 'lhz',   0x9400_0000, 0x03FF_FFFF, :rD, :rA_simm16, :memsz => 2
		addop 'lhs',   0x9800_0000, 0x03FF_FFFF, :rD, :rA_simm16, :memsz => 2
		addop 'add',   0x9C00_0000, 0x03FF_FFFF, :rD, :rA, :simm16
		addop 'and',   0xA400_0000, 0x03FF_FFFF, :rD, :rA, :uimm16
		addop 'or',    0xA800_0000, 0x03FF_FFFF, :rD, :rA, :uimm16
		addop 'xor',   0xAC00_0000, 0x03FF_FFFF, :rD, :rA, :simm16
		addop 'mfspr', 0xB400_0000, 0x03FF_FFFF, :rD, :rA, :simm16
		addop 'shl',   0xB800_0000, 0x03FF_FF3F, :rD, :rA, :uimm5
		addop 'ror',   0xB800_0040, 0x03FF_FF3F, :rD, :rA, :uimm5
		addop 'sar',   0xB800_0080, 0x03FF_FF3F, :rD, :rA, :uimm5
		addop 'sfeq',  0xBC00_0000, 0x001F_FFFF, :rA, :simm16
		addop 'sfne',  0xBC20_0000, 0x001F_FFFF, :rA, :simm16
		addop 'sfgtu', 0xBC40_0000, 0x001F_FFFF, :rA, :uimm16
		addop 'sfgeu', 0xBC60_0000, 0x001F_FFFF, :rA, :uimm16
		addop 'sfltu', 0xBC80_0000, 0x001F_FFFF, :rA, :uimm16
		addop 'sfleu', 0xBCA0_0000, 0x001F_FFFF, :rA, :uimm16
		addop 'sfgts', 0xBD40_0000, 0x001F_FFFF, :rA, :simm16
		addop 'sfges', 0xBD60_0000, 0x001F_FFFF, :rA, :simm16
		addop 'sflts', 0xBD80_0000, 0x001F_FFFF, :rA, :simm16
		addop 'sfles', 0xBDA0_0000, 0x001F_FFFF, :rA, :simm16
		addop 'mtspr', 0xC000_0000, 0x03FF_FFFF, :rA_smoo, :rB		# smoo = (ins & 0x7ff) | ((ins >> 10) & 0xf800) ; setspr((rA|smoo), rB)
		addop 'add',   0xC800_0000, 0x03FF_FF00, :fD, :fA, :fB		# FPU
		addop 'sub',   0xC800_0001, 0x03FF_FF00, :fD, :fA, :fB
		addop 'mul',   0xC800_0002, 0x03FF_FF00, :fD, :fA, :fB
		addop 'div',   0xC800_0003, 0x03FF_FF00, :fD, :fA, :fB
		addop 'itof',  0xC800_0004, 0x03FF_FF00, :fD, :rA
		addop 'ftoi',  0xC800_0005, 0x03FF_FF00, :rD, :fA
		addop 'madd',  0xC800_0007, 0x03FF_FF00, :fD, :fA, :fB		# fD += fA*fB
		addop 'sfeq',  0xC800_0008, 0x03FF_FF00, :fA, :fB
		addop 'sfne',  0xC800_0009, 0x03FF_FF00, :fA, :fB
		addop 'sfgt',  0xC800_000A, 0x03FF_FF00, :fA, :fB
		addop 'sfge',  0xC800_000B, 0x03FF_FF00, :fA, :fB
		addop 'sflt',  0xC800_000C, 0x03FF_FF00, :fA, :fB
		addop 'sfle',  0xC800_000D, 0x03FF_FF00, :fA, :fB
		addop 'swa',   0xCC00_0000, 0x03FF_FFFF, :rA_smoo, :rB, :memsz => 4	# sw + setf(ra_smoo == current_EA ?)
		addop 'sw',    0xD400_0000, 0x03FF_FFFF, :rA_smoo, :rB, :memsz => 4
		addop 'sb',    0xD800_0000, 0x03FF_FFFF, :rA_smoo, :rB, :memsz => 1
		addop 'sh',    0xDC00_0000, 0x03FF_FFFF, :rA_smoo, :rB, :memsz => 2
		addop 'add',   0xE000_0000, 0x03FF_FC30, :rD, :rA, :rB
		addop 'sub',   0xE000_0002, 0x03FF_FC30, :rD, :rA, :rB
		addop 'and',   0xE000_0003, 0x03FF_FC30, :rD, :rA, :rB
		addop 'or',    0xE000_0004, 0x03FF_FC30, :rD, :rA, :rB
		addop 'xor',   0xE000_0005, 0x03FF_FC30, :rD, :rA, :rB
		addop 'shl',   0xE000_0008, 0x03FF_FC30, :rD, :rA, :rB
		addop 'ff1',   0xE000_000F, 0x03FF_FC30, :rD, :rA, :rB	# find first bit == 1
		addop 'shr',   0xE000_0048, 0x03FF_FC30, :rD, :rA, :rB
		addop 'sar',   0xE000_0088, 0x03FF_FC30, :rD, :rA, :rB
		addop 'fl1',   0xE000_010F, 0x03FF_FC30, :rD, :rA, :rB	# find last bit
		addop 'mul',   0xE000_0306, 0x03FF_FC30, :rD, :rA, :rB	# signed multiply ?
		addop 'div',   0xE000_0309, 0x03FF_FC30, :rD, :rA, :rB
		addop 'divu',  0xE000_030A, 0x03FF_FC30, :rD, :rA, :rB	# rD = rA&0xffffffff / rB&0xffffffff
		addop 'sfeq',  0xE400_0000, 0x001F_FFFF, :rA, :rB
		addop 'sfne',  0xE420_0000, 0x001F_FFFF, :rA, :rB
		addop 'sfgtu', 0xE440_0000, 0x001F_FFFF, :rA, :rB
		addop 'sfgeu', 0xE460_0000, 0x001F_FFFF, :rA, :rB
		addop 'sfltu', 0xE480_0000, 0x001F_FFFF, :rA, :rB
		addop 'sfleu', 0xE4A0_0000, 0x001F_FFFF, :rA, :rB
		addop 'sfgts', 0xE540_0000, 0x001F_FFFF, :rA, :rB
		addop 'sfges', 0xE560_0000, 0x001F_FFFF, :rA, :rB
		addop 'sflts', 0xE580_0000, 0x001F_FFFF, :rA, :rB
		addop 'sfles', 0xE5A0_0000, 0x001F_FFFF, :rA, :rB
	end

	alias init_latest init_or1k
end
end
