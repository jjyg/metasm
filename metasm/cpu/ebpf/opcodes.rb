#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/ebpf/main'

module Metasm

class EBPF
	def addop(name, bin, *args)
		o = Opcode.new name, bin
		args.each { |a|
			o.args << a if @valid_args[a]
			o.props.update a if a.kind_of?(::Hash)
		}
		@opcode_list << o
	end

	def addop_alu(name, bin)
		addop name, bin | 0x07, :rd, :i
		addop name, bin | 0x0F, :rd, :rs
		addop name+'32', bin | 0x04, :rd, :i
		addop name+'32', bin | 0x0C, :rd, :rs
	end

	def addop_ldx(name, bin, dst, src)
		addop 'mov', bin | 0x00, dst, src, :msz => 4	# ldxw
		addop 'mov', bin | 0x08, dst, src, :msz => 2	# ldxh
		addop 'mov', bin | 0x10, dst, src, :msz => 1	# ldxb
		addop 'mov', bin | 0x18, dst, src, :msz => 8	# ldxdw
	end

	def addop_j(name, bin)
		addop name, bin | 0x00, :rd, :i, :off, :setip
		addop name, bin | 0x08, :rd, :rs, :off, :setip
	end

	def init_ebpf
		@opcode_list = []
		[:i, :rs, :rd, :off, :p_rs_o, :p_rd_o].each { |a| @valid_args[a] = true }

		# ALU
		addop_alu 'add', 0x00
		addop_alu 'sub', 0x10
		addop_alu 'mul', 0x20
		addop_alu 'div', 0x30
		addop_alu 'or',  0x40
		addop_alu 'and', 0x50
		addop_alu 'shl', 0x60
		addop_alu 'shr', 0x70
		addop 'neg',     0x87, :rd
		addop 'neg32',   0x84, :rd
		addop_alu 'mod', 0x90
		addop_alu 'xor', 0xa0
		addop_alu 'mov', 0xb0
		addop_alu 'sar', 0xc0

		addop 'le', 0xd4, :i, :rd	# native to little endian (short if i==16, word if i==32, quad if imm==64)
		addop 'be', 0xd4, :i, :rd	# native to big endian

		# LD/ST
		addop 'mov', 0x18, :rd, :i	# 'lddw'
		#addop_ldx 'ldabs', 0x20, :rs, :rd, :i
		#addop_ldx 'ldind', 0x40, :rs, :rd, :i
		addop_ldx 'ldx', 0x61, :rd, :p_rs_o
		addop_ldx 'st', 0x62, :p_rd_o, :rs
		addop_ldx 'stx', 0x63, :p_rd_o, :rs

		# BRANCH
		addop 'jmp', :off, :setip, :stopexec	# 'ja'
		addop_j 'jeq',  0x15
		addop_j 'jgt',  0x25
		addop_j 'jge',  0x35
		addop_j 'jset', 0x45
		addop_j 'jne',  0x55
		addop_j 'jsgt', 0x65
		addop_j 'jsge', 0x75
		addop 'call', 0x85, :i, :setip, :saveip, :stopexec	# XXX off ?
		addop 'ret', 0x95, :stopexec	# 'exit'
	end

	alias init_latest init_ebpf
end
end
