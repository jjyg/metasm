#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/dwarf/opcodes'

module Metasm
class Dwarf
	def dbg_register_list
		@dbg_register_list ||= [:r0, :r1, :r2, :r3, :opstack, :pc]
	end

	def dbg_resolve_pc(di, fbd, pc_reg, dbg_ctx)
		case di.opcode.name
		when 'bra'
			if dbg_ctx.resolve(Indirection[:opstack, @size/8]) != 0
				fbd[pc_reg] = di.instruction.args[0]
			else
				fbd[pc_reg] = di.next_addr
			end
		else return super(di, fbd, pc_reg, dbg_ctx)
		end
	end

	def dbg_end_stepout(dbg, addr, di)
		true
	end

	def initialize_emudbg(dbg)
		stack = EncodedData.new("\x00" * 0x1000)
		stack_addr = 0x10000
		stack_addr += 0x10000 while dbg.disassembler.get_section_at(stack_addr)
		dbg.disassembler.add_section(stack, stack_addr)
		dbg.set_reg_value(:opstack, stack_addr)
	end
end
end
