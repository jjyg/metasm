#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/webasm/opcodes'

module Metasm
class WebAsm
	def dbg_register_list
		@dbg_register_list ||= [:pc, :opstack, :mem, :local_base]
	end

	def dbg_resolve_pc(di, fbd, pc_reg, dbg_ctx)
		case di.opcode.name
		when 'br_if', 'if'
			if dbg_ctx.resolve(Indirection[:opstack, 8]) != 0
				fbd[pc_reg] = di.next_addr
			else
				fbd[pc_reg] = di.misc[:x]
			end
		else return super(di, fbd, pc_reg, dbg_ctx)
		end
	end
end
end
