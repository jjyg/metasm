#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/openrisc/opcodes'

module Metasm
class OpenRisc
	def dbg_register_pc
		@dbg_register_pc ||= :pc
	end
	def dbg_register_sp
		@dbg_register_sp ||= :r1
	end

	def dbg_register_list
		@dbg_register_list ||= (1..31).to_a.map { |i| "r#{i}".to_sym } + [:pc, :nextpc, :flag]
	end

	def dbg_flag_list
		@dbg_flag_list ||= []
	end

	def dbg_register_size
		@dbg_register_size ||= Hash.new(32)
	end

	def get_fwdemu_binding(di, pc_reg=nil, dbg_ctx=nil)
		fbd = di.backtrace_binding ||= get_backtrace_binding(di)
		fbd = fix_fwdemu_binding(di, fbd)
		if pc_reg
			if @delay_slot == 0
				n_a = Expression[pc_reg, :+, 4]
			else
				n_a = Expression[:nextpc, :+, 4]
			end
			if di.opcode.props[:setip]
				xr = get_xrefs_x(nil, di).to_a
				xr |= [n_a] if not di.opcode.props[:stopexec]
				if xr.length == 1
					if @delay_slot == 0
						fbd[pc_reg] = xr[0]
					else
						fbd[pc_reg] = Expression[:nextpc]
						fbd[:nextpc] = xr[0]
					end
				else
					dbg_resolve_pc(di, fbd, pc_reg, dbg_ctx)
				end
			else
				if @delay_slot == 0
					fbd[pc_reg] = n_a
				else
					fbd[pc_reg] = Expression[:nextpc]
					fbd[:nextpc] = n_a
				end
			end
		end
		fbd
	end

	def dbg_resolve_pc(di, fbd, pc_reg, dbg_ctx)
		a = di.instruction.args.map { |aa| symbolic(aa) }

		cond = case di.opcode.name
		when 'bf'; dbg_ctx.get_reg_value(:flag) != 0
		when 'bnf'; dbg_ctx.get_reg_value(:flag) == 0
		else return super(di, fbd, pc_reg, dbg_ctx)
		end

		if cond
			n_a = a.last
		else
			if @delay_slot == 0
				n_a = di.next_addr + 4
			else
				n_a = Expression[:nextpc, :+, 4]
			end
		end

		if @delay_slot == 0
			fbd[pc_reg] = n_a
		else
			fbd[pc_reg] = Expression[:nextpc]
			fbd[:nextpc] = n_a
		end
	end

	def dbg_enable_bp(dbg, bp)
	end

	def dbg_disable_bp(dbg, bp)
	end

	def dbg_need_stepover(dbg, addr, di)
		if @delay_slot == 0
			di.opcode.props[:saveip]
		else
			ddi = dbg.disassembler.di_at(addr-4)
			ddi and ddi.opcode.props[:saveip]
		end
	end
end
end
