#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/ebpf/opcodes'

module Metasm
class EBPF
	def dbg_register_pc
		@dbg_register_pc ||= :pc
	end
	def dbg_register_sp
		@dbg_register_sp ||= :r10
	end

	def dbg_register_list
		@dbg_register_list ||= [:r0, :r1, :r2, :r3, :r4, :r5, :r6, :r7, :r8, :r9, :r10, :pc]
	end

	def dbg_flag_list
		@dbg_flag_list ||= []
	end

	def dbg_register_size
		@dbg_register_size ||= Hash.new(64)
	end

	def dbg_need_stepover(dbg, addr, di)
		false
	end

	def dbg_resolve_pc(di, fbd, pc_reg, dbg_ctx)
		a = di.instruction.args.map { |aa| symbolic(aa) }

		cond = case di.opcode.name
		when 'jeq'; dbg_ctx.resolve(a[0]) == dbg_ctx.resolve(a[1])
		when 'jgt'; dbg_ctx.resolve(a[0]) >  dbg_ctx.resolve(a[1])
		when 'jge'; dbg_ctx.resolve(a[0]) >= dbg_ctx.resolve(a[1])
		when 'jset'; dbg_ctx.resolve(a[0]) & dbg_ctx.resolve(a[1]) > 0
		when 'jne'; dbg_ctx.resolve(a[0]) != dbg_ctx.resolve(a[1])
		when 'jsgt'; Expression.make_signed(dbg_ctx.resolve(a[0]), 64) >  Expression.make_signed(dbg_ctx.resolve(a[1]), 64)
		when 'jsge'; Expression.make_signed(dbg_ctx.resolve(a[0]), 64) >= Expression.make_signed(dbg_ctx.resolve(a[1]), 64)
		else return super(di, fbd, pc_reg, dbg_ctx)
		end

		if cond
			fbd[pc_reg] = a.last
		else
			fbd[pc_reg] = di.next_addr
		end
	end

	def dbg_enable_bp(dbg, bp)
	end

	def dbg_disable_bp(dbg, bp)
	end
end
end
