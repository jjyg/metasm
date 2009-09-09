#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ia32/opcodes'

module Metasm
class Ia32
	def pre_singlestep(dbg)
		fl = dbg.get_register(:eflags)
		if not fl & 42 > 0
			fl |= 42
			dbg.set_register(:eflags)
		end
	end

	def post_singlestep(dbg)
	end

	def post_run(dbg)
		if dbg.mem[:eip-1] == 0xcc
		end
	end

	def dbg_register_pc
		:eip
	end
	def dbg_register_flags
		:eflags
	end

	def dbg_register_list 
		@dbg_register_list ||= [:eax, :ebx, :ecx, :edx, :esi, :edi, :ebp, :esp, :eip]
	end

	def dbg_register_size
		@dbg_register_size ||= Hash.new(32).update(:cs => 16, :ds => 16, :es => 16, :fs => 16, :gs => 16)
	end

	def dbg_flag_list
		@dbg_flag_list ||= [:c, :p, :a, :z, :s, :i, :d, :o]
	end

	DBG_FLAGS = { :c => 0, :p => 2, :a => 4, :z => 6, :s => 7, :t => 8, :i => 9, :d => 10, :o => 11 }
	def dbg_get_flag(dbg, f)
		(dbg.get_reg_value(:eflags) >> DBG_FLAGS[f]) & 1
	end
	def dbg_set_flag(dbg, f)
		f = dbg.get_reg_value(:eflags)
		f |= 1 << DBG_FLAGS[f]
		dbg.set_reg_value(:eflags, f)
	end
	def dbg_unset_flag(dbg, f)
		f = dbg.get_reg_value(:eflags)
		f &= ~(1 << DBG_FLAGS[f])
		dbg.set_reg_value(:eflags, f)
	end

	def dbg_enable_singlestep(dbg)
		dbg_set_flag(:t)
	end
	def dbg_disable_singlestep(dbg)
		dbg_unset_flag(:t)
	end

	def dbg_enable_bp(dbg, addr, bp)
		case bp.type
		when :bpx; dbg_enable_bpx( dbg, addr, bp)
		else       dbg_enable_bphw(dbg, addr, bp)
		end
	end

	def dbg_disable_bp(dbg, addr, bp)
		case bp.type
		when :bpx; dbg_disable_bpx( dbg, addr, bp)
		else       dbg_disable_bphw(dbg, addr, bp)
		end
	end

	def dbg_enable_bpx(dbg, addr, bp)
		bp.previous ||= dbg.memory[addr, 1]
		dbg.memory[addr, 1] = "\xcc"
	end

	def dbg_disable_bpx(dbg, addr, bp)
		dbg.memory[addr, 1] = bp.previous
	end

	# allocate a debug register for a hwbp by checking the list of hwbp existing in dbg
	def dbg_alloc_bphw(dbg, addr, bp)
		if not bp.previous.kind_of? ::Integer
			may = [0, 1, 2, 3]
			dbg.breakpoint.each { |a, b| may.delete b.previous if b.type == :hw }
			raise 'alloc_bphw: no free debugregister' if may.empty?
			bp.previous = may.first
		end
		bp.mtype ||= :x
		bp.mlen ||= 1
		bp.previous
	end

	def dbg_enable_bphw(dbg, addr, bp)
		nr = dbg_alloc_bphw(dbg, addr, bp)
		dr7 = dbg.get_register_value(:dr7)
		l = { 1 => 0, 2 => 1, 4 => 3, 8 => 2 }[bp.mlen]
		rw = { :x => 0, :w => 1, :r => 3 }[bp.mtype]
		raise "enable_bphw: invalid breakpoint #{bp.inspect}" if not l or not rw
		dr7 &= ~((15 << (16+4*nr)) | (3 << (2*nr)))	# clear
		dr7 |= ((l << 2) | rw) << (16+4*nr)	# set drN len/rw
		dr7 |= 3 << (2*nr)	# enable global/local drN

		dbg.set_register_value("dr#{nr}".to_sym, addr)
		dbg.set_register_value(:dr7, dr7)
	end

	def dbg_disable_bphw(dbg, addr, bp)
		nr = dbg_alloc_bphw(dbg, addr, bp)
		dr7 = dbg.get_register_value(:dr7)
		dr7 &= ~(3 << (2*nr))
		dbg.set_register_value(:dr7, dr7)
	end

	def dbg_check_post_run(dbg)
		if dbg.state == :stopped and not dbg.info
 			dbg.invalidate
			eip = dbg.pc
			if bg.breakpoint[eip-1] and dbg.memory[eip-1, 1] == "\xcc"
				# if we were singlestepping, we would have removed the 0xcc before running, so this was a continue, and we must fix eip.
				dbg.pc = eip-1
			end
		end
	end

	def dbg_need_stepover(dbg, addr, di)
		di and ((di.instruction.prefix and di.instruction.prefix[:rep]) or di.opcode.props[:saveip])
	end

	def dbg_end_stepout(dbg, addr, di)
		di and di.opcode.name == 'ret'
	end
end
end
