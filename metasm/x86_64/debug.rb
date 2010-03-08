#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/x86_64/opcodes'

module Metasm
class X86_64
	def dbg_register_pc
		@dbg_register_pc ||= :rip
	end
	def dbg_register_flags
		@dbg_register_flags ||= :rflags
	end

	def dbg_register_list 
		@dbg_register_list ||= [:rax, :rbx, :rcx, :rdx, :rsi, :rdi, :rbp, :rsp, :r8, :r9, :r10, :r11, :r12, :r13, :r14, :r15, :rip]
	end

	def dbg_register_size
		@dbg_register_size ||= Hash.new(64).update(:cs => 16, :ds => 16, :es => 16, :fs => 16, :gs => 16)
	end

	# what's left is inherited from Ia32
end
end
