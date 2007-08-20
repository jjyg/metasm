#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# 
# this exemple illustrates the use of the PTrace32 class to implement a pytstop-like functionnality
# Works on linux/x86
#

require 'metasm/os/linux'

module Metasm
class Rubstop < PTrace32
	# define accessors for registers
	%w[eax ebx ecx edx ebp esp edi esi eip orig_eax].each { |reg|
		define_method(reg) { peekusr(REGS_I386[reg.upcase]) }
		define_method(reg+'=') { |v| pokeusr(REGS_I386[reg.upcase], v) }
	}

	# read memory
	# use LinuxRemoteString for better performances - it uses /proc/pid/mem instead of ptrace(peekusr)
	def [](addr, len)
		readmem(addr, len)
	end

	# write memory
	# len ignored, uses val.length
	def []=(addr, len, val)
		writemem(addr, val)
	end
end
end

if $0 == __FILE__
	require 'metasm/preprocessor'

	# map syscall number to syscall name
	pp = Metasm::Preprocessor.new
	pp.define('__i386__')
	pp.feed '#include <asm/unistd.h>'
	pp.readtok until pp.eos?

	syscall = {}
	pp.definition.each_value { |macro|
		next if macro.name.raw !~ /__NR_(.*)/
		syscall[macro.body.first.raw.to_i] = $1.downcase
	}

	# start debugging
	rs = Metasm::Rubstop.new(ARGV.shift)

	begin
		loop do
			rs.syscall
			Process.waitpid(rs.pid)
			puts syscall[rs.orig_eax]
		end
	rescue
		rs.detach rescue nil
	end
end
