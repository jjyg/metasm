#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# 
# this exemple illustrates the use of the PTrace32 class to implement a pytstop-like functionnality
# Works on linux/x86
#

require 'metasm'

module Metasm
class Rubstop < PTrace32
	# define accessors for registers
	%w[eax ebx ecx edx ebp esp edi esi eip orig_eax].each { |reg|
		define_method(reg) { peekusr(REGS_I386[reg.upcase]) }
		define_method(reg+'=') { |v| pokeusr(REGS_I386[reg.upcase], v) }
	}

	def cont(*a)
		super
		::Process.waitpid(@pid)
	end
	def singlestep(*a)
		super
		::Process.waitpid(@pid)
	end
	def syscall(*a)
		super
		::Process.waitpid(@pid)
	end

	def initialize(*a)
		super
		@pgm = ExeFormat.new Ia32.new
		@pgm.encoded = EncodedData.new LinuxRemoteString.new(@pid)
		@pgm.encoded.data.ptrace = self
	end

	def mnemonic(addr = eip)
		@pgm.encoded.ptr = addr
		@pgm.cpu.decode_instruction(@pgm, @pgm.encoded, addr).instruction
	end

	def regs
		[%w[eax ebx ecx edx orig_eax], %w[ebp esp edi esi eip]].map { |l|
			l.map { |reg| "#{reg}=#{'%08x' % (send(reg)&0xffff_ffff)}" }.join(' ')
		}.join("\n")
	end

	def [](addr, len)
		@pgm.encoded.data[addr, len]
	end
	def []=(addr, len, str)
		@pgm.encoded.data[addr, len] = str
	end
end
end

if $0 == __FILE__

	# map syscall number to syscall name
	pp = Metasm::Preprocessor.new
	pp.define('__i386__')
	pp.feed '#include <asm/unistd.h>'
	pp.readtok until pp.eos?

	syscall_map = {}
	pp.definition.each_value { |macro|
		next if macro.name.raw !~ /__NR_(.*)/
		syscall_map[macro.body.first.raw.to_i] = $1.downcase
	}

	# start debugging
	rs = Metasm::Rubstop.new(ARGV.shift)

	begin
		while $?.stopped? and $?.stopsig == Signal.list['TRAP']
			if $VERBOSE
				rs.singlestep
				puts "#{'%08x' % (rs.eip & 0xffffffff)} #{rs.mnemonic}"
			else
				rs.syscall ; rs.syscall	# wait return of syscall
				puts syscall_map[rs.orig_eax]
			end
		end
		p $?
		puts rs.regs
	rescue Interrupt
		rs.detach rescue nil
		puts 'interrupted!'
	rescue Errno::ESRCH
	end
end
