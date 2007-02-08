#!/usr/bin/ruby

class PTrace
	def do_things
		eip = peekusr(EIP)
		return unless eip & 0xf000_0000 == 0
		code = readmem(eip, 8)
		puts '%08x ' % eip + code.unpack('C*').map { |e| '\\x%02x' % e }.join
	end

	# target: pid (numeric) or path (string)
	def initialize(target)
		@buf = 'xxxx'
		@bufptr = [@buf].pack('P').unpack('l').first
		begin
			@pid = Integer(target)
			attach
		rescue
			if not @pid = fork
				traceme
				exec target
			end
			puts "attached #@pid"
		end
	end

	def bufval
		@buf.unpack('l').first
	end

	def main_loop
		count = 0
		until @loop_stop
			count += 1
			Process.waitpid(@pid, 0)
			if $?.stopped? and $?.stopsig == 5	# sigtrap
				do_things
				singlestep
			elsif $?.stopped?
				puts "stopped by sig #{$?.stopsig}"
				dump_now = true
				singlestep #$?.stopsig
			elsif $?.signaled?
				puts "exited by signal #{$?.termsig}"
				break
			elsif $?.exited?
				puts "exited with status #{$?.exitstatus}"
				break
			end
		end
		puts "#{count} instructions executed"
	end

	def readmem(off, len)
		decal = off & 3
		buf = ''
		if decal > 0
			off -= decal
			peekdata(off)
			off += 4
			buf << @buf[decal..3]
		end
		offend = off + len - 3
		while off < offend
			peekdata(off)
			buf << @buf[0, 4]
			off += 4
		end
		buf[0, len]
	end

# i486-asm/ptrace.h
EBX = 0
ECX = 1
EDX = 2
ESI = 3
EDI = 4
EBP = 5
EAX = 6
DS  = 7
ES  = 8
FS  = 9
GS  = 10
ORIG_EAX = 11
EIP = 12
CS  = 13
EFL = 14
UESP= 15
SS  = 16
FRAME_SIZE = 17

# this struct defines the way the registers are stored on the stack during a system call.
#struct pt_regs {
#        long ebx; long ecx; long edx; long esi;
#        long edi; long ebp; long eax; int  xds;
#        int  xes; long orig_eax; long eip; int  xcs;
#        long eflags; long esp; int  xss;
#};

# Arbitrarily choose the same ptrace numbers as used by the Sparc code.
GETREGS         =  12
SETREGS         =  13
GETFPREGS       =  14
SETFPREGS       =  15
GETFPXREGS      =  18
SETFPXREGS      =  19

OLDSETOPTIONS   =  21

GET_THREAD_AREA =  25
SET_THREAD_AREA =  26

SYSEMU           = 31
SYSEMU_SINGLESTEP= 32


# linux/ptrace.h
# structs and defines to help the user use the ptrace system call.
TRACEME         =   0
PEEKTEXT        =   1
PEEKDATA        =   2
PEEKUSR         =   3
POKETEXT        =   4
POKEDATA        =   5
POKEUSR         =   6
CONT            =   7
KILL            =   8
SINGLESTEP      =   9

ATTACH          =0x10
DETACH          =0x11

SYSCALL         =  24
	
	def ptrace(req, pid, addr, data)
		Kernel.syscall(26, req, pid, addr, data)
	end

	def traceme
		ptrace(TRACEME,  0, 0, 0)
	end

	def peektext(addr)
		ptrace(PEEKTEXT, @pid, addr, 0)
	end

	def peekdata(addr)
		ptrace(PEEKDATA, @pid, addr, @bufptr)
	end

	def peekusr(addr)
		ptrace(PEEKUSR,  @pid, 4*addr, @bufptr)
		bufval
	end

	def poketext(addr, data)
		ptrace(POKETEXT, @pid, addr, data)
	end

	def pokedata(addr, data)
		ptrace(POKEDATA, @pid, addr, data)
	end

	def pokeusr(addr, data)
		ptrace(POKEUSR,  @pid, 4*addr, data)
	end

	def cont(sig = 0)
		ptrace(CONT, @pid, 0, sig)
	end

	def kill
		ptrace(KILL, @pid, 0, 0)
	end

	def singlestep(sig = 0)
		ptrace(SINGLESTEP, @pid, 0, sig)
	end

	def syscall
		ptrace(SYSCALL, @pid, 0, 0)
	end

	def attach
		@loop_stop = false
		ptrace(ATTACH, @pid, 0, 0)
	end

	def detach
		@loop_stop = true
		ptrace(DETACH, @pid, 0, 0)
	end


# 0x4200-0x4300 are reserved for architecture-independent additions.
SETOPTIONS      =0x4200
GETEVENTMSG     =0x4201
GETSIGINFO      =0x4202
SETSIGINFO      =0x4203

# options set using PTRACE_SETOPTIONS
O_TRACESYSGOOD  =0x00000001
O_TRACEFORK     =0x00000002
O_TRACEVFORK    =0x00000004
O_TRACECLONE    =0x00000008
O_TRACEEXEC     =0x00000010
O_TRACEVFORKDONE=0x00000020
O_TRACEEXIT     =0x00000040

O_MASK          =0x0000007f

# Wait extended result codes for the above trace options.
EVENT_FORK      =1
EVENT_VFORK     =2
EVENT_CLONE     =3
EVENT_EXEC      =4
EVENT_VFORK_DONE=5
EVENT_EXIT      =6
end

if __FILE__ == $0
	PTrace.new(ARGV.shift).main_loop
end
