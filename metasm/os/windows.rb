#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/os/main'
begin
require 'Win32API' if RUBY_PLATFORM =~ /mswin|mingw/i
rescue LoadError
end

module Metasm
module WinAPI
class << self
	def last_error_msg
		message = ' '*512
		errno = getlasterror
		if formatmessage(FORMAT_MESSAGE_FROM_SYSTEM, nil, errno, 0, message, message.length, nil) == 0
			message = 'unknown error %x' % errno
		else
			message = message[0, message.index(?\0)] if message.index(?\0)
			message.chomp!
		end
		message
	end

	def new_api(lib, name, args, zero_is_err = true)
		args = args.delete(' ').split(//)
		retval = args.pop
		begin
			const_set(name, Win32API.new(lib, name, args, retval))
		rescue
			puts "no export #{name} found in #{lib}" if $VERBOSE
 			return
		end
		# booh this is fugly
		class << self ; self ; end.send(:define_method, name.downcase) { |*a|
			r = const_get(name).call(*a)
			if r == 0 and zero_is_err
				puts "WinAPI: Error in #{name}: #{last_error_msg}" if $VERBOSE and (not zero_is_err.kind_of?(Proc) or zero_is_err[])
				nil
			else
				r
			end
		}
	end
end	# class << self

	if defined? Win32API
	new_api 'kernel32', 'CloseHandle', 'I I'
	new_api 'kernel32', 'ContinueDebugEvent', 'III I'
	new_api 'kernel32', 'CreateProcessA', 'PPPPIIPPPP I'
	new_api 'kernel32', 'CreateRemoteThread', 'IPIIIIP I'
	new_api 'kernel32', 'DebugActiveProcess', 'I I'
	new_api 'kernel32', 'DebugBreakProcess', 'I I'
	new_api 'kernel32', 'DebugSetProcessKillOnExit', 'I I'
	new_api 'kernel32', 'FormatMessage', 'IPIIPIP I', false
	new_api 'kernel32', 'GetCurrentProcess', 'I'
	new_api 'kernel32', 'GetThreadContext', 'IP I'
	new_api 'kernel32', 'GetLastError', 'I', false
	new_api 'kernel32', 'GetProcessId', 'I I'
	new_api 'kernel32', 'OpenProcess', 'III I'
	new_api 'kernel32', 'ReadProcessMemory', 'IIPIP I', lambda { getlasterror != ERROR_PARTIAL_COPY }
	new_api 'kernel32', 'ResumeThread', 'I I', false
	new_api 'kernel32', 'SetThreadContext', 'IP I'
	new_api 'kernel32', 'SuspendThread', 'I I', false
	new_api 'kernel32', 'TerminateProcess', 'II I'
	new_api 'kernel32', 'VirtualAllocEx', 'IIIII I'
	new_api 'kernel32', 'WaitForDebugEvent', 'PI I', lambda { getlasterror != ERROR_SEM_TIMEOUT }
	new_api 'kernel32', 'WriteProcessMemory', 'IIPIP I'
	new_api 'advapi32', 'OpenProcessToken', 'IIP I'
	new_api 'advapi32', 'LookupPrivilegeValueA', 'PPP I'
	new_api 'advapi32', 'AdjustTokenPrivileges', 'IIPIPP I'
	new_api 'psapi', 'EnumProcesses', 'PIP I'
	new_api 'psapi', 'EnumProcessModules', 'IPIP I'
	new_api 'psapi', 'GetModuleFileNameEx', 'IIPI I'
	new_api 'user32', 'PostMessageA', 'IIII I'
	new_api 'user32', 'MessageBoxA', 'IPPI I'
	end

	CONTEXT_i386 = 0x00010000
	CONTEXT86_CONTROL  = (CONTEXT_i386 | 0x0001) # SS:ESP, CS:EIP, FLAGS, EBP */
	CONTEXT86_INTEGER  = (CONTEXT_i386 | 0x0002) # EAX, EBX, ECX, EDX, ESI, EDI */
	CONTEXT86_SEGMENTS = (CONTEXT_i386 | 0x0004) # DS, ES, FS, GS */
	CONTEXT86_FLOATING_POINT  = (CONTEXT_i386 | 0x0008) # 387 state */
	CONTEXT86_DEBUG_REGISTERS = (CONTEXT_i386 | 0x0010) # DB 0-3,6,7 */
	CONTEXT86_FULL = (CONTEXT86_CONTROL | CONTEXT86_INTEGER | CONTEXT86_SEGMENTS)
	CREATE_PROCESS_DEBUG_EVENT = 3
	CREATE_THREAD_DEBUG_EVENT = 2
	DBG_CONTINUE = 0x00010002
	DBG_EXCEPTION_NOT_HANDLED = 0x80010001
	DEBUG_PROCESS = 0x00000001
	DEBUG_ONLY_THIS_PROCESS = 0x00000002
	CREATE_SUSPENDED = 0x00000004
	ERROR_SEM_TIMEOUT = 121
	ERROR_PARTIAL_COPY = 299
	EXCEPTION_DEBUG_EVENT = 1
	EXIT_PROCESS_DEBUG_EVENT = 5
	EXIT_THREAD_DEBUG_EVENT = 4
	FORMAT_MESSAGE_FROM_SYSTEM = 0x1000
	INFINITE = 0xffffffff
	LOAD_DLL_DEBUG_EVENT = 6
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	OUTPUT_DEBUG_STRING_EVENT = 8
	PAGE_READONLY = 0x02
	PAGE_EXECUTE_READWRITE = 0x40
	PROCESS_ALL_ACCESS = 0x1F0FFF
	PROCESS_QUERY_INFORMATION = 0x400
	PROCESS_VM_READ = 0x10
	PROCESS_VM_WRITE = 0x20
	RIP_EVENT = 9
	SE_DEBUG_NAME = 'SeDebugPrivilege'
	SE_PRIVILEGE_ENABLED = 0x2
	STATUS_ACCESS_VIOLATION = 0xC0000005
	STATUS_BREAKPOINT = 0x80000003
	STATUS_GUARD_PAGE_VIOLATION = 0x80000001
	STATUS_SINGLE_STEP = 0x80000004
	TOKEN_ADJUST_PRIVILEGES = 0x20
	TOKEN_QUERY = 0x8
	UNLOAD_DLL_DEBUG_EVENT = 7
end

class WinOS < OS
	class Process < OS::Process
		# on-demand cached openprocess(ALL_ACCESS) handle
		def handle
			@handle ||= WinAPI.openprocess(WinAPI::PROCESS_ALL_ACCESS, 0, @pid)
		end
		def handle=(h) @handle = h end
		def memory
			@memory ||= WindowsRemoteString.new(handle)
		end
		def memory=(m) @memory = m end
		def debugger
			@debugger ||= WinDebugger.new(@pid)
		end
		def debugger=(d) @debugger = d end
		def addrsz; 32 ; end
	end

class << self
	# try to enable debug privilege in current process
	def get_debug_privilege
		htok = [0].pack('L')
		return if not WinAPI.openprocesstoken(WinAPI.getcurrentprocess(), WinAPI::TOKEN_ADJUST_PRIVILEGES | WinAPI::TOKEN_QUERY, htok)
		luid = [0, 0].pack('LL')
		return if not WinAPI.lookupprivilegevaluea(nil, WinAPI::SE_DEBUG_NAME, luid)

		# priv.PrivilegeCount = 1;
		# priv.Privileges[0].Luid = luid;
		# priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		priv = luid.unpack('LL').unshift(1).push(WinAPI::SE_PRIVILEGE_ENABLED).pack('LLLL')
		return if not WinAPI.adjusttokenprivileges(htok.unpack('L').first, 0, priv, 0, nil, nil)

		true
	end

	# returns an array of Processes, with pid/module listing
	def list_processes
		tab = ' '*4096
		int = [0].pack('L')
		return if not WinAPI.enumprocesses(tab, tab.length, int)
		pids = tab[0, int.unpack('L').first].unpack('L*')
		begin
		 # temporarily hide errors from openprocess(system_process) when VERBOSE
		 oldverb, $VERBOSE = $VERBOSE, false

		 pids.map { |pid|
			pr = Process.new
			pr.pid = pid
			if handle = WinAPI.openprocess(WinAPI::PROCESS_QUERY_INFORMATION | WinAPI::PROCESS_VM_READ, 0, pid)
				mods = ' '*4096
				ret = [0].pack('L')
				if WinAPI.enumprocessmodules(handle, mods, mods.length, ret)
					pr.modules = []
					mods[0, ret.unpack('L').first].unpack('L*').each { |mod|
						path = ' ' * 512
						m = Process::Module.new
						m.addr = mod
						len = WinAPI.getmodulefilenameex(handle, mod, path, path.length)
						m.path = path[0, len]
						pr.modules << m
					}
				end
				WinAPI.closehandle(handle)
			end
			pr
		 }
		ensure
			$VERBOSE = oldverb
		end
	end

	def create_debugger(path)
		WinDebugger.new(path)
	end

	# Injects a shellcode into the memory space of targetproc
	# target is a WinOS::Process
	# shellcode may be a String (raw shellcode) or an EncodedData
	# With an EncodedData, unresolved relocations are solved using
	# exports of modules from the target address space ; also the
	# shellcode need not be position-independant.
	def inject_shellcode(target, shellcode)
		raise 'cannot open target memory' if not remote_mem = target.memory
		return if not injectaddr = WinAPI.virtualallocex(target.handle, 0, shellcode.length,
				WinAPI::MEM_COMMIT | WinAPI::MEM_RESERVE, WinAPI::PAGE_EXECUTE_READWRITE)
		puts 'remote buffer at %x' % injectaddr if $VERBOSE

		if shellcode.kind_of? EncodedData
			fixup_shellcode_relocs(shellcode, target, remote_mem)
			shellcode.fixup! shellcode.binding(injectaddr)
			r = shellcode.reloc.values.map { |r_| r_.target }
			raise "unresolved shellcode relocs #{r.join(', ')}" if not r.empty?
			shellcode = shellcode.data
		end

		# inject the shellcode
		remote_mem[injectaddr, shellcode.length] = shellcode

		injectaddr
	end

	def fixup_shellcode_relocs(shellcode, target, remote_mem)
		ext = shellcode.reloc_externals
		binding = {}
		while e = ext.pop
			next if binding[e]
			next if not lib = WindowsExports::EXPORT[e]	# XXX could scan all exports... LoadLibrary ftw
			next if not m = target.modules.find { |m_| m_.path.downcase.include? lib.downcase }
			lib = LoadedPE.load(remote_mem[m.addr, 0x1000_0000])
			lib.decode_header
			lib.decode_exports
			lib.export.exports.each { |e_|
				next if not e_.name or not e_.target
				binding[e_.name] = m.addr + lib.label_rva(e_.target)
			}
			shellcode.fixup! binding
		end
	end

	def createthread(target, startaddr)
		WinAPI.createremotethread(target.handle, 0, 0, startaddr, 0, 0, 0)
	end

	# calls inject_shellcode and createthread
	def inject_run_shellcode(target, shellcode)
		raise "failed to inject shellcode" if not addr = inject_shellcode(target, shellcode)
		createthread(target, addr)
	end

	def open_process_handle(h)
		find_process(WinAPI.getprocessid(h))	# booh
	end
end	# class << self
end

class WindowsRemoteString < VirtualString
	def self.open_pid(pid, access = nil)
		if access
			handle = WinAPI.openprocess(access, 0, pid)
		else
			handle = WinAPI.openprocess(WinAPI::PROCESS_ALL_ACCESS, 0, pid)
			if not handle
				puts "cannot openprocess ALL_ACCESS pid #{pid}, try ro" if $VERBOSE
				handle = WinAPI.openprocess(WinAPI::PROCESS_VM_READ, 0, pid)
			end
		end
		raise "OpenProcess(#{pid}): #{WinAPI.last_error_msg}" if not handle

		new(handle)
	end

	attr_accessor :handle

	# returns a virtual string proxying the specified process memory range
	# reads are cached (4096 aligned bytes read at once)
	# writes are done directly (if handle has appropriate privileges)
	def initialize(handle, addr_start=0, length=nil)
		@handle = handle
		length ||= 1 << (WinOS.open_process_handle(@handle).addrsz rescue 32)
		super(addr_start, length)
	end

	def dup(addr = @addr_start, len = @length)
		self.class.new(@handle, addr, len)
	end

	def rewrite_at(addr, data)
		WinAPI.writeprocessmemory(@handle, addr, data, data.length, nil)
	end

	def get_page(addr, len=@pagelength)
		page = 0.chr*len
		page.force_encoding('binary') if page.respond_to? :force_encoding
		return if not WinAPI.readprocessmemory(@handle, addr, page, len, 0)
		page
	end

	def realstring
		s = 0.chr * @length
		s.force_encoding('binary') if s.respond_to? :force_encoding
		WinAPI.readprocessmemory(@handle, @addr_start, s, @length, 0)
		s
	end
end

class WinDbgAPI
	# pid => VirtualString
	attr_accessor :mem
	# pid => handle
	attr_accessor :hprocess
	# pid => (tid => handle)
	attr_accessor :hthread

	# creates a new debugger for target (a PID or an exe filename)
	def initialize(target, debug_children = false)
		@mem = {}
		@hprocess = {}
		@hthread = {}
		begin
			pid = Integer(target)
			WinAPI.debugactiveprocess(pid)
			WinAPI.debugsetprocesskillonexit(0) rescue nil
			@mem[pid] = WindowsRemoteString.open_pid(pid)
		rescue ArgumentError
			# *(int*)&startupinfo = sizeof(startupinfo);
			startupinfo = [17*[0].pack('L').length, *([0]*16)].pack('L*')
			processinfo = [0, 0, 0, 0].pack('L*')
			flags = WinAPI::DEBUG_PROCESS
			flags |= WinAPI::DEBUG_ONLY_THIS_PROCESS if not debug_children
			target = target.dup if target.frozen?
			raise "CreateProcess: #{WinAPI.last_error_msg}" if not h = WinAPI.createprocessa(nil, target, nil, nil, 0, flags, nil, nil, startupinfo, processinfo)
			hprocess, hthread, pid, tid = processinfo.unpack('LLLL')
			WinAPI.closehandle(hthread)
			@mem[pid] = WindowsRemoteString.new(hprocess) # need @mem not empty (terminate condition of debugloop)
		end
	end

	# thread context (register values)
	class Context
		OFFSETS = {}
		OFFSETS[:ctxflags] = 0
		%w[dr0 dr1 dr2 dr3 dr6 dr7].each { |reg| OFFSETS[reg.to_sym] = OFFSETS.values.max + 4 }
		OFFSETS[:fpctrl] = OFFSETS.values.max + 4
		OFFSETS[:fpstatus] = OFFSETS.values.max + 4
		OFFSETS[:fptag] = OFFSETS.values.max + 4
		OFFSETS[:fperroffset] = OFFSETS.values.max + 4
		OFFSETS[:fperrselect] = OFFSETS.values.max + 4
		OFFSETS[:fpdataoffset] = OFFSETS.values.max + 4
		OFFSETS[:fpdataselect] = OFFSETS.values.max + 4
		OFFSETS[:fpregs] = OFFSETS.values.max + 4
		OFFSETS[:fpcr0] = OFFSETS.values.max + 80
		%w[gs fs es ds edi esi ebx edx ecx eax ebp eip cs eflags esp ss].each { |reg|
			OFFSETS[reg.to_sym] = OFFSETS.values.max + 4
		}

		attr_accessor :hthread, :ctx
		# retrieves the thread context
		def initialize(hthread, flags)
			@hthread = hthread
			@ctx = 0.chr * (OFFSETS.values.max + 4 + 512)
			@flags = flags
			update
		end

		def update(flags=@flags)
			set_val(:ctxflags, flags)
			WinAPI.getthreadcontext(@hthread, @ctx)
		end

		# returns the value of an unsigned int register
		def [](reg)
			raise "invalid register #{reg.inspect}" if not o = OFFSETS[reg]
			@ctx[o, 4].unpack('L').first
		end

		# updates the value of an unsigned int register
		def []=(reg, value)
			set_val(reg, value)
			commit
		end

		# updates the local copy of the context, do not commit
		def set_val(reg, value)
			raise "invalid register #{reg.inspect}" if not o = OFFSETS[reg]
			@ctx[o, 4] = [value].pack('L')
		end

		# updates the thread registers from the local copy
		def commit
			WinAPI.setthreadcontext(@hthread, @ctx)
		end

		def to_hash
			h = {}
			OFFSETS.each_key { |k| h[k] = self[k] }
			h
		end
	end

	# returns the specified thread context
	def get_context(pid, tid, flags = WinAPI::CONTEXT86_FULL | WinAPI::CONTEXT86_DEBUG_REGISTERS)
		Context.new(@hthread[pid][tid], flags)
	end

	# classes for debug informations
	class ExceptionInfo
		attr_accessor :code, :flags, :recordptr, :addr, :nparam, :info, :firstchance
		def initialize(str)
			@code, @flags, @recordptr, @addr, @nparam, @info, @firstchance = str.unpack('LLLLLC60L')
		end
	end
	class CreateThreadInfo
		attr_accessor :hthread, :threadlocalbase, :startaddr
		def initialize(str)
			@hthread, @threadlocalbase, @startaddr = str.unpack('LLL')
		end
	end
	class CreateProcessInfo
		attr_accessor :hfile, :hprocess, :hthread, :imagebase, :debugfileoff, :debugfilesize, :threadlocalbase, :startaddr, :imagename, :unicode
		def initialize(str)
			@hfile, @hprocess, @hthread, @imagebase, @debugfileoff, @debugfilesize, @threadlocalbase,
				@startaddr, @imagename, @unicode = str.unpack('LLLLLLLLLS')
		end
	end
	class ExitThreadInfo
		attr_accessor :exitcode
		def initialize(str)
			@exitcode = *str.unpack('L')
		end
	end
	class ExitProcessInfo
		attr_accessor :exitcode
		def initialize(str)
			@exitcode = *str.unpack('L')
		end
	end
	class LoadDllInfo
		attr_accessor :hfile, :imagebase, :debugfileoff, :debugfilesize, :imagename, :unicode
		def initialize(str)
			@hfile, @imagebase, @debugfileoff, @debugfilesize, @imagename, @unicode = str.unpack('LLLLLS')
		end
	end
	class UnloadDllInfo
		attr_accessor :imagebase
		def initialize(str)
			@imagebase = *str.unpack('L')
		end
	end
	class OutputDebugStringInfo
		attr_accessor :ptr, :unicode, :length
		def initialize(str)
			@ptr, @unicode, @length = str.unpack('LSS')
		end
	end
	class RipInfo
		attr_accessor :error, :type
		def initialize(str)
			@error, @type = str.unpack('LL')
		end
	end

	# returns a string suitable for use as a debugevent structure
	def debugevent_alloc
		# on wxpsp2, debugevent is at most 24*uint
		[0].pack('L')*30
	end

	# waits for debug events
	# dispatches to the different handler_*
	# custom handlers should call the default version (especially for newprocess/newthread/endprocess/endthread)
	# if given a block, yields { |pid, tid, code, rawinfo| }
	# if the block returns something not numeric, dispatch_debugevent is called
	def loop
		raw = debugevent_alloc
		while not @mem.empty?
			return if not ev = waitfordebugevent(raw)
			ret = nil
			ret = yield(*ev) if block_given?
			ret = dispatch_debugevent(*ev) if not ret.kind_of? ::Integer
			ret = WinAPI::DBG_CONTINUE if not ret.kind_of? ::Integer
			continuedebugevent(ev[0], ev[1], ret)
		end
	end

	# waits for a debug event (will put the current [debugger] process to sleep)
	# returns [pid, tid, eventcode, eventdata] or nil
	def waitfordebugevent(raw = debugevent_alloc, timeout = WinAPI::INFINITE)
		if WinAPI.waitfordebugevent(raw, timeout)
			code, pid, tid, info = raw.unpack('LLLa*')
			info = decode_info(code, info)
			predispatch_debugevent(pid, tid, code, info)
			[pid, tid, code, info]
		end
	end

	# tells the target pid:tid to resume
	def continuedebugevent(pid, tid, cont=WinAPI::DBG_CONTINUE)
		WinAPI.continuedebugevent(pid, tid, cont)
	end

	# casts a raw info to the corresponding object according to code
	def decode_info(code, info)
		c = {
			WinAPI::EXCEPTION_DEBUG_EVENT => ExceptionInfo,
			WinAPI::CREATE_PROCESS_DEBUG_EVENT => CreateProcessInfo,
			WinAPI::CREATE_THREAD_DEBUG_EVENT => CreateThreadInfo,
			WinAPI::EXIT_PROCESS_DEBUG_EVENT => ExitProcessInfo,
			WinAPI::EXIT_THREAD_DEBUG_EVENT => ExitThreadInfo,
			WinAPI::LOAD_DLL_DEBUG_EVENT => LoadDllInfo,
			WinAPI::UNLOAD_DLL_DEBUG_EVENT => UnloadDllInfo,
			WinAPI::OUTPUT_DEBUG_STRING_EVENT => OutputDebugStringInfo,
			WinAPI::RIP_EVENT => RipInfo,
		}[code]
		c ? c.new(info) : info
	end

	# update this object internal state from debug events (new thread/process)
	def predispatch_debugevent(pid, tid, code, info)
		case code
		when WinAPI::CREATE_PROCESS_DEBUG_EVENT; prehandler_newprocess pid, tid, info
		when WinAPI::CREATE_THREAD_DEBUG_EVENT;  prehandler_newthread  pid, tid, info
		# can't prehandle_endprocess/thread, the handler runs after us and may need the handles
		end
	end

	# handles one debug event
	# calls the corresponding handler
	# returns the handler return value
	def dispatch_debugevent(pid, tid, code, info)
		case code
		when WinAPI::EXCEPTION_DEBUG_EVENT;      handler_exception   pid, tid, info
		when WinAPI::CREATE_PROCESS_DEBUG_EVENT; handler_newprocess  pid, tid, info
		when WinAPI::CREATE_THREAD_DEBUG_EVENT;  handler_newthread   pid, tid, info
		when WinAPI::EXIT_PROCESS_DEBUG_EVENT;   handler_endprocess  pid, tid, info
		when WinAPI::EXIT_THREAD_DEBUG_EVENT;    handler_endthread   pid, tid, info
		when WinAPI::LOAD_DLL_DEBUG_EVENT;       handler_loaddll     pid, tid, info
		when WinAPI::UNLOAD_DLL_DEBUG_EVENT;     handler_unloaddll   pid, tid, info
		when WinAPI::OUTPUT_DEBUG_STRING_EVENT;  handler_debugstring pid, tid, info
		when WinAPI::RIP_EVENT;                  handler_rip         pid, tid, info
		else                                     handler_unknown     pid, tid, code, info
		end
	end

	def handler_exception(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} exception" if $DEBUG
		case info.code
		when WinAPI::STATUS_ACCESS_VIOLATION
			# fix fs bug in xpsp1
			ctx = get_context(pid, tid)
			if ctx[:fs] != 0x3b
				puts "wdbg: #{pid}:#{tid} fix fs bug" if $DEBUG
				ctx[:fs] = 0x3b
				return WinAPI::DBG_CONTINUE
			end
			WinAPI::DBG_EXCEPTION_NOT_HANDLED
		when WinAPI::STATUS_BREAKPOINT
			# we must ack ntdll interrupts on process start
			# but we should not mask process-generated exceptions by default..
			WinAPI::DBG_CONTINUE
		when WinAPI::STATUS_SINGLE_STEP
			WinAPI::DBG_CONTINUE
		else
			WinAPI::DBG_EXCEPTION_NOT_HANDLED
		end
	end

	def prehandler_newprocess(pid, tid, info)
		@mem[pid] ||= WindowsRemoteString.new(info.hprocess)
		@hprocess[pid] = info.hprocess
		prehandler_newthread(pid, tid, info)
	end

	def prehandler_newthread(pid, tid, info)
		@hthread[pid] ||= {}
		@hthread[pid][tid] = info.hthread
	end

	def prehandler_endthread(pid, tid, info)
		@hthread[pid].delete tid
	end

	def prehandler_endprocess(pid, tid, info)
		@hprocess.delete pid
		@hthread.delete pid
		@mem.delete pid
	end

	def handler_newprocess(pid, tid, info)
		str = read_str_indirect(pid, info.imagename, info.unicode)
		puts "wdbg: #{pid}:#{tid} new process #{str.inspect} at #{'0x%08X' % info.imagebase}" if $DEBUG
		handler_newthread(pid, tid, info)
		WinAPI::DBG_CONTINUE
	end

	def handler_newthread(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} new thread at #{'0x%08X' % info.startaddr}" if $DEBUG
		WinAPI::DBG_CONTINUE
	end

	def handler_endprocess(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} process died" if $DEBUG
		prehandler_endprocess(pid, tid, info)
		WinAPI::DBG_CONTINUE
	end

	def handler_endthread(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} thread died" if $DEBUG
		prehandler_endthread(pid, tid, info)
		WinAPI::DBG_CONTINUE
	end

	def handler_loaddll(pid, tid, info)
		if $DEBUG
			dll = LoadedPE.load(@mem[pid][info.imagebase, 0x1000_0000])
			dll.decode_header
			dll.decode_exports
			str = (dll.export ? dll.export.libname : read_str_indirect(pid, info.imagename, info.unicode))
			puts "wdbg: #{pid}:#{tid} loaddll #{str.inspect} at #{'0x%08X' % info.imagebase}"
		end
		WinAPI.closehandle(info.hfile)
		WinAPI::DBG_CONTINUE
	end

	def handler_unloaddll(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} unloaddll #{'0x%08X' % info.imagebase}" if $DEBUG
		WinAPI::DBG_CONTINUE
	end

	def handler_debugstring(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} debugstring #{read_str_indirect(pid, info.ptr, info.unicode)}" if $VERBOSE
		WinAPI::DBG_CONTINUE
	end

	def handler_rip(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} rip" if $VERBOSE
		WinAPI::DBG_CONTINUE
	end

	def handler_unknown(pid, tid, code, raw)
		puts "wdbg: #{pid}:#{tid} unknown debugevent #{'0x%X' % code} #{raw.inspect}" if $VERBOSE
		WinAPI::DBG_CONTINUE
	end

	# reads a null-terminated string from a pointer in the remote address space
	def read_str_indirect(pid, ptr, unicode=0)
		return '' if not ptr or ptr == 0
		ptr = @mem[pid][ptr, 4].unpack('L').first
		str = @mem[pid][ptr, 512]
		str = str.unpack('S*').pack('C*') if unicode != 0
		str = str[0, str.index(?\0)] if str.index(?\0)
		str
	end

	def break(pid)
		WinAPI.debugbreakprocess(@hprocess[pid])
	end


	attr_accessor :logger
	def puts(*s)
		@logger ||= $stdout
		@logger.puts(*s)
	end
end

# this class implements a high-level API over the Windows debugging primitives
class WinDebugger < Debugger
	attr_accessor :dbg
	def initialize(pid)
		@dbg = WinDbgAPI.new(pid)
		@dbg.logger = self
		@pid = @dbg.mem.keys.first
		# TODO get current cpu (x64)
		@cpu = Ia32.new
		@memory = @dbg.mem[@pid]
		super()
		# get a valid @tid (for reg values etc)
		@dbg.loop { |pid_, tid, code, info|
			update_dbgev([pid_, tid, code, info])
			case code
			when WinAPI::CREATE_THREAD_DEBUG_EVENT, WinAPI::CREATE_PROCESS_DEBUG_EVENT
				@tid = tid

				break
			end
		}
		@continuecode = WinAPI::DBG_CONTINUE	#WinAPI::DBG_EXCEPTION_NOT_HANDLED
	end

	def tid=(tid)
		super(tid)
		@ctx = nil
	end

	def ctx
		@ctx ||= @dbg.get_context(@pid, @tid)
	end

	def invalidate
		@ctx = nil
		super()
	end

	def get_reg_value(r)
		ctx[r]
	end
	def set_reg_value(r, v)
		ctx[r] = v
	end

	def enable_bp(addr)
		return if not b = @breakpoint[addr]
		@cpu.dbg_enable_bp(self, addr, b)
		b.state = :active
	end

	def disable_bp(addr)
		return if not b = @breakpoint[addr]
		@cpu.dbg_disable_bp(self, addr, b)
		b.state = :inactive
	end

	def do_continue(*a)
		@cpu.dbg_disable_singlestep(self)
		@dbg.continuedebugevent(@pid, @tid, @continuecode)
		@state = :running
		@info = 'continue'
	end

	def do_singlestep(*a)
		@cpu.dbg_enable_singlestep(self)
		@dbg.continuedebugevent(@pid, @tid, @continuecode)
		@state = :running
		@info = 'singlestep'
	end

	def do_check_target
		ev = @dbg.waitfordebugevent(@dbg.debugevent_alloc, 0)
		update_dbgev(ev)
	end


	def do_wait_target
		@dbg.loop { |*ev|
			update_dbgev(ev)
			break if @state != :running
		} if @state == :running
	end

	def break
		@dbg.break(@pid) if @state == :running
	end

	def kill(*a)
		WinAPI.terminateprocess(@dbg.hprocess[@pid], 0)
		@state = :dead
		@info = 'killed'
	end

	def check_post_run(*a)
		@cpu.dbg_check_post_run(self)
		super(*a)
	end

	def update_dbgev(ev)
		return if not ev
		pid, tid, code, info = ev
		return if pid != @pid
		invalidate
		@continuecode = WinAPI::DBG_CONTINUE
		case code
		when WinAPI::EXCEPTION_DEBUG_EVENT
			# attr :code, :flags, :recordptr, :addr, :nparam, :info, :firstchance
			case info.code
			when WinAPI::STATUS_ACCESS_VIOLATION
				# fix fs bug in xpsp1
				if @cpu.kind_of? Ia32 and ctx = @dbg.get_context(pid, tid) and ctx[:fs] != 0x3b
					puts "wdbg: #{pid}:#{tid} fix fs bug" if $DEBUG
					ctx[:fs] = 0x3b
					@dbg.continuedebugevent(pid, tid, WinAPI::DBG_CONTINUE)
					return
				end
				@state = :stopped
				@info = "access violation at #{Expression[info.addr]}"
			when WinAPI::STATUS_BREAKPOINT, WinAPI::STATUS_SINGLE_STEP
				@state = :stopped
				@info = nil
			else
				@state = :stopped
				@info = "unknown #{info.inspect}"
				@continuecode = WinAPI::DBG_EXCEPTION_NOT_HANDLED
			end
		when WinAPI::CREATE_THREAD_DEBUG_EVENT
			@state = :stopped
			@info = "thread #{tid} created"
		when WinAPI::EXIT_THREAD_DEBUG_EVENT
			@state = :stopped
			@info = "thread #{tid} died, exitcode #{info.exitcode}"
		when WinAPI::EXIT_PROCESS_DEBUG_EVENT
			@state = :dead
			@info = "process died, exitcode #{info.exitcode}"
		else
			# loadsyms(info.imagebase) if code == WinAPI::LOAD_DLL_DEBUG_EVENT
			@dbg.continuedebugevent(pid, tid, WinAPI::DBG_CONTINUE)
			return
		end
		@tid = tid
	end
end

class WindowsExports
	# exported symbol name => exporting library name for common libraries
	# used by PE#autoimports
	EXPORT = {}
	# see samples/pe_listexports for the generator of this data
	data = <<EOL	# XXX libraries do not support __END__/DATA...
ADVAPI32
 I_ScGetCurrentGroupStateW A_SHAFinal A_SHAInit A_SHAUpdate AbortSystemShutdownA AbortSystemShutdownW AccessCheck AccessCheckAndAuditAlarmA
 AccessCheckAndAuditAlarmW AccessCheckByType AccessCheckByTypeAndAuditAlarmA AccessCheckByTypeAndAuditAlarmW AccessCheckByTypeResultList
 AccessCheckByTypeResultListAndAuditAlarmA AccessCheckByTypeResultListAndAuditAlarmByHandleA AccessCheckByTypeResultListAndAuditAlarmByHandleW
 AccessCheckByTypeResultListAndAuditAlarmW AddAccessAllowedAce AddAccessAllowedAceEx AddAccessAllowedObjectAce AddAccessDeniedAce AddAccessDeniedAceEx
 AddAccessDeniedObjectAce AddAce AddAuditAccessAce AddAuditAccessAceEx AddAuditAccessObjectAce AddUsersToEncryptedFile AdjustTokenGroups AdjustTokenPrivileges
 AllocateAndInitializeSid AllocateLocallyUniqueId AreAllAccessesGranted AreAnyAccessesGranted BackupEventLogA BackupEventLogW BuildExplicitAccessWithNameA
 BuildExplicitAccessWithNameW BuildImpersonateExplicitAccessWithNameA BuildImpersonateExplicitAccessWithNameW BuildImpersonateTrusteeA BuildImpersonateTrusteeW
 BuildSecurityDescriptorA BuildSecurityDescriptorW BuildTrusteeWithNameA BuildTrusteeWithNameW BuildTrusteeWithObjectsAndNameA BuildTrusteeWithObjectsAndNameW
 BuildTrusteeWithObjectsAndSidA BuildTrusteeWithObjectsAndSidW BuildTrusteeWithSidA BuildTrusteeWithSidW CancelOverlappedAccess ChangeServiceConfig2A
 ChangeServiceConfig2W ChangeServiceConfigA ChangeServiceConfigW CheckTokenMembership ClearEventLogA ClearEventLogW CloseCodeAuthzLevel CloseEncryptedFileRaw
 CloseEventLog CloseServiceHandle CloseTrace CommandLineFromMsiDescriptor ComputeAccessTokenFromCodeAuthzLevel ControlService ControlTraceA ControlTraceW
 ConvertAccessToSecurityDescriptorA ConvertAccessToSecurityDescriptorW ConvertSDToStringSDRootDomainA ConvertSDToStringSDRootDomainW
 ConvertSecurityDescriptorToAccessA ConvertSecurityDescriptorToAccessNamedA ConvertSecurityDescriptorToAccessNamedW ConvertSecurityDescriptorToAccessW
 ConvertSecurityDescriptorToStringSecurityDescriptorA ConvertSecurityDescriptorToStringSecurityDescriptorW ConvertSidToStringSidA ConvertSidToStringSidW
 ConvertStringSDToSDDomainA ConvertStringSDToSDDomainW ConvertStringSDToSDRootDomainA ConvertStringSDToSDRootDomainW
 ConvertStringSecurityDescriptorToSecurityDescriptorA ConvertStringSecurityDescriptorToSecurityDescriptorW ConvertStringSidToSidA ConvertStringSidToSidW
 ConvertToAutoInheritPrivateObjectSecurity CopySid CreateCodeAuthzLevel CreatePrivateObjectSecurity CreatePrivateObjectSecurityEx
 CreatePrivateObjectSecurityWithMultipleInheritance CreateProcessAsUserA CreateProcessAsUserSecure CreateProcessAsUserW CreateProcessWithLogonW
 CreateRestrictedToken CreateServiceA CreateServiceW CreateTraceInstanceId CreateWellKnownSid CredDeleteA CredDeleteW CredEnumerateA CredEnumerateW CredFree
 CredGetSessionTypes CredGetTargetInfoA CredGetTargetInfoW CredIsMarshaledCredentialA CredIsMarshaledCredentialW CredMarshalCredentialA CredMarshalCredentialW
 CredProfileLoaded CredReadA CredReadDomainCredentialsA CredReadDomainCredentialsW CredReadW CredRenameA CredRenameW CredUnmarshalCredentialA
 CredUnmarshalCredentialW CredWriteA CredWriteDomainCredentialsA CredWriteDomainCredentialsW CredWriteW CredpConvertCredential CredpConvertTargetInfo
 CredpDecodeCredential CredpEncodeCredential CryptAcquireContextA CryptAcquireContextW CryptContextAddRef CryptCreateHash CryptDecrypt CryptDeriveKey
 CryptDestroyHash CryptDestroyKey CryptDuplicateHash CryptDuplicateKey CryptEncrypt CryptEnumProviderTypesA CryptEnumProviderTypesW CryptEnumProvidersA
 CryptEnumProvidersW CryptExportKey CryptGenKey CryptGenRandom CryptGetDefaultProviderA CryptGetDefaultProviderW CryptGetHashParam CryptGetKeyParam
 CryptGetProvParam CryptGetUserKey CryptHashData CryptHashSessionKey CryptImportKey CryptReleaseContext CryptSetHashParam CryptSetKeyParam CryptSetProvParam
 CryptSetProviderA CryptSetProviderExA CryptSetProviderExW CryptSetProviderW CryptSignHashA CryptSignHashW CryptVerifySignatureA CryptVerifySignatureW
 DecryptFileA DecryptFileW DeleteAce DeleteService DeregisterEventSource DestroyPrivateObjectSecurity DuplicateEncryptionInfoFile DuplicateToken
 DuplicateTokenEx ElfBackupEventLogFileA ElfBackupEventLogFileW ElfChangeNotify ElfClearEventLogFileA ElfClearEventLogFileW ElfCloseEventLog
 ElfDeregisterEventSource ElfFlushEventLog ElfNumberOfRecords ElfOldestRecord ElfOpenBackupEventLogA ElfOpenBackupEventLogW ElfOpenEventLogA ElfOpenEventLogW
 ElfReadEventLogA ElfReadEventLogW ElfRegisterEventSourceA ElfRegisterEventSourceW ElfReportEventA ElfReportEventW EnableTrace EncryptFileA EncryptFileW
 EncryptedFileKeyInfo EncryptionDisable EnumDependentServicesA EnumDependentServicesW EnumServiceGroupW EnumServicesStatusA EnumServicesStatusExA
 EnumServicesStatusExW EnumServicesStatusW EnumerateTraceGuids EqualDomainSid EqualPrefixSid EqualSid FileEncryptionStatusA FileEncryptionStatusW
 FindFirstFreeAce FlushTraceA FlushTraceW FreeEncryptedFileKeyInfo FreeEncryptionCertificateHashList FreeInheritedFromArray FreeSid
 GetAccessPermissionsForObjectA GetAccessPermissionsForObjectW GetAce GetAclInformation GetAuditedPermissionsFromAclA GetAuditedPermissionsFromAclW
 GetCurrentHwProfileA GetCurrentHwProfileW GetEffectiveRightsFromAclA GetEffectiveRightsFromAclW GetEventLogInformation GetExplicitEntriesFromAclA
 GetExplicitEntriesFromAclW GetFileSecurityA GetFileSecurityW GetInformationCodeAuthzLevelW GetInformationCodeAuthzPolicyW GetInheritanceSourceA
 GetInheritanceSourceW GetKernelObjectSecurity GetLengthSid GetLocalManagedApplicationData GetLocalManagedApplications GetManagedApplicationCategories
 GetManagedApplications GetMultipleTrusteeA GetMultipleTrusteeOperationA GetMultipleTrusteeOperationW GetMultipleTrusteeW GetNamedSecurityInfoA
 GetNamedSecurityInfoExA GetNamedSecurityInfoExW GetNamedSecurityInfoW GetNumberOfEventLogRecords GetOldestEventLogRecord GetOverlappedAccessResults
 GetPrivateObjectSecurity GetSecurityDescriptorControl GetSecurityDescriptorDacl GetSecurityDescriptorGroup GetSecurityDescriptorLength
 GetSecurityDescriptorOwner GetSecurityDescriptorRMControl GetSecurityDescriptorSacl GetSecurityInfo GetSecurityInfoExA GetSecurityInfoExW
 GetServiceDisplayNameA GetServiceDisplayNameW GetServiceKeyNameA GetServiceKeyNameW GetSidIdentifierAuthority GetSidLengthRequired GetSidSubAuthority
 GetSidSubAuthorityCount GetTokenInformation GetTraceEnableFlags GetTraceEnableLevel GetTraceLoggerHandle GetTrusteeFormA GetTrusteeFormW GetTrusteeNameA
 GetTrusteeNameW GetTrusteeTypeA GetTrusteeTypeW GetUserNameA GetUserNameW GetWindowsAccountDomainSid I_ScIsSecurityProcess I_ScPnPGetServiceName
 I_ScSendTSMessage I_ScSetServiceBitsA I_ScSetServiceBitsW IdentifyCodeAuthzLevelW ImpersonateAnonymousToken ImpersonateLoggedOnUser ImpersonateNamedPipeClient
 ImpersonateSelf InitializeAcl InitializeSecurityDescriptor InitializeSid InitiateSystemShutdownA InitiateSystemShutdownExA InitiateSystemShutdownExW
 InitiateSystemShutdownW InstallApplication IsTextUnicode IsTokenRestricted IsTokenUntrusted IsValidAcl IsValidSecurityDescriptor IsValidSid IsWellKnownSid
 LockServiceDatabase LogonUserA LogonUserExA LogonUserExW LogonUserW LookupAccountNameA LookupAccountNameW LookupAccountSidA LookupAccountSidW
 LookupPrivilegeDisplayNameA LookupPrivilegeDisplayNameW LookupPrivilegeNameA LookupPrivilegeNameW LookupPrivilegeValueA LookupPrivilegeValueW
 LookupSecurityDescriptorPartsA LookupSecurityDescriptorPartsW LsaAddAccountRights LsaAddPrivilegesToAccount LsaClearAuditLog LsaClose LsaCreateAccount
 LsaCreateSecret LsaCreateTrustedDomain LsaCreateTrustedDomainEx LsaDelete LsaDeleteTrustedDomain LsaEnumerateAccountRights LsaEnumerateAccounts
 LsaEnumerateAccountsWithUserRight LsaEnumeratePrivileges LsaEnumeratePrivilegesOfAccount LsaEnumerateTrustedDomains LsaEnumerateTrustedDomainsEx LsaFreeMemory
 LsaGetQuotasForAccount LsaGetRemoteUserName LsaGetSystemAccessAccount LsaGetUserName LsaICLookupNames LsaICLookupNamesWithCreds LsaICLookupSids
 LsaICLookupSidsWithCreds LsaLookupNames2 LsaLookupNames LsaLookupPrivilegeDisplayName LsaLookupPrivilegeName LsaLookupPrivilegeValue LsaLookupSids
 LsaNtStatusToWinError LsaOpenAccount LsaOpenPolicy LsaOpenPolicySce LsaOpenSecret LsaOpenTrustedDomain LsaOpenTrustedDomainByName
 LsaQueryDomainInformationPolicy LsaQueryForestTrustInformation LsaQueryInfoTrustedDomain LsaQueryInformationPolicy LsaQuerySecret LsaQuerySecurityObject
 LsaQueryTrustedDomainInfo LsaQueryTrustedDomainInfoByName LsaRemoveAccountRights LsaRemovePrivilegesFromAccount LsaRetrievePrivateData
 LsaSetDomainInformationPolicy LsaSetForestTrustInformation LsaSetInformationPolicy LsaSetInformationTrustedDomain LsaSetQuotasForAccount LsaSetSecret
 LsaSetSecurityObject LsaSetSystemAccessAccount LsaSetTrustedDomainInfoByName LsaSetTrustedDomainInformation LsaStorePrivateData MD4Final MD4Init MD4Update
 MD5Final MD5Init MD5Update MSChapSrvChangePassword2 MSChapSrvChangePassword MakeAbsoluteSD2 MakeAbsoluteSD MakeSelfRelativeSD MapGenericMask
 NotifyBootConfigStatus NotifyChangeEventLog ObjectCloseAuditAlarmA ObjectCloseAuditAlarmW ObjectDeleteAuditAlarmA ObjectDeleteAuditAlarmW ObjectOpenAuditAlarmA
 ObjectOpenAuditAlarmW ObjectPrivilegeAuditAlarmA ObjectPrivilegeAuditAlarmW OpenBackupEventLogA OpenBackupEventLogW OpenEncryptedFileRawA OpenEncryptedFileRawW
 OpenEventLogA OpenEventLogW OpenProcessToken OpenSCManagerA OpenSCManagerW OpenServiceA OpenServiceW OpenThreadToken OpenTraceA OpenTraceW PrivilegeCheck
 PrivilegedServiceAuditAlarmA PrivilegedServiceAuditAlarmW ProcessIdleTasks ProcessTrace QueryAllTracesA QueryAllTracesW QueryRecoveryAgentsOnEncryptedFile
 QueryServiceConfig2A QueryServiceConfig2W QueryServiceConfigA QueryServiceConfigW QueryServiceLockStatusA QueryServiceLockStatusW QueryServiceObjectSecurity
 QueryServiceStatus QueryServiceStatusEx QueryTraceA QueryTraceW QueryUsersOnEncryptedFile QueryWindows31FilesMigration ReadEncryptedFileRaw ReadEventLogA
 ReadEventLogW RegCloseKey RegConnectRegistryA RegConnectRegistryW RegCreateKeyA RegCreateKeyExA RegCreateKeyExW RegCreateKeyW RegDeleteKeyA RegDeleteKeyW
 RegDeleteValueA RegDeleteValueW RegDisablePredefinedCache RegEnumKeyA RegEnumKeyExA RegEnumKeyExW RegEnumKeyW RegEnumValueA RegEnumValueW RegFlushKey
 RegGetKeySecurity RegLoadKeyA RegLoadKeyW RegNotifyChangeKeyValue RegOpenCurrentUser RegOpenKeyA RegOpenKeyExA RegOpenKeyExW RegOpenKeyW RegOpenUserClassesRoot
 RegOverridePredefKey RegQueryInfoKeyA RegQueryInfoKeyW RegQueryMultipleValuesA RegQueryMultipleValuesW RegQueryValueA RegQueryValueExA RegQueryValueExW
 RegQueryValueW RegReplaceKeyA RegReplaceKeyW RegRestoreKeyA RegRestoreKeyW RegSaveKeyA RegSaveKeyExA RegSaveKeyExW RegSaveKeyW RegSetKeySecurity RegSetValueA
 RegSetValueExA RegSetValueExW RegSetValueW RegUnLoadKeyA RegUnLoadKeyW RegisterEventSourceA RegisterEventSourceW RegisterIdleTask RegisterServiceCtrlHandlerA
 RegisterServiceCtrlHandlerExA RegisterServiceCtrlHandlerExW RegisterServiceCtrlHandlerW RegisterTraceGuidsA RegisterTraceGuidsW RemoveTraceCallback
 RemoveUsersFromEncryptedFile ReportEventA ReportEventW RevertToSelf SaferCloseLevel SaferComputeTokenFromLevel SaferCreateLevel SaferGetLevelInformation
 SaferGetPolicyInformation SaferIdentifyLevel SaferRecordEventLogEntry SaferSetLevelInformation SaferSetPolicyInformation SaferiChangeRegistryScope
 SaferiCompareTokenLevels SaferiIsExecutableFileType SaferiPopulateDefaultsInRegistry SaferiRecordEventLogEntry SaferiReplaceProcessThreadTokens
 SaferiSearchMatchingHashRules SetAclInformation SetEntriesInAccessListA SetEntriesInAccessListW SetEntriesInAclA SetEntriesInAclW SetEntriesInAuditListA
 SetEntriesInAuditListW SetFileSecurityA SetFileSecurityW SetInformationCodeAuthzLevelW SetInformationCodeAuthzPolicyW SetKernelObjectSecurity
 SetNamedSecurityInfoA SetNamedSecurityInfoExA SetNamedSecurityInfoExW SetNamedSecurityInfoW SetPrivateObjectSecurity SetPrivateObjectSecurityEx
 SetSecurityDescriptorControl SetSecurityDescriptorDacl SetSecurityDescriptorGroup SetSecurityDescriptorOwner SetSecurityDescriptorRMControl
 SetSecurityDescriptorSacl SetSecurityInfo SetSecurityInfoExA SetSecurityInfoExW SetServiceBits SetServiceObjectSecurity SetServiceStatus SetThreadToken
 SetTokenInformation SetTraceCallback SetUserFileEncryptionKey StartServiceA StartServiceCtrlDispatcherA StartServiceCtrlDispatcherW StartServiceW StartTraceA
 StartTraceW StopTraceA StopTraceW SynchronizeWindows31FilesAndWindowsNTRegistry SystemFunction001 SystemFunction002 SystemFunction003 SystemFunction004
 SystemFunction005 SystemFunction006 SystemFunction007 SystemFunction008 SystemFunction009 SystemFunction010 SystemFunction011 SystemFunction012
 SystemFunction013 SystemFunction014 SystemFunction015 SystemFunction016 SystemFunction017 SystemFunction018 SystemFunction019 SystemFunction020
 SystemFunction021 SystemFunction022 SystemFunction023 SystemFunction024 SystemFunction025 SystemFunction026 SystemFunction027 SystemFunction028
 SystemFunction029 SystemFunction030 SystemFunction031 SystemFunction032 SystemFunction033 SystemFunction034 SystemFunction035 SystemFunction036
 SystemFunction040 SystemFunction041 TraceEvent TraceEventInstance TraceMessage TraceMessageVa TreeResetNamedSecurityInfoA TreeResetNamedSecurityInfoW
 TrusteeAccessToObjectA TrusteeAccessToObjectW UninstallApplication UnlockServiceDatabase UnregisterIdleTask UnregisterTraceGuids UpdateTraceA UpdateTraceW
 WdmWmiServiceMain WmiCloseBlock WmiCloseTraceWithCursor WmiConvertTimestamp WmiDevInstToInstanceNameA WmiDevInstToInstanceNameW WmiEnumerateGuids
 WmiExecuteMethodA WmiExecuteMethodW WmiFileHandleToInstanceNameA WmiFileHandleToInstanceNameW WmiFreeBuffer WmiGetFirstTraceOffset WmiGetNextEvent
 WmiGetTraceHeader WmiMofEnumerateResourcesA WmiMofEnumerateResourcesW WmiNotificationRegistrationA WmiNotificationRegistrationW WmiOpenBlock
 WmiOpenTraceWithCursor WmiParseTraceEvent WmiQueryAllDataA WmiQueryAllDataMultipleA WmiQueryAllDataMultipleW WmiQueryAllDataW WmiQueryGuidInformation
 WmiQuerySingleInstanceA WmiQuerySingleInstanceMultipleA WmiQuerySingleInstanceMultipleW WmiQuerySingleInstanceW WmiReceiveNotificationsA
 WmiReceiveNotificationsW WmiSetSingleInstanceA WmiSetSingleInstanceW WmiSetSingleItemA WmiSetSingleItemW Wow64Win32ApiEntry WriteEncryptedFileRaw
WS2_32
 accept bind closesocket connect getpeername getsockname getsockopt htonl htons ioctlsocket inet_addr inet_ntoa listen ntohl ntohs recv recvfrom select send
 sendto setsockopt shutdown socket GetAddrInfoW GetNameInfoW WSApSetPostRoutine FreeAddrInfoW WPUCompleteOverlappedRequest WSAAccept WSAAddressToStringA
 WSAAddressToStringW WSACloseEvent WSAConnect WSACreateEvent WSADuplicateSocketA WSADuplicateSocketW WSAEnumNameSpaceProvidersA WSAEnumNameSpaceProvidersW
 WSAEnumNetworkEvents WSAEnumProtocolsA WSAEnumProtocolsW WSAEventSelect WSAGetOverlappedResult WSAGetQOSByName WSAGetServiceClassInfoA WSAGetServiceClassInfoW
 WSAGetServiceClassNameByClassIdA WSAGetServiceClassNameByClassIdW WSAHtonl WSAHtons gethostbyaddr gethostbyname getprotobyname getprotobynumber getservbyname
 getservbyport gethostname WSAInstallServiceClassA WSAInstallServiceClassW WSAIoctl WSAJoinLeaf WSALookupServiceBeginA WSALookupServiceBeginW
 WSALookupServiceEnd WSALookupServiceNextA WSALookupServiceNextW WSANSPIoctl WSANtohl WSANtohs WSAProviderConfigChange WSARecv WSARecvDisconnect WSARecvFrom
 WSARemoveServiceClass WSAResetEvent WSASend WSASendDisconnect WSASendTo WSASetEvent WSASetServiceA WSASetServiceW WSASocketA WSASocketW WSAStringToAddressA
 WSAStringToAddressW WSAWaitForMultipleEvents WSCDeinstallProvider WSCEnableNSProvider WSCEnumProtocols WSCGetProviderPath WSCInstallNameSpace
 WSCInstallProvider WSCUnInstallNameSpace WSCUpdateProvider WSCWriteNameSpaceOrder WSCWriteProviderOrder freeaddrinfo getaddrinfo getnameinfo WSAAsyncSelect
 WSAAsyncGetHostByAddr WSAAsyncGetHostByName WSAAsyncGetProtoByNumber WSAAsyncGetProtoByName WSAAsyncGetServByPort WSAAsyncGetServByName WSACancelAsyncRequest
 WSASetBlockingHook WSAUnhookBlockingHook WSAGetLastError WSASetLastError WSACancelBlockingCall WSAIsBlocking WSAStartup WSACleanup __WSAFDIsSet WEP
msvcrt
 _CIacos _CIasin _CIatan _CIatan2 _CIcos _CIcosh
 _CIexp _CIfmod _CIlog _CIlog10 _CIpow _CIsin _CIsinh _CIsqrt _CItan _CItanh _CxxThrowException _EH_prolog _Getdays _Getmonths _Gettnames _HUGE _Strftime
 _XcptFilter __CxxCallUnwindDtor __CxxDetectRethrow __CxxExceptionFilter __CxxFrameHandler __CxxLongjmpUnwind __CxxQueryExceptionSize
 __CxxRegisterExceptionObject __CxxUnregisterExceptionObject __DestructExceptionObject __RTCastToVoid __RTDynamicCast __RTtypeid __STRINGTOLD
 ___lc_codepage_func ___lc_handle_func ___mb_cur_max_func ___setlc_active_func ___unguarded_readlc_active_add_func __argc __argv __badioinfo __crtCompareStringA __crtCompareStringW __crtGetLocaleInfoW __crtGetStringTypeW __crtLCMapStringA __crtLCMapStringW __dllonexit __doserrno __fpecode __getmainargs __initenv
 __iob_func __isascii __iscsym __iscsymf __lc_codepage __lc_collate_cp __lc_handle __lconv_init __mb_cur_max __p___argc __p___argv __p___initenv
 __p___mb_cur_max __p___wargv __p___winitenv __p__acmdln __p__amblksiz __p__commode __p__daylight __p__dstbias __p__environ __p__fileinfo __p__fmode __p__iob
 __p__mbcasemap __p__mbctype __p__osver __p__pctype __p__pgmptr __p__pwctype __p__timezone __p__tzname __p__wcmdln __p__wenviron __p__winmajor __p__winminor
 __p__winver __p__wpgmptr __pctype_func __pioinfo __pxcptinfoptrs __set_app_type __setlc_active __setusermatherr __threadhandle __threadid __toascii __unDName
 __unDNameEx __unguarded_readlc_active __wargv __wcserror __wgetmainargs __winitenv _abnormal_termination _access _acmdln _adj_fdiv_m16i _adj_fdiv_m32
 _adj_fdiv_m32i _adj_fdiv_m64 _adj_fdiv_r _adj_fdivr_m16i _adj_fdivr_m32 _adj_fdivr_m32i _adj_fdivr_m64 _adj_fpatan _adj_fprem _adj_fprem1 _adj_fptan
 _adjust_fdiv _aexit_rtn _aligned_free _aligned_malloc _aligned_offset_malloc _aligned_offset_realloc _aligned_realloc _amsg_exit _assert _atodbl _atoi64
 _atoldbl _beep _beginthread _beginthreadex _c_exit _cabs _callnewh _cexit _cgets _cgetws _chdir _chdrive _chgsign _chkesp _chmod _chsize _clearfp _close
 _commit _commode _control87 _controlfp _copysign _cprintf _cputs _cputws _creat _cscanf _ctime64 _ctype _cwait _cwprintf _cwscanf _daylight _dstbias _dup _dup2 _ecvt _endthread _endthreadex _environ _eof _errno _except_handler2 _except_handler3 _execl _execle _execlp _execlpe _execv _execve _execvp _execvpe _exit
 _expand _fcloseall _fcvt _fdopen _fgetchar _fgetwchar _filbuf _fileinfo _filelength _filelengthi64 _fileno _findclose _findfirst _findfirst64 _findfirsti64
 _findnext _findnext64 _findnexti64 _finite _flsbuf _flushall _fmode _fpclass _fpieee_flt _fpreset _fputchar _fputwchar _fsopen _fstat _fstat64 _fstati64 _ftime _ftime64 _ftol _fullpath _futime _futime64 _gcvt _get_heap_handle _get_osfhandle _get_sbh_threshold _getch _getche _getcwd _getdcwd _getdiskfree
 _getdllprocaddr _getdrive _getdrives _getmaxstdio _getmbcp _getpid _getsystime _getw _getwch _getwche _getws _global_unwind2 _gmtime64 _heapadd _heapchk
 _heapmin _heapset _heapused _heapwalk _hypot _i64toa _i64tow _initterm _inp _inpd _inpw _iob _isatty _isctype _ismbbalnum _ismbbalpha _ismbbgraph _ismbbkalnum
 _ismbbkana _ismbbkprint _ismbbkpunct _ismbblead _ismbbprint _ismbbpunct _ismbbtrail _ismbcalnum _ismbcalpha _ismbcdigit _ismbcgraph _ismbchira _ismbckata
 _ismbcl0 _ismbcl1 _ismbcl2 _ismbclegal _ismbclower _ismbcprint _ismbcpunct _ismbcspace _ismbcsymbol _ismbcupper _ismbslead _ismbstrail _isnan _itoa _itow _j0
 _j1 _jn _kbhit _lfind _loaddll _local_unwind2 _localtime64 _lock _locking _logb _longjmpex _lrotl _lrotr _lsearch _lseek _lseeki64 _ltoa _ltow _makepath
 _mbbtombc _mbbtype _mbcasemap _mbccpy _mbcjistojms _mbcjmstojis _mbclen _mbctohira _mbctokata _mbctolower _mbctombb _mbctoupper _mbctype _mbsbtype _mbscat
 _mbschr _mbscmp _mbscoll _mbscpy _mbscspn _mbsdec _mbsdup _mbsicmp _mbsicoll _mbsinc _mbslen _mbslwr _mbsnbcat _mbsnbcmp _mbsnbcnt _mbsnbcoll _mbsnbcpy
 _mbsnbicmp _mbsnbicoll _mbsnbset _mbsncat _mbsnccnt _mbsncmp _mbsncoll _mbsncpy _mbsnextc _mbsnicmp _mbsnicoll _mbsninc _mbsnset _mbspbrk _mbsrchr _mbsrev
 _mbsset _mbsspn _mbsspnp _mbsstr _mbstok _mbstrlen _mbsupr _memccpy _memicmp _mkdir _mktemp _mktime64 _msize _nextafter _onexit _open _open_osfhandle
 _osplatform _osver _outp _outpd _outpw _pclose _pctype _pgmptr _pipe _popen _purecall _putch _putenv _putw _putwch _putws _pwctype _read _resetstkoflw _rmdir
 _rmtmp _rotl _rotr _safe_fdiv _safe_fdivr _safe_fprem _safe_fprem1 _scalb _scprintf _scwprintf _searchenv _seh_longjmp_unwind _set_SSE2_enable _set_error_mode
 _set_sbh_threshold _seterrormode _setjmp _setjmp3 _setmaxstdio _setmbcp _setmode _setsystime _sleep _snprintf _snscanf _snwprintf _snwscanf _sopen _spawnl
 _spawnle _spawnlp _spawnlpe _spawnv _spawnve _spawnvp _spawnvpe _splitpath _stat _stat64 _stati64 _statusfp _strcmpi _strdate _strdup _strerror _stricmp
 _stricoll _strlwr _strncoll _strnicmp _strnicoll _strnset _strrev _strset _strtime _strtoi64 _strtoui64 _strupr _swab _sys_errlist _sys_nerr _tell _telli64
 _tempnam _time64 _timezone _tolower _toupper _tzname _tzset _ui64toa _ui64tow _ultoa _ultow _umask _ungetch _ungetwch _unlink _unloaddll _unlock _utime
 _utime64 _vscprintf _vscwprintf _vsnprintf _vsnwprintf _waccess _wasctime _wchdir _wchmod _wcmdln _wcreat _wcsdup _wcserror _wcsicmp _wcsicoll _wcslwr
 _wcsncoll _wcsnicmp _wcsnicoll _wcsnset _wcsrev _wcsset _wcstoi64 _wcstoui64 _wcsupr _wctime _wctime64 _wenviron _wexecl _wexecle _wexeclp _wexeclpe _wexecv
 _wexecve _wexecvp _wexecvpe _wfdopen _wfindfirst _wfindfirst64 _wfindfirsti64 _wfindnext _wfindnext64 _wfindnexti64 _wfopen _wfreopen _wfsopen _wfullpath
 _wgetcwd _wgetdcwd _wgetenv _winmajor _winminor _winver _wmakepath _wmkdir _wmktemp _wopen _wperror _wpgmptr _wpopen _wputenv _wremove _wrename _write _wrmdir
 _wsearchenv _wsetlocale _wsopen _wspawnl _wspawnle _wspawnlp _wspawnlpe _wspawnv _wspawnve _wspawnvp _wspawnvpe _wsplitpath _wstat _wstat64 _wstati64 _wstrdate _wstrtime _wsystem _wtempnam _wtmpnam _wtof _wtoi _wtoi64 _wtol _wunlink _wutime _wutime64 _y0 _y1 _yn abort abs acos asctime asin atan atan2 atexit atof atoi
 atol bsearch calloc ceil clearerr clock cos cosh ctime difftime div exit exp fabs fclose feof ferror fflush fgetc fgetpos fgets fgetwc fgetws floor fmod fopen
 fprintf fputc fputs fputwc fputws fread free freopen frexp fscanf fseek fsetpos ftell fwprintf fwrite fwscanf getc getchar getenv gets getwc getwchar gmtime
 is_wctype isalnum isalpha iscntrl isdigit isgraph isleadbyte islower isprint ispunct isspace isupper iswalnum iswalpha iswascii iswcntrl iswctype iswdigit
 iswgraph iswlower iswprint iswpunct iswspace iswupper iswxdigit isxdigit labs ldexp ldiv localeconv localtime log log10 longjmp malloc mblen mbstowcs mbtowc
 memchr memcmp memcpy memmove memset mktime modf perror pow printf putc putchar puts putwc putwchar qsort raise rand realloc remove rename rewind scanf setbuf
 setlocale setvbuf signal sin sinh sprintf sqrt srand sscanf strcat strchr strcmp strcoll strcpy strcspn strerror strftime strlen strncat strncmp strncpy
 strpbrk strrchr strspn strstr strtod strtok strtol strtoul strxfrm swprintf swscanf system tan tanh time tmpfile tmpnam tolower toupper towlower towupper
 ungetc ungetwc vfprintf vfwprintf vprintf vsprintf vswprintf vwprintf wcscat wcschr wcscmp wcscoll wcscpy wcscspn wcsftime wcslen wcsncat wcsncmp wcsncpy
 wcspbrk wcsrchr wcsspn wcsstr wcstod wcstok wcstol wcstombs wcstoul wcsxfrm wctomb wprintf wscanf
comdlg32
 ChooseColorA ChooseColorW ChooseFontA ChooseFontW CommDlgExtendedError FindTextA FindTextW GetFileTitleA GetFileTitleW GetOpenFileNameA GetOpenFileNameW
 GetSaveFileNameA GetSaveFileNameW LoadAlterBitmap PageSetupDlgA PageSetupDlgW PrintDlgA PrintDlgExA PrintDlgExW PrintDlgW ReplaceTextA ReplaceTextW
 Ssync_ANSI_UNICODE_Struct_For_WOW WantArrows dwLBSubclass dwOKSubclass
PSAPI
 EmptyWorkingSet EnumDeviceDrivers EnumPageFilesA EnumPageFilesW EnumProcessModules EnumProcesses GetDeviceDriverBaseNameA GetDeviceDriverBaseNameW
 GetDeviceDriverFileNameA GetDeviceDriverFileNameW GetMappedFileNameA GetMappedFileNameW GetModuleBaseNameA GetModuleBaseNameW GetModuleFileNameExA
 GetModuleFileNameExW GetModuleInformation GetPerformanceInfo GetProcessImageFileNameA GetProcessImageFileNameW GetProcessMemoryInfo GetWsChanges
 InitializeProcessForWsWatch QueryWorkingSet
USER32
 ActivateKeyboardLayout AdjustWindowRect AdjustWindowRectEx AlignRects AllowForegroundActivation AllowSetForegroundWindow AnimateWindow AnyPopup AppendMenuA
 AppendMenuW ArrangeIconicWindows AttachThreadInput BeginDeferWindowPos BeginPaint BlockInput BringWindowToTop BroadcastSystemMessage BroadcastSystemMessageA
 BroadcastSystemMessageExA BroadcastSystemMessageExW BroadcastSystemMessageW BuildReasonArray CalcMenuBar CallMsgFilter CallMsgFilterA CallMsgFilterW
 CallNextHookEx CallWindowProcA CallWindowProcW CascadeChildWindows CascadeWindows ChangeClipboardChain ChangeDisplaySettingsA ChangeDisplaySettingsExA
 ChangeDisplaySettingsExW ChangeDisplaySettingsW ChangeMenuA ChangeMenuW CharLowerA CharLowerBuffA CharLowerBuffW CharLowerW CharNextA CharNextExA CharNextW
 CharPrevA CharPrevExA CharPrevW CharToOemA CharToOemBuffA CharToOemBuffW CharToOemW CharUpperA CharUpperBuffA CharUpperBuffW CharUpperW CheckDlgButton
 CheckMenuItem CheckMenuRadioItem CheckRadioButton ChildWindowFromPoint ChildWindowFromPointEx CliImmSetHotKey ClientThreadSetup ClientToScreen ClipCursor
 CloseClipboard CloseDesktop CloseWindow CloseWindowStation CopyAcceleratorTableA CopyAcceleratorTableW CopyIcon CopyImage CopyRect CountClipboardFormats
 CreateAcceleratorTableA CreateAcceleratorTableW CreateCaret CreateCursor CreateDesktopA CreateDesktopW CreateDialogIndirectParamA CreateDialogIndirectParamAorW
 CreateDialogIndirectParamW CreateDialogParamA CreateDialogParamW CreateIcon CreateIconFromResource CreateIconFromResourceEx CreateIconIndirect CreateMDIWindowA
 CreateMDIWindowW CreateMenu CreatePopupMenu CreateSystemThreads CreateWindowExA CreateWindowExW CreateWindowStationA CreateWindowStationW
 CsrBroadcastSystemMessageExW CtxInitUser32 DdeAbandonTransaction DdeAccessData DdeAddData DdeClientTransaction DdeCmpStringHandles DdeConnect DdeConnectList
 DdeCreateDataHandle DdeCreateStringHandleA DdeCreateStringHandleW DdeDisconnect DdeDisconnectList DdeEnableCallback DdeFreeDataHandle DdeFreeStringHandle
 DdeGetData DdeGetLastError DdeGetQualityOfService DdeImpersonateClient DdeInitializeA DdeInitializeW DdeKeepStringHandle DdeNameService DdePostAdvise
 DdeQueryConvInfo DdeQueryNextServer DdeQueryStringA DdeQueryStringW DdeReconnect DdeSetQualityOfService DdeSetUserHandle DdeUnaccessData DdeUninitialize
 DefDlgProcA DefDlgProcW DefFrameProcA DefFrameProcW DefMDIChildProcA DefMDIChildProcW DefRawInputProc DefWindowProcA DefWindowProcW DeferWindowPos DeleteMenu
 DeregisterShellHookWindow DestroyAcceleratorTable DestroyCaret DestroyCursor DestroyIcon DestroyMenu DestroyReasons DestroyWindow DeviceEventWorker
 DialogBoxIndirectParamA DialogBoxIndirectParamAorW DialogBoxIndirectParamW DialogBoxParamA DialogBoxParamW DisableProcessWindowsGhosting DispatchMessageA
 DispatchMessageW DisplayExitWindowsWarnings DlgDirListA DlgDirListComboBoxA DlgDirListComboBoxW DlgDirListW DlgDirSelectComboBoxExA DlgDirSelectComboBoxExW
 DlgDirSelectExA DlgDirSelectExW DragDetect DragObject DrawAnimatedRects DrawCaption DrawCaptionTempA DrawCaptionTempW DrawEdge DrawFocusRect DrawFrame
 DrawFrameControl DrawIcon DrawIconEx DrawMenuBar DrawMenuBarTemp DrawStateA DrawStateW DrawTextA DrawTextExA DrawTextExW DrawTextW EditWndProc EmptyClipboard
 EnableMenuItem EnableScrollBar EnableWindow EndDeferWindowPos EndDialog EndMenu EndPaint EndTask EnterReaderModeHelper EnumChildWindows EnumClipboardFormats
 EnumDesktopWindows EnumDesktopsA EnumDesktopsW EnumDisplayDevicesA EnumDisplayDevicesW EnumDisplayMonitors EnumDisplaySettingsA EnumDisplaySettingsExA
 EnumDisplaySettingsExW EnumDisplaySettingsW EnumPropsA EnumPropsExA EnumPropsExW EnumPropsW EnumThreadWindows EnumWindowStationsA EnumWindowStationsW
 EnumWindows EqualRect ExcludeUpdateRgn ExitWindowsEx FillRect FindWindowA FindWindowExA FindWindowExW FindWindowW FlashWindow FlashWindowEx FrameRect
 FreeDDElParam GetActiveWindow GetAltTabInfo GetAltTabInfoA GetAltTabInfoW GetAncestor GetAppCompatFlags2 GetAppCompatFlags GetAsyncKeyState GetCapture
 GetCaretBlinkTime GetCaretPos GetClassInfoA GetClassInfoExA GetClassInfoExW GetClassInfoW GetClassLongA GetClassLongW GetClassNameA GetClassNameW GetClassWord
 GetClientRect GetClipCursor GetClipboardData GetClipboardFormatNameA GetClipboardFormatNameW GetClipboardOwner GetClipboardSequenceNumber GetClipboardViewer
 GetComboBoxInfo GetCursor GetCursorFrameInfo GetCursorInfo GetCursorPos GetDC GetDCEx GetDesktopWindow GetDialogBaseUnits GetDlgCtrlID GetDlgItem GetDlgItemInt
 GetDlgItemTextA GetDlgItemTextW GetDoubleClickTime GetFocus GetForegroundWindow GetGUIThreadInfo GetGuiResources GetIconInfo GetInputDesktop GetInputState
 GetInternalWindowPos GetKBCodePage GetKeyNameTextA GetKeyNameTextW GetKeyState GetKeyboardLayout GetKeyboardLayoutList GetKeyboardLayoutNameA
 GetKeyboardLayoutNameW GetKeyboardState GetKeyboardType GetLastActivePopup GetLastInputInfo GetLayeredWindowAttributes GetListBoxInfo GetMenu GetMenuBarInfo
 GetMenuCheckMarkDimensions GetMenuContextHelpId GetMenuDefaultItem GetMenuInfo GetMenuItemCount GetMenuItemID GetMenuItemInfoA GetMenuItemInfoW GetMenuItemRect
 GetMenuState GetMenuStringA GetMenuStringW GetMessageA GetMessageExtraInfo GetMessagePos GetMessageTime GetMessageW GetMonitorInfoA GetMonitorInfoW
 GetMouseMovePointsEx GetNextDlgGroupItem GetNextDlgTabItem GetOpenClipboardWindow GetParent GetPriorityClipboardFormat GetProcessDefaultLayout
 GetProcessWindowStation GetProgmanWindow GetPropA GetPropW GetQueueStatus GetRawInputBuffer GetRawInputData GetRawInputDeviceInfoA GetRawInputDeviceInfoW
 GetRawInputDeviceList GetReasonTitleFromReasonCode GetRegisteredRawInputDevices GetScrollBarInfo GetScrollInfo GetScrollPos GetScrollRange GetShellWindow
 GetSubMenu GetSysColor GetSysColorBrush GetSystemMenu GetSystemMetrics GetTabbedTextExtentA GetTabbedTextExtentW GetTaskmanWindow GetThreadDesktop
 GetTitleBarInfo GetTopWindow GetUpdateRect GetUpdateRgn GetUserObjectInformationA GetUserObjectInformationW GetUserObjectSecurity GetWinStationInfo GetWindow
 GetWindowContextHelpId GetWindowDC GetWindowInfo GetWindowLongA GetWindowLongW GetWindowModuleFileName GetWindowModuleFileNameA GetWindowModuleFileNameW
 GetWindowPlacement GetWindowRect GetWindowRgn GetWindowRgnBox GetWindowTextA GetWindowTextLengthA GetWindowTextLengthW GetWindowTextW GetWindowThreadProcessId
 GetWindowWord GrayStringA GrayStringW HideCaret HiliteMenuItem IMPGetIMEA IMPGetIMEW IMPQueryIMEA IMPQueryIMEW IMPSetIMEA IMPSetIMEW ImpersonateDdeClientWindow
 InSendMessage InSendMessageEx InflateRect InitializeLpkHooks InitializeWin32EntryTable InsertMenuA InsertMenuItemA InsertMenuItemW InsertMenuW
 InternalGetWindowText IntersectRect InvalidateRect InvalidateRgn InvertRect IsCharAlphaA IsCharAlphaNumericA IsCharAlphaNumericW IsCharAlphaW IsCharLowerA
 IsCharLowerW IsCharUpperA IsCharUpperW IsChild IsClipboardFormatAvailable IsDialogMessage IsDialogMessageA IsDialogMessageW IsDlgButtonChecked IsGUIThread
 IsHungAppWindow IsIconic IsMenu IsRectEmpty IsServerSideWindow IsWinEventHookInstalled IsWindow IsWindowEnabled IsWindowInDestroy IsWindowUnicode
 IsWindowVisible IsZoomed KillSystemTimer KillTimer LoadAcceleratorsA LoadAcceleratorsW LoadBitmapA LoadBitmapW LoadCursorA LoadCursorFromFileA
 LoadCursorFromFileW LoadCursorW LoadIconA LoadIconW LoadImageA LoadImageW LoadKeyboardLayoutA LoadKeyboardLayoutEx LoadKeyboardLayoutW LoadLocalFonts LoadMenuA
 LoadMenuIndirectA LoadMenuIndirectW LoadMenuW LoadRemoteFonts LoadStringA LoadStringW LockSetForegroundWindow LockWindowStation LockWindowUpdate
 LockWorkStation LookupIconIdFromDirectory LookupIconIdFromDirectoryEx MBToWCSEx MB_GetString MapDialogRect MapVirtualKeyA MapVirtualKeyExA MapVirtualKeyExW
 MapVirtualKeyW MapWindowPoints MenuItemFromPoint MenuWindowProcA MenuWindowProcW MessageBeep MessageBoxA MessageBoxExA MessageBoxExW MessageBoxIndirectA
 MessageBoxIndirectW MessageBoxTimeoutA MessageBoxTimeoutW MessageBoxW ModifyMenuA ModifyMenuW MonitorFromPoint MonitorFromRect MonitorFromWindow MoveWindow
 MsgWaitForMultipleObjects MsgWaitForMultipleObjectsEx NotifyWinEvent OemKeyScan OemToCharA OemToCharBuffA OemToCharBuffW OemToCharW OffsetRect OpenClipboard
 OpenDesktopA OpenDesktopW OpenIcon OpenInputDesktop OpenWindowStationA OpenWindowStationW PackDDElParam PaintDesktop PaintMenuBar PeekMessageA PeekMessageW
 PostMessageA PostMessageW PostQuitMessage PostThreadMessageA PostThreadMessageW PrintWindow PrivateExtractIconExA PrivateExtractIconExW PrivateExtractIconsA
 PrivateExtractIconsW PrivateSetDbgTag PrivateSetRipFlags PtInRect QuerySendMessage QueryUserCounters RealChildWindowFromPoint RealGetWindowClass
 RealGetWindowClassA RealGetWindowClassW ReasonCodeNeedsBugID ReasonCodeNeedsComment RecordShutdownReason RedrawWindow RegisterClassA RegisterClassExA
 RegisterClassExW RegisterClassW RegisterClipboardFormatA RegisterClipboardFormatW RegisterDeviceNotificationA RegisterDeviceNotificationW RegisterHotKey
 RegisterLogonProcess RegisterMessagePumpHook RegisterRawInputDevices RegisterServicesProcess RegisterShellHookWindow RegisterSystemThread RegisterTasklist
 RegisterUserApiHook RegisterWindowMessageA RegisterWindowMessageW ReleaseCapture ReleaseDC RemoveMenu RemovePropA RemovePropW ReplyMessage ResolveDesktopForWOW
 ReuseDDElParam ScreenToClient ScrollChildren ScrollDC ScrollWindow ScrollWindowEx SendDlgItemMessageA SendDlgItemMessageW SendIMEMessageExA SendIMEMessageExW
 SendInput SendMessageA SendMessageCallbackA SendMessageCallbackW SendMessageTimeoutA SendMessageTimeoutW SendMessageW SendNotifyMessageA SendNotifyMessageW
 SetActiveWindow SetCapture SetCaretBlinkTime SetCaretPos SetClassLongA SetClassLongW SetClassWord SetClipboardData SetClipboardViewer SetConsoleReserveKeys
 SetCursor SetCursorContents SetCursorPos SetDebugErrorLevel SetDeskWallpaper SetDlgItemInt SetDlgItemTextA SetDlgItemTextW SetDoubleClickTime SetFocus
 SetForegroundWindow SetInternalWindowPos SetKeyboardState SetLastErrorEx SetLayeredWindowAttributes SetLogonNotifyWindow SetMenu SetMenuContextHelpId
 SetMenuDefaultItem SetMenuInfo SetMenuItemBitmaps SetMenuItemInfoA SetMenuItemInfoW SetMessageExtraInfo SetMessageQueue SetParent SetProcessDefaultLayout
 SetProcessWindowStation SetProgmanWindow SetPropA SetPropW SetRect SetRectEmpty SetScrollInfo SetScrollPos SetScrollRange SetShellWindow SetShellWindowEx
 SetSysColors SetSysColorsTemp SetSystemCursor SetSystemMenu SetSystemTimer SetTaskmanWindow SetThreadDesktop SetTimer SetUserObjectInformationA
 SetUserObjectInformationW SetUserObjectSecurity SetWinEventHook SetWindowContextHelpId SetWindowLongA SetWindowLongW SetWindowPlacement SetWindowPos
 SetWindowRgn SetWindowStationUser SetWindowTextA SetWindowTextW SetWindowWord SetWindowsHookA SetWindowsHookExA SetWindowsHookExW SetWindowsHookW ShowCaret
 ShowCursor ShowOwnedPopups ShowScrollBar ShowStartGlass ShowWindow ShowWindowAsync SoftModalMessageBox SubtractRect SwapMouseButton SwitchDesktop
 SwitchToThisWindow SystemParametersInfoA SystemParametersInfoW TabbedTextOutA TabbedTextOutW TileChildWindows TileWindows ToAscii ToAsciiEx ToUnicode
 ToUnicodeEx TrackMouseEvent TrackPopupMenu TrackPopupMenuEx TranslateAccelerator TranslateAcceleratorA TranslateAcceleratorW TranslateMDISysAccel
 TranslateMessage TranslateMessageEx UnhookWinEvent UnhookWindowsHook UnhookWindowsHookEx UnionRect UnloadKeyboardLayout UnlockWindowStation UnpackDDElParam
 UnregisterClassA UnregisterClassW UnregisterDeviceNotification UnregisterHotKey UnregisterMessagePumpHook UnregisterUserApiHook UpdateLayeredWindow
 UpdatePerUserSystemParameters UpdateWindow User32InitializeImmEntryTable UserClientDllInitialize UserHandleGrantAccess UserLpkPSMTextOut UserLpkTabbedTextOut
 UserRealizePalette UserRegisterWowHandlers VRipOutput VTagOutput ValidateRect ValidateRgn VkKeyScanA VkKeyScanExA VkKeyScanExW VkKeyScanW WCSToMBEx
 WINNLSEnableIME WINNLSGetEnableStatus WINNLSGetIMEHotkey WaitForInputIdle WaitMessage Win32PoolAllocationStats WinHelpA WinHelpW WindowFromDC WindowFromPoint
 keybd_event mouse_event wsprintfA wsprintfW wvsprintfA wvsprintfW
KERNEL32
 ActivateActCtx AddAtomA AddAtomW AddConsoleAliasA AddConsoleAliasW AddLocalAlternateComputerNameA AddLocalAlternateComputerNameW AddRefActCtx
 AddVectoredExceptionHandler AllocConsole AllocateUserPhysicalPages AreFileApisANSI AssignProcessToJobObject AttachConsole BackupRead BackupSeek BackupWrite
 BaseCheckAppcompatCache BaseCleanupAppcompatCache BaseCleanupAppcompatCacheSupport BaseDumpAppcompatCache BaseFlushAppcompatCache BaseInitAppcompatCache
 BaseInitAppcompatCacheSupport BaseProcessInitPostImport BaseQueryModuleData BaseUpdateAppcompatCache BasepCheckWinSaferRestrictions Beep BeginUpdateResourceA
 BeginUpdateResourceW BindIoCompletionCallback BuildCommDCBA BuildCommDCBAndTimeoutsA BuildCommDCBAndTimeoutsW BuildCommDCBW CallNamedPipeA CallNamedPipeW
 CancelDeviceWakeupRequest CancelIo CancelTimerQueueTimer CancelWaitableTimer ChangeTimerQueueTimer CheckNameLegalDOS8Dot3A CheckNameLegalDOS8Dot3W
 CheckRemoteDebuggerPresent ClearCommBreak ClearCommError CloseConsoleHandle CloseHandle CloseProfileUserMapping CmdBatNotification CommConfigDialogA
 CommConfigDialogW CompareFileTime CompareStringA CompareStringW ConnectNamedPipe ConsoleMenuControl ContinueDebugEvent ConvertDefaultLocale
 ConvertFiberToThread ConvertThreadToFiber CopyFileA CopyFileExA CopyFileExW CopyFileW CopyLZFile CreateActCtxA CreateActCtxW CreateConsoleScreenBuffer
 CreateDirectoryA CreateDirectoryExA CreateDirectoryExW CreateDirectoryW CreateEventA CreateEventW CreateFiber CreateFiberEx CreateFileA CreateFileMappingA
 CreateFileMappingW CreateFileW CreateHardLinkA CreateHardLinkW CreateIoCompletionPort CreateJobObjectA CreateJobObjectW CreateJobSet CreateMailslotA
 CreateMailslotW CreateMemoryResourceNotification CreateMutexA CreateMutexW CreateNamedPipeA CreateNamedPipeW CreateNlsSecurityDescriptor CreatePipe
 CreateProcessA CreateProcessInternalA CreateProcessInternalW CreateProcessInternalWSecure CreateProcessW CreateRemoteThread CreateSemaphoreA CreateSemaphoreW
 CreateSocketHandle CreateTapePartition CreateThread CreateTimerQueue CreateTimerQueueTimer CreateToolhelp32Snapshot CreateVirtualBuffer CreateWaitableTimerA
 CreateWaitableTimerW DeactivateActCtx DebugActiveProcess DebugActiveProcessStop DebugBreak DebugBreakProcess DebugSetProcessKillOnExit DecodePointer
 DecodeSystemPointer DefineDosDeviceA DefineDosDeviceW DelayLoadFailureHook DeleteAtom DeleteCriticalSection DeleteFiber DeleteFileA DeleteFileW
 DeleteTimerQueue DeleteTimerQueueEx DeleteTimerQueueTimer DeleteVolumeMountPointA DeleteVolumeMountPointW DeviceIoControl DisableThreadLibraryCalls
 DisconnectNamedPipe DnsHostnameToComputerNameA DnsHostnameToComputerNameW DosDateTimeToFileTime DosPathToSessionPathA DosPathToSessionPathW
 DuplicateConsoleHandle DuplicateHandle EncodePointer EncodeSystemPointer EndUpdateResourceA EndUpdateResourceW EnterCriticalSection EnumCalendarInfoA
 EnumCalendarInfoExA EnumCalendarInfoExW EnumCalendarInfoW EnumDateFormatsA EnumDateFormatsExA EnumDateFormatsExW EnumDateFormatsW EnumLanguageGroupLocalesA
 EnumLanguageGroupLocalesW EnumResourceLanguagesA EnumResourceLanguagesW EnumResourceNamesA EnumResourceNamesW EnumResourceTypesA EnumResourceTypesW
 EnumSystemCodePagesA EnumSystemCodePagesW EnumSystemGeoID EnumSystemLanguageGroupsA EnumSystemLanguageGroupsW EnumSystemLocalesA EnumSystemLocalesW
 EnumTimeFormatsA EnumTimeFormatsW EnumUILanguagesA EnumUILanguagesW EnumerateLocalComputerNamesA EnumerateLocalComputerNamesW EraseTape EscapeCommFunction
 ExitProcess ExitThread ExitVDM ExpandEnvironmentStringsA ExpandEnvironmentStringsW ExpungeConsoleCommandHistoryA ExpungeConsoleCommandHistoryW
 ExtendVirtualBuffer FatalAppExitA FatalAppExitW FatalExit FileTimeToDosDateTime FileTimeToLocalFileTime FileTimeToSystemTime FillConsoleOutputAttribute
 FillConsoleOutputCharacterA FillConsoleOutputCharacterW FindActCtxSectionGuid FindActCtxSectionStringA FindActCtxSectionStringW FindAtomA FindAtomW FindClose
 FindCloseChangeNotification FindFirstChangeNotificationA FindFirstChangeNotificationW FindFirstFileA FindFirstFileExA FindFirstFileExW FindFirstFileW
 FindFirstVolumeA FindFirstVolumeMountPointA FindFirstVolumeMountPointW FindFirstVolumeW FindNextChangeNotification FindNextFileA FindNextFileW FindNextVolumeA
 FindNextVolumeMountPointA FindNextVolumeMountPointW FindNextVolumeW FindResourceA FindResourceExA FindResourceExW FindResourceW FindVolumeClose
 FindVolumeMountPointClose FlushConsoleInputBuffer FlushFileBuffers FlushInstructionCache FlushViewOfFile FoldStringA FoldStringW FormatMessageA FormatMessageW
 FreeConsole FreeEnvironmentStringsA FreeEnvironmentStringsW FreeLibrary FreeLibraryAndExitThread FreeResource FreeUserPhysicalPages FreeVirtualBuffer
 GenerateConsoleCtrlEvent GetACP GetAtomNameA GetAtomNameW GetBinaryType GetBinaryTypeA GetBinaryTypeW GetCPFileNameFromRegistry GetCPInfo GetCPInfoExA
 GetCPInfoExW GetCalendarInfoA GetCalendarInfoW GetComPlusPackageInstallStatus GetCommConfig GetCommMask GetCommModemStatus GetCommProperties GetCommState
 GetCommTimeouts GetCommandLineA GetCommandLineW GetCompressedFileSizeA GetCompressedFileSizeW GetComputerNameA GetComputerNameExA GetComputerNameExW
 GetComputerNameW GetConsoleAliasA GetConsoleAliasExesA GetConsoleAliasExesLengthA GetConsoleAliasExesLengthW GetConsoleAliasExesW GetConsoleAliasW
 GetConsoleAliasesA GetConsoleAliasesLengthA GetConsoleAliasesLengthW GetConsoleAliasesW GetConsoleCP GetConsoleCharType GetConsoleCommandHistoryA
 GetConsoleCommandHistoryLengthA GetConsoleCommandHistoryLengthW GetConsoleCommandHistoryW GetConsoleCursorInfo GetConsoleCursorMode GetConsoleDisplayMode
 GetConsoleFontInfo GetConsoleFontSize GetConsoleHardwareState GetConsoleInputExeNameA GetConsoleInputExeNameW GetConsoleInputWaitHandle
 GetConsoleKeyboardLayoutNameA GetConsoleKeyboardLayoutNameW GetConsoleMode GetConsoleNlsMode GetConsoleOutputCP GetConsoleProcessList
 GetConsoleScreenBufferInfo GetConsoleSelectionInfo GetConsoleTitleA GetConsoleTitleW GetConsoleWindow GetCurrencyFormatA GetCurrencyFormatW GetCurrentActCtx
 GetCurrentConsoleFont GetCurrentDirectoryA GetCurrentDirectoryW GetCurrentProcess GetCurrentProcessId GetCurrentThread GetCurrentThreadId GetDateFormatA
 GetDateFormatW GetDefaultCommConfigA GetDefaultCommConfigW GetDefaultSortkeySize GetDevicePowerState GetDiskFreeSpaceA GetDiskFreeSpaceExA GetDiskFreeSpaceExW
 GetDiskFreeSpaceW GetDllDirectoryA GetDllDirectoryW GetDriveTypeA GetDriveTypeW GetEnvironmentStrings GetEnvironmentStringsA GetEnvironmentStringsW
 GetEnvironmentVariableA GetEnvironmentVariableW GetExitCodeProcess GetExitCodeThread GetExpandedNameA GetExpandedNameW GetFileAttributesA GetFileAttributesExA
 GetFileAttributesExW GetFileAttributesW GetFileInformationByHandle GetFileSize GetFileSizeEx GetFileTime GetFileType GetFirmwareEnvironmentVariableA
 GetFirmwareEnvironmentVariableW GetFullPathNameA GetFullPathNameW GetGeoInfoA GetGeoInfoW GetHandleContext GetHandleInformation GetLargestConsoleWindowSize
 GetLastError GetLinguistLangSize GetLocalTime GetLocaleInfoA GetLocaleInfoW GetLogicalDriveStringsA GetLogicalDriveStringsW GetLogicalDrives GetLongPathNameA
 GetLongPathNameW GetMailslotInfo GetModuleFileNameA GetModuleFileNameW GetModuleHandleA GetModuleHandleExA GetModuleHandleExW GetModuleHandleW
 GetNamedPipeHandleStateA GetNamedPipeHandleStateW GetNamedPipeInfo GetNativeSystemInfo GetNextVDMCommand GetNlsSectionName GetNumaAvailableMemory
 GetNumaAvailableMemoryNode GetNumaHighestNodeNumber GetNumaNodeProcessorMask GetNumaProcessorMap GetNumaProcessorNode GetNumberFormatA GetNumberFormatW
 GetNumberOfConsoleFonts GetNumberOfConsoleInputEvents GetNumberOfConsoleMouseButtons GetOEMCP GetOverlappedResult GetPriorityClass GetPrivateProfileIntA
 GetPrivateProfileIntW GetPrivateProfileSectionA GetPrivateProfileSectionNamesA GetPrivateProfileSectionNamesW GetPrivateProfileSectionW
 GetPrivateProfileStringA GetPrivateProfileStringW GetPrivateProfileStructA GetPrivateProfileStructW GetProcAddress GetProcessAffinityMask GetProcessHandleCount
 GetProcessHeap GetProcessHeaps GetProcessId GetProcessIoCounters GetProcessPriorityBoost GetProcessShutdownParameters GetProcessTimes GetProcessVersion
 GetProcessWorkingSetSize GetProfileIntA GetProfileIntW GetProfileSectionA GetProfileSectionW GetProfileStringA GetProfileStringW GetQueuedCompletionStatus
 GetShortPathNameA GetShortPathNameW GetStartupInfoA GetStartupInfoW GetStdHandle GetStringTypeA GetStringTypeExA GetStringTypeExW GetStringTypeW
 GetSystemDefaultLCID GetSystemDefaultLangID GetSystemDefaultUILanguage GetSystemDirectoryA GetSystemDirectoryW GetSystemInfo GetSystemPowerStatus
 GetSystemRegistryQuota GetSystemTime GetSystemTimeAdjustment GetSystemTimeAsFileTime GetSystemTimes GetSystemWindowsDirectoryA GetSystemWindowsDirectoryW
 GetSystemWow64DirectoryA GetSystemWow64DirectoryW GetTapeParameters GetTapePosition GetTapeStatus GetTempFileNameA GetTempFileNameW GetTempPathA GetTempPathW
 GetThreadContext GetThreadIOPendingFlag GetThreadLocale GetThreadPriority GetThreadPriorityBoost GetThreadSelectorEntry GetThreadTimes GetTickCount
 GetTimeFormatA GetTimeFormatW GetTimeZoneInformation GetUserDefaultLCID GetUserDefaultLangID GetUserDefaultUILanguage GetUserGeoID GetVDMCurrentDirectories
 GetVersion GetVersionExA GetVersionExW GetVolumeInformationA GetVolumeInformationW GetVolumeNameForVolumeMountPointA GetVolumeNameForVolumeMountPointW
 GetVolumePathNameA GetVolumePathNameW GetVolumePathNamesForVolumeNameA GetVolumePathNamesForVolumeNameW GetWindowsDirectoryA GetWindowsDirectoryW GetWriteWatch
 GlobalAddAtomA GlobalAddAtomW GlobalAlloc GlobalCompact GlobalDeleteAtom GlobalFindAtomA GlobalFindAtomW GlobalFix GlobalFlags GlobalFree GlobalGetAtomNameA
 GlobalGetAtomNameW GlobalHandle GlobalLock GlobalMemoryStatus GlobalMemoryStatusEx GlobalReAlloc GlobalSize GlobalUnWire GlobalUnfix GlobalUnlock GlobalWire
 Heap32First Heap32ListFirst Heap32ListNext Heap32Next HeapAlloc HeapCompact HeapCreate HeapCreateTagsW HeapDestroy HeapExtend HeapFree HeapLock
 HeapQueryInformation HeapQueryTagW HeapReAlloc HeapSetInformation HeapSize HeapSummary HeapUnlock HeapUsage HeapValidate HeapWalk InitAtomTable
 InitializeCriticalSection InitializeCriticalSectionAndSpinCount InitializeSListHead InterlockedCompareExchange InterlockedDecrement InterlockedExchange
 InterlockedExchangeAdd InterlockedFlushSList InterlockedIncrement InterlockedPopEntrySList InterlockedPushEntrySList InvalidateConsoleDIBits IsBadCodePtr
 IsBadHugeReadPtr IsBadHugeWritePtr IsBadReadPtr IsBadStringPtrA IsBadStringPtrW IsBadWritePtr IsDBCSLeadByte IsDBCSLeadByteEx IsDebuggerPresent IsProcessInJob
 IsProcessorFeaturePresent IsSystemResumeAutomatic IsValidCodePage IsValidLanguageGroup IsValidLocale IsValidUILanguage IsWow64Process LCMapStringA LCMapStringW
 LZClose LZCloseFile LZCopy LZCreateFileW LZDone LZInit LZOpenFileA LZOpenFileW LZRead LZSeek LZStart LeaveCriticalSection LoadLibraryA LoadLibraryExA
 LoadLibraryExW LoadLibraryW LoadModule LoadResource LocalAlloc LocalCompact LocalFileTimeToFileTime LocalFlags LocalFree LocalHandle LocalLock LocalReAlloc
 LocalShrink LocalSize LocalUnlock LockFile LockFileEx LockResource MapUserPhysicalPages MapUserPhysicalPagesScatter MapViewOfFile MapViewOfFileEx Module32First
 Module32FirstW Module32Next Module32NextW MoveFileA MoveFileExA MoveFileExW MoveFileW MoveFileWithProgressA MoveFileWithProgressW MulDiv MultiByteToWideChar
 NlsConvertIntegerToString NlsGetCacheUpdateCount NlsResetProcessLocale NumaVirtualQueryNode OpenConsoleW OpenDataFile OpenEventA OpenEventW OpenFile
 OpenFileMappingA OpenFileMappingW OpenJobObjectA OpenJobObjectW OpenMutexA OpenMutexW OpenProcess OpenProfileUserMapping OpenSemaphoreA OpenSemaphoreW
 OpenThread OpenWaitableTimerA OpenWaitableTimerW OutputDebugStringA OutputDebugStringW PeekConsoleInputA PeekConsoleInputW PeekNamedPipe
 PostQueuedCompletionStatus PrepareTape PrivCopyFileExW PrivMoveFileIdentityW Process32First Process32FirstW Process32Next Process32NextW ProcessIdToSessionId
 PulseEvent PurgeComm QueryActCtxW QueryDepthSList QueryDosDeviceA QueryDosDeviceW QueryInformationJobObject QueryMemoryResourceNotification
 QueryPerformanceCounter QueryPerformanceFrequency QueryWin31IniFilesMappedToRegistry QueueUserAPC QueueUserWorkItem RaiseException ReadConsoleA
 ReadConsoleInputA ReadConsoleInputExA ReadConsoleInputExW ReadConsoleInputW ReadConsoleOutputA ReadConsoleOutputAttribute ReadConsoleOutputCharacterA
 ReadConsoleOutputCharacterW ReadConsoleOutputW ReadConsoleW ReadDirectoryChangesW ReadFile ReadFileEx ReadFileScatter ReadProcessMemory RegisterConsoleIME
 RegisterConsoleOS2 RegisterConsoleVDM RegisterWaitForInputIdle RegisterWaitForSingleObject RegisterWaitForSingleObjectEx RegisterWowBaseHandlers
 RegisterWowExec ReleaseActCtx ReleaseMutex ReleaseSemaphore RemoveDirectoryA RemoveDirectoryW RemoveLocalAlternateComputerNameA
 RemoveLocalAlternateComputerNameW RemoveVectoredExceptionHandler ReplaceFile ReplaceFileA ReplaceFileW RequestDeviceWakeup RequestWakeupLatency ResetEvent
 ResetWriteWatch RestoreLastError ResumeThread RtlCaptureContext RtlCaptureStackBackTrace RtlFillMemory RtlMoveMemory RtlUnwind RtlZeroMemory
 ScrollConsoleScreenBufferA ScrollConsoleScreenBufferW SearchPathA SearchPathW SetCPGlobal SetCalendarInfoA SetCalendarInfoW SetClientTimeZoneInformation
 SetComPlusPackageInstallStatus SetCommBreak SetCommConfig SetCommMask SetCommState SetCommTimeouts SetComputerNameA SetComputerNameExA SetComputerNameExW
 SetComputerNameW SetConsoleActiveScreenBuffer SetConsoleCP SetConsoleCommandHistoryMode SetConsoleCtrlHandler SetConsoleCursor SetConsoleCursorInfo
 SetConsoleCursorMode SetConsoleCursorPosition SetConsoleDisplayMode SetConsoleFont SetConsoleHardwareState SetConsoleIcon SetConsoleInputExeNameA
 SetConsoleInputExeNameW SetConsoleKeyShortcuts SetConsoleLocalEUDC SetConsoleMaximumWindowSize SetConsoleMenuClose SetConsoleMode SetConsoleNlsMode
 SetConsoleNumberOfCommandsA SetConsoleNumberOfCommandsW SetConsoleOS2OemFormat SetConsoleOutputCP SetConsolePalette SetConsoleScreenBufferSize
 SetConsoleTextAttribute SetConsoleTitleA SetConsoleTitleW SetConsoleWindowInfo SetCriticalSectionSpinCount SetCurrentDirectoryA SetCurrentDirectoryW
 SetDefaultCommConfigA SetDefaultCommConfigW SetDllDirectoryA SetDllDirectoryW SetEndOfFile SetEnvironmentVariableA SetEnvironmentVariableW SetErrorMode
 SetEvent SetFileApisToANSI SetFileApisToOEM SetFileAttributesA SetFileAttributesW SetFilePointer SetFilePointerEx SetFileShortNameA SetFileShortNameW
 SetFileTime SetFileValidData SetFirmwareEnvironmentVariableA SetFirmwareEnvironmentVariableW SetHandleContext SetHandleCount SetHandleInformation
 SetInformationJobObject SetLastConsoleEventActive SetLastError SetLocalPrimaryComputerNameA SetLocalPrimaryComputerNameW SetLocalTime SetLocaleInfoA
 SetLocaleInfoW SetMailslotInfo SetMessageWaitingIndicator SetNamedPipeHandleState SetPriorityClass SetProcessAffinityMask SetProcessPriorityBoost
 SetProcessShutdownParameters SetProcessWorkingSetSize SetStdHandle SetSystemPowerState SetSystemTime SetSystemTimeAdjustment SetTapeParameters SetTapePosition
 SetTermsrvAppInstallMode SetThreadAffinityMask SetThreadContext SetThreadExecutionState SetThreadIdealProcessor SetThreadLocale SetThreadPriority
 SetThreadPriorityBoost SetThreadUILanguage SetTimeZoneInformation SetTimerQueueTimer SetUnhandledExceptionFilter SetUserGeoID SetVDMCurrentDirectories
 SetVolumeLabelA SetVolumeLabelW SetVolumeMountPointA SetVolumeMountPointW SetWaitableTimer SetupComm ShowConsoleCursor SignalObjectAndWait SizeofResource Sleep
 SleepEx SuspendThread SwitchToFiber SwitchToThread SystemTimeToFileTime SystemTimeToTzSpecificLocalTime TerminateJobObject TerminateProcess TerminateThread
 TermsrvAppInstallMode Thread32First Thread32Next TlsAlloc TlsFree TlsGetValue TlsSetValue Toolhelp32ReadProcessMemory TransactNamedPipe TransmitCommChar
 TrimVirtualBuffer TryEnterCriticalSection TzSpecificLocalTimeToSystemTime UTRegister UTUnRegister UnhandledExceptionFilter UnlockFile UnlockFileEx
 UnmapViewOfFile UnregisterConsoleIME UnregisterWait UnregisterWaitEx UpdateResourceA UpdateResourceW VDMConsoleOperation VDMOperationStarted ValidateLCType
 ValidateLocale VerLanguageNameA VerLanguageNameW VerSetConditionMask VerifyConsoleIoHandle VerifyVersionInfoA VerifyVersionInfoW VirtualAlloc VirtualAllocEx
 VirtualBufferExceptionHandler VirtualFree VirtualFreeEx VirtualLock VirtualProtect VirtualProtectEx VirtualQuery VirtualQueryEx VirtualUnlock
 WTSGetActiveConsoleSessionId WaitCommEvent WaitForDebugEvent WaitForMultipleObjects WaitForMultipleObjectsEx WaitForSingleObject WaitForSingleObjectEx
 WaitNamedPipeA WaitNamedPipeW WideCharToMultiByte WinExec WriteConsoleA WriteConsoleInputA WriteConsoleInputVDMA WriteConsoleInputVDMW WriteConsoleInputW
 WriteConsoleOutputA WriteConsoleOutputAttribute WriteConsoleOutputCharacterA WriteConsoleOutputCharacterW WriteConsoleOutputW WriteConsoleW WriteFile
 WriteFileEx WriteFileGather WritePrivateProfileSectionA WritePrivateProfileSectionW WritePrivateProfileStringA WritePrivateProfileStringW
 WritePrivateProfileStructA WritePrivateProfileStructW WriteProcessMemory WriteProfileSectionA WriteProfileSectionW WriteProfileStringA WriteProfileStringW
 WriteTapemark ZombifyActCtx _hread _hwrite _lclose _lcreat _llseek _lopen _lread _lwrite lstrcat lstrcatA lstrcatW lstrcmp lstrcmpA lstrcmpW lstrcmpi lstrcmpiA
 lstrcmpiW lstrcpy lstrcpyA lstrcpyW lstrcpyn lstrcpynA lstrcpynW lstrlen lstrlenA lstrlenW
ntdll
 PropertyLengthAsVariant RtlConvertPropertyToVariant RtlConvertVariantToProperty RtlInterlockedPushListSList RtlUlongByteSwap RtlUlonglongByteSwap
 RtlUshortByteSwap CsrAllocateCaptureBuffer CsrAllocateMessagePointer CsrCaptureMessageBuffer CsrCaptureMessageMultiUnicodeStringsInPlace
 CsrCaptureMessageString CsrCaptureTimeout CsrClientCallServer CsrClientConnectToServer CsrFreeCaptureBuffer CsrGetProcessId CsrIdentifyAlertableThread
 CsrNewThread CsrProbeForRead CsrProbeForWrite CsrSetPriorityClass DbgBreakPoint DbgPrint DbgPrintEx DbgPrintReturnControlC DbgPrompt DbgQueryDebugFilterState
 DbgSetDebugFilterState DbgUiConnectToDbg DbgUiContinue DbgUiConvertStateChangeStructure DbgUiDebugActiveProcess DbgUiGetThreadDebugObject
 DbgUiIssueRemoteBreakin DbgUiRemoteBreakin DbgUiSetThreadDebugObject DbgUiStopDebugging DbgUiWaitStateChange DbgUserBreakPoint KiFastSystemCall
 KiFastSystemCallRet KiIntSystemCall KiRaiseUserExceptionDispatcher KiUserApcDispatcher KiUserCallbackDispatcher KiUserExceptionDispatcher
 LdrAccessOutOfProcessResource LdrAccessResource LdrAddRefDll LdrAlternateResourcesEnabled LdrCreateOutOfProcessImage LdrDestroyOutOfProcessImage
 LdrDisableThreadCalloutsForDll LdrEnumResources LdrEnumerateLoadedModules LdrFindCreateProcessManifest LdrFindEntryForAddress LdrFindResourceDirectory_U
 LdrFindResourceEx_U LdrFindResource_U LdrFlushAlternateResourceModules LdrGetDllHandle LdrGetDllHandleEx LdrGetProcedureAddress LdrHotPatchRoutine
 LdrInitShimEngineDynamic LdrInitializeThunk LdrLoadAlternateResourceModule LdrLoadDll LdrLockLoaderLock LdrProcessRelocationBlock
 LdrQueryImageFileExecutionOptions LdrQueryProcessModuleInformation LdrSetAppCompatDllRedirectionCallback LdrSetDllManifestProber LdrShutdownProcess
 LdrShutdownThread LdrUnloadAlternateResourceModule LdrUnloadDll LdrUnlockLoaderLock LdrVerifyImageMatchesChecksum NlsAnsiCodePage NlsMbCodePageTag
 NlsMbOemCodePageTag NtAcceptConnectPort NtAccessCheck NtAccessCheckAndAuditAlarm NtAccessCheckByType NtAccessCheckByTypeAndAuditAlarm
 NtAccessCheckByTypeResultList NtAccessCheckByTypeResultListAndAuditAlarm NtAccessCheckByTypeResultListAndAuditAlarmByHandle NtAddAtom NtAddBootEntry
 NtAdjustGroupsToken NtAdjustPrivilegesToken NtAlertResumeThread NtAlertThread NtAllocateLocallyUniqueId NtAllocateUserPhysicalPages NtAllocateUuids
 NtAllocateVirtualMemory NtAreMappedFilesTheSame NtAssignProcessToJobObject NtCallbackReturn NtCancelDeviceWakeupRequest NtCancelIoFile NtCancelTimer
 NtClearEvent NtClose NtCloseObjectAuditAlarm NtCompactKeys NtCompareTokens NtCompleteConnectPort NtCompressKey NtConnectPort NtContinue NtCreateDebugObject
 NtCreateDirectoryObject NtCreateEvent NtCreateEventPair NtCreateFile NtCreateIoCompletion NtCreateJobObject NtCreateJobSet NtCreateKey NtCreateKeyedEvent
 NtCreateMailslotFile NtCreateMutant NtCreateNamedPipeFile NtCreatePagingFile NtCreatePort NtCreateProcess NtCreateProcessEx NtCreateProfile NtCreateSection
 NtCreateSemaphore NtCreateSymbolicLinkObject NtCreateThread NtCreateTimer NtCreateToken NtCreateWaitablePort NtCurrentTeb NtDebugActiveProcess NtDebugContinue
 NtDelayExecution NtDeleteAtom NtDeleteBootEntry NtDeleteFile NtDeleteKey NtDeleteObjectAuditAlarm NtDeleteValueKey NtDeviceIoControlFile NtDisplayString
 NtDuplicateObject NtDuplicateToken NtEnumerateBootEntries NtEnumerateKey NtEnumerateSystemEnvironmentValuesEx NtEnumerateValueKey NtExtendSection NtFilterToken
 NtFindAtom NtFlushBuffersFile NtFlushInstructionCache NtFlushKey NtFlushVirtualMemory NtFlushWriteBuffer NtFreeUserPhysicalPages NtFreeVirtualMemory
 NtFsControlFile NtGetContextThread NtGetDevicePowerState NtGetPlugPlayEvent NtGetWriteWatch NtImpersonateAnonymousToken NtImpersonateClientOfPort
 NtImpersonateThread NtInitializeRegistry NtInitiatePowerAction NtIsProcessInJob NtIsSystemResumeAutomatic NtListenPort NtLoadDriver NtLoadKey2 NtLoadKey
 NtLockFile NtLockProductActivationKeys NtLockRegistryKey NtLockVirtualMemory NtMakePermanentObject NtMakeTemporaryObject NtMapUserPhysicalPages
 NtMapUserPhysicalPagesScatter NtMapViewOfSection NtModifyBootEntry NtNotifyChangeDirectoryFile NtNotifyChangeKey NtNotifyChangeMultipleKeys
 NtOpenDirectoryObject NtOpenEvent NtOpenEventPair NtOpenFile NtOpenIoCompletion NtOpenJobObject NtOpenKey NtOpenKeyedEvent NtOpenMutant NtOpenObjectAuditAlarm
 NtOpenProcess NtOpenProcessToken NtOpenProcessTokenEx NtOpenSection NtOpenSemaphore NtOpenSymbolicLinkObject NtOpenThread NtOpenThreadToken NtOpenThreadTokenEx
 NtOpenTimer NtPlugPlayControl NtPowerInformation NtPrivilegeCheck NtPrivilegeObjectAuditAlarm NtPrivilegedServiceAuditAlarm NtProtectVirtualMemory NtPulseEvent
 NtQueryAttributesFile NtQueryBootEntryOrder NtQueryBootOptions NtQueryDebugFilterState NtQueryDefaultLocale NtQueryDefaultUILanguage NtQueryDirectoryFile
 NtQueryDirectoryObject NtQueryEaFile NtQueryEvent NtQueryFullAttributesFile NtQueryInformationAtom NtQueryInformationFile NtQueryInformationJobObject
 NtQueryInformationPort NtQueryInformationProcess NtQueryInformationThread NtQueryInformationToken NtQueryInstallUILanguage NtQueryIntervalProfile
 NtQueryIoCompletion NtQueryKey NtQueryMultipleValueKey NtQueryMutant NtQueryObject NtQueryOpenSubKeys NtQueryPerformanceCounter NtQueryPortInformationProcess
 NtQueryQuotaInformationFile NtQuerySection NtQuerySecurityObject NtQuerySemaphore NtQuerySymbolicLinkObject NtQuerySystemEnvironmentValue
 NtQuerySystemEnvironmentValueEx NtQuerySystemInformation NtQuerySystemTime NtQueryTimer NtQueryTimerResolution NtQueryValueKey NtQueryVirtualMemory
 NtQueryVolumeInformationFile NtQueueApcThread NtRaiseException NtRaiseHardError NtReadFile NtReadFileScatter NtReadRequestData NtReadVirtualMemory
 NtRegisterThreadTerminatePort NtReleaseKeyedEvent NtReleaseMutant NtReleaseSemaphore NtRemoveIoCompletion NtRemoveProcessDebug NtRenameKey NtReplaceKey
 NtReplyPort NtReplyWaitReceivePort NtReplyWaitReceivePortEx NtReplyWaitReplyPort NtRequestDeviceWakeup NtRequestPort NtRequestWaitReplyPort
 NtRequestWakeupLatency NtResetEvent NtResetWriteWatch NtRestoreKey NtResumeProcess NtResumeThread NtSaveKey NtSaveKeyEx NtSaveMergedKeys NtSecureConnectPort
 NtSetBootEntryOrder NtSetBootOptions NtSetContextThread NtSetDebugFilterState NtSetDefaultHardErrorPort NtSetDefaultLocale NtSetDefaultUILanguage NtSetEaFile
 NtSetEvent NtSetEventBoostPriority NtSetHighEventPair NtSetHighWaitLowEventPair NtSetInformationDebugObject NtSetInformationFile NtSetInformationJobObject
 NtSetInformationKey NtSetInformationObject NtSetInformationProcess NtSetInformationThread NtSetInformationToken NtSetIntervalProfile NtSetIoCompletion
 NtSetLdtEntries NtSetLowEventPair NtSetLowWaitHighEventPair NtSetQuotaInformationFile NtSetSecurityObject NtSetSystemEnvironmentValue
 NtSetSystemEnvironmentValueEx NtSetSystemInformation NtSetSystemPowerState NtSetSystemTime NtSetThreadExecutionState NtSetTimer NtSetTimerResolution
 NtSetUuidSeed NtSetValueKey NtSetVolumeInformationFile NtShutdownSystem NtSignalAndWaitForSingleObject NtStartProfile NtStopProfile NtSuspendProcess
 NtSuspendThread NtSystemDebugControl NtTerminateJobObject NtTerminateProcess NtTerminateThread NtTestAlert NtTraceEvent NtTranslateFilePath NtUnloadDriver
 NtUnloadKey NtUnloadKeyEx NtUnlockFile NtUnlockVirtualMemory NtUnmapViewOfSection NtVdmControl NtWaitForDebugEvent NtWaitForKeyedEvent NtWaitForMultipleObjects
 NtWaitForSingleObject NtWaitHighEventPair NtWaitLowEventPair NtWriteFile NtWriteFileGather NtWriteRequestData NtWriteVirtualMemory NtYieldExecution
 PfxFindPrefix PfxInitialize PfxInsertPrefix PfxRemovePrefix RtlAbortRXact RtlAbsoluteToSelfRelativeSD RtlAcquirePebLock RtlAcquireResourceExclusive
 RtlAcquireResourceShared RtlActivateActivationContext RtlActivateActivationContextEx RtlActivateActivationContextUnsafeFast RtlAddAccessAllowedAce
 RtlAddAccessAllowedAceEx RtlAddAccessAllowedObjectAce RtlAddAccessDeniedAce RtlAddAccessDeniedAceEx RtlAddAccessDeniedObjectAce RtlAddAce RtlAddActionToRXact
 RtlAddAtomToAtomTable RtlAddAttributeActionToRXact RtlAddAuditAccessAce RtlAddAuditAccessAceEx RtlAddAuditAccessObjectAce RtlAddCompoundAce RtlAddRange
 RtlAddRefActivationContext RtlAddRefMemoryStream RtlAddVectoredExceptionHandler RtlAddressInSectionTable RtlAdjustPrivilege RtlAllocateAndInitializeSid
 RtlAllocateHandle RtlAllocateHeap RtlAnsiCharToUnicodeChar RtlAnsiStringToUnicodeSize RtlAnsiStringToUnicodeString RtlAppendAsciizToString RtlAppendPathElement
 RtlAppendStringToString RtlAppendUnicodeStringToString RtlAppendUnicodeToString RtlApplicationVerifierStop RtlApplyRXact RtlApplyRXactNoFlush
 RtlAreAllAccessesGranted RtlAreAnyAccessesGranted RtlAreBitsClear RtlAreBitsSet RtlAssert2 RtlAssert RtlCancelTimer RtlCaptureContext RtlCaptureStackBackTrace
 RtlCaptureStackContext RtlCharToInteger RtlCheckForOrphanedCriticalSections RtlCheckProcessParameters RtlCheckRegistryKey RtlClearAllBits RtlClearBits
 RtlCloneMemoryStream RtlCommitMemoryStream RtlCompactHeap RtlCompareMemory RtlCompareMemoryUlong RtlCompareString RtlCompareUnicodeString RtlCompressBuffer
 RtlComputeCrc32 RtlComputeImportTableHash RtlComputePrivatizedDllName_U RtlConsoleMultiByteToUnicodeN RtlConvertExclusiveToShared RtlConvertLongToLargeInteger
 RtlConvertSharedToExclusive RtlConvertSidToUnicodeString RtlConvertToAutoInheritSecurityObject RtlConvertUiListToApiList RtlConvertUlongToLargeInteger
 RtlCopyLuid RtlCopyLuidAndAttributesArray RtlCopyMemoryStreamTo RtlCopyOutOfProcessMemoryStreamTo RtlCopyRangeList RtlCopySecurityDescriptor RtlCopySid
 RtlCopySidAndAttributesArray RtlCopyString RtlCopyUnicodeString RtlCreateAcl RtlCreateActivationContext RtlCreateAndSetSD RtlCreateAtomTable
 RtlCreateBootStatusDataFile RtlCreateEnvironment RtlCreateHeap RtlCreateProcessParameters RtlCreateQueryDebugBuffer RtlCreateRegistryKey
 RtlCreateSecurityDescriptor RtlCreateSystemVolumeInformationFolder RtlCreateTagHeap RtlCreateTimer RtlCreateTimerQueue RtlCreateUnicodeString
 RtlCreateUnicodeStringFromAsciiz RtlCreateUserProcess RtlCreateUserSecurityObject RtlCreateUserThread RtlCustomCPToUnicodeN RtlCutoverTimeToSystemTime
 RtlDeNormalizeProcessParams RtlDeactivateActivationContext RtlDeactivateActivationContextUnsafeFast RtlDebugPrintTimes RtlDecodePointer RtlDecodeSystemPointer
 RtlDecompressBuffer RtlDecompressFragment RtlDefaultNpAcl RtlDelete RtlDeleteAce RtlDeleteAtomFromAtomTable RtlDeleteCriticalSection
 RtlDeleteElementGenericTable RtlDeleteElementGenericTableAvl RtlDeleteNoSplay RtlDeleteOwnersRanges RtlDeleteRange RtlDeleteRegistryValue RtlDeleteResource
 RtlDeleteSecurityObject RtlDeleteTimer RtlDeleteTimerQueue RtlDeleteTimerQueueEx RtlDeregisterWait RtlDeregisterWaitEx RtlDestroyAtomTable
 RtlDestroyEnvironment RtlDestroyHandleTable RtlDestroyHeap RtlDestroyProcessParameters RtlDestroyQueryDebugBuffer RtlDetermineDosPathNameType_U
 RtlDllShutdownInProgress RtlDnsHostNameToComputerName RtlDoesFileExists_U RtlDosApplyFileIsolationRedirection_Ustr RtlDosPathNameToNtPathName_U
 RtlDosSearchPath_U RtlDosSearchPath_Ustr RtlDowncaseUnicodeChar RtlDowncaseUnicodeString RtlDumpResource RtlDuplicateUnicodeString RtlEmptyAtomTable
 RtlEnableEarlyCriticalSectionEventCreation RtlEncodePointer RtlEncodeSystemPointer RtlEnlargedIntegerMultiply RtlEnlargedUnsignedDivide
 RtlEnlargedUnsignedMultiply RtlEnterCriticalSection RtlEnumProcessHeaps RtlEnumerateGenericTable RtlEnumerateGenericTableAvl
 RtlEnumerateGenericTableLikeADirectory RtlEnumerateGenericTableWithoutSplaying RtlEnumerateGenericTableWithoutSplayingAvl RtlEqualComputerName
 RtlEqualDomainName RtlEqualLuid RtlEqualPrefixSid RtlEqualSid RtlEqualString RtlEqualUnicodeString RtlEraseUnicodeString RtlExitUserThread
 RtlExpandEnvironmentStrings_U RtlExtendHeap RtlExtendedIntegerMultiply RtlExtendedLargeIntegerDivide RtlExtendedMagicDivide RtlFillMemory RtlFillMemoryUlong
 RtlFinalReleaseOutOfProcessMemoryStream RtlFindActivationContextSectionGuid RtlFindActivationContextSectionString RtlFindCharInUnicodeString RtlFindClearBits
 RtlFindClearBitsAndSet RtlFindClearRuns RtlFindLastBackwardRunClear RtlFindLeastSignificantBit RtlFindLongestRunClear RtlFindMessage RtlFindMostSignificantBit
 RtlFindNextForwardRunClear RtlFindRange RtlFindSetBits RtlFindSetBitsAndClear RtlFirstEntrySList RtlFirstFreeAce RtlFlushSecureMemoryCache
 RtlFormatCurrentUserKeyPath RtlFormatMessage RtlFreeAnsiString RtlFreeHandle RtlFreeHeap RtlFreeOemString RtlFreeRangeList RtlFreeSid
 RtlFreeThreadActivationContextStack RtlFreeUnicodeString RtlFreeUserThreadStack RtlGUIDFromString RtlGenerate8dot3Name RtlGetAce RtlGetActiveActivationContext
 RtlGetCallersAddress RtlGetCompressionWorkSpaceSize RtlGetControlSecurityDescriptor RtlGetCurrentDirectory_U RtlGetCurrentPeb RtlGetDaclSecurityDescriptor
 RtlGetElementGenericTable RtlGetElementGenericTableAvl RtlGetFirstRange RtlGetFrame RtlGetFullPathName_U RtlGetGroupSecurityDescriptor RtlGetLastNtStatus
 RtlGetLastWin32Error RtlGetLengthWithoutLastFullDosOrNtPathElement RtlGetLengthWithoutTrailingPathSeperators RtlGetLongestNtPathLength
 RtlGetNativeSystemInformation RtlGetNextRange RtlGetNtGlobalFlags RtlGetNtProductType RtlGetNtVersionNumbers RtlGetOwnerSecurityDescriptor RtlGetProcessHeaps
 RtlGetSaclSecurityDescriptor RtlGetSecurityDescriptorRMControl RtlGetSetBootStatusData RtlGetUnloadEventTrace RtlGetUserInfoHeap RtlGetVersion
 RtlHashUnicodeString RtlIdentifierAuthoritySid RtlImageDirectoryEntryToData RtlImageNtHeader RtlImageRvaToSection RtlImageRvaToVa RtlImpersonateSelf
 RtlInitAnsiString RtlInitCodePageTable RtlInitMemoryStream RtlInitNlsTables RtlInitOutOfProcessMemoryStream RtlInitString RtlInitUnicodeString
 RtlInitUnicodeStringEx RtlInitializeAtomPackage RtlInitializeBitMap RtlInitializeContext RtlInitializeCriticalSection RtlInitializeCriticalSectionAndSpinCount
 RtlInitializeGenericTable RtlInitializeGenericTableAvl RtlInitializeHandleTable RtlInitializeRXact RtlInitializeRangeList RtlInitializeResource
 RtlInitializeSListHead RtlInitializeSid RtlInitializeStackTraceDataBase RtlInsertElementGenericTable RtlInsertElementGenericTableAvl RtlInt64ToUnicodeString
 RtlIntegerToChar RtlIntegerToUnicodeString RtlInterlockedFlushSList RtlInterlockedPopEntrySList RtlInterlockedPushEntrySList RtlInvertRangeList
 RtlIpv4AddressToStringA RtlIpv4AddressToStringExA RtlIpv4AddressToStringExW RtlIpv4AddressToStringW RtlIpv4StringToAddressA RtlIpv4StringToAddressExA
 RtlIpv4StringToAddressExW RtlIpv4StringToAddressW RtlIpv6AddressToStringA RtlIpv6AddressToStringExA RtlIpv6AddressToStringExW RtlIpv6AddressToStringW
 RtlIpv6StringToAddressA RtlIpv6StringToAddressExA RtlIpv6StringToAddressExW RtlIpv6StringToAddressW RtlIsActivationContextActive RtlIsDosDeviceName_U
 RtlIsGenericTableEmpty RtlIsGenericTableEmptyAvl RtlIsNameLegalDOS8Dot3 RtlIsRangeAvailable RtlIsTextUnicode RtlIsThreadWithinLoaderCallout RtlIsValidHandle
 RtlIsValidIndexHandle RtlLargeIntegerAdd RtlLargeIntegerArithmeticShift RtlLargeIntegerDivide RtlLargeIntegerNegate RtlLargeIntegerShiftLeft
 RtlLargeIntegerShiftRight RtlLargeIntegerSubtract RtlLargeIntegerToChar RtlLeaveCriticalSection RtlLengthRequiredSid RtlLengthSecurityDescriptor RtlLengthSid
 RtlLocalTimeToSystemTime RtlLockBootStatusData RtlLockHeap RtlLockMemoryStreamRegion RtlLogStackBackTrace RtlLookupAtomInAtomTable RtlLookupElementGenericTable
 RtlLookupElementGenericTableAvl RtlMakeSelfRelativeSD RtlMapGenericMask RtlMapSecurityErrorToNtStatus RtlMergeRangeLists RtlMoveMemory
 RtlMultiAppendUnicodeStringBuffer RtlMultiByteToUnicodeN RtlMultiByteToUnicodeSize RtlNewInstanceSecurityObject RtlNewSecurityGrantedAccess
 RtlNewSecurityObject RtlNewSecurityObjectEx RtlNewSecurityObjectWithMultipleInheritance RtlNormalizeProcessParams RtlNtPathNameToDosPathName
 RtlNtStatusToDosError RtlNtStatusToDosErrorNoTeb RtlNumberGenericTableElements RtlNumberGenericTableElementsAvl RtlNumberOfClearBits RtlNumberOfSetBits
 RtlOemStringToUnicodeSize RtlOemStringToUnicodeString RtlOemToUnicodeN RtlOpenCurrentUser RtlPcToFileHeader RtlPinAtomInAtomTable RtlPopFrame RtlPrefixString
 RtlPrefixUnicodeString RtlProtectHeap RtlPushFrame RtlQueryAtomInAtomTable RtlQueryDepthSList RtlQueryEnvironmentVariable_U RtlQueryHeapInformation
 RtlQueryInformationAcl RtlQueryInformationActivationContext RtlQueryInformationActiveActivationContext RtlQueryInterfaceMemoryStream
 RtlQueryProcessBackTraceInformation RtlQueryProcessDebugInformation RtlQueryProcessHeapInformation RtlQueryProcessLockInformation RtlQueryRegistryValues
 RtlQuerySecurityObject RtlQueryTagHeap RtlQueryTimeZoneInformation RtlQueueApcWow64Thread RtlQueueWorkItem RtlRaiseException RtlRaiseStatus RtlRandom
 RtlRandomEx RtlReAllocateHeap RtlReadMemoryStream RtlReadOutOfProcessMemoryStream RtlRealPredecessor RtlRealSuccessor RtlRegisterSecureMemoryCacheCallback
 RtlRegisterWait RtlReleaseActivationContext RtlReleaseMemoryStream RtlReleasePebLock RtlReleaseResource RtlRemoteCall RtlRemoveVectoredExceptionHandler
 RtlResetRtlTranslations RtlRestoreLastWin32Error RtlRevertMemoryStream RtlRunDecodeUnicodeString RtlRunEncodeUnicodeString RtlSecondsSince1970ToTime
 RtlSecondsSince1980ToTime RtlSeekMemoryStream RtlSelfRelativeToAbsoluteSD2 RtlSelfRelativeToAbsoluteSD RtlSetAllBits RtlSetAttributesSecurityDescriptor
 RtlSetBits RtlSetControlSecurityDescriptor RtlSetCriticalSectionSpinCount RtlSetCurrentDirectory_U RtlSetCurrentEnvironment RtlSetDaclSecurityDescriptor
 RtlSetEnvironmentVariable RtlSetGroupSecurityDescriptor RtlSetHeapInformation RtlSetInformationAcl RtlSetIoCompletionCallback RtlSetLastWin32Error
 RtlSetLastWin32ErrorAndNtStatusFromNtStatus RtlSetMemoryStreamSize RtlSetOwnerSecurityDescriptor RtlSetProcessIsCritical RtlSetSaclSecurityDescriptor
 RtlSetSecurityDescriptorRMControl RtlSetSecurityObject RtlSetSecurityObjectEx RtlSetThreadIsCritical RtlSetThreadPoolStartFunc RtlSetTimeZoneInformation
 RtlSetTimer RtlSetUnicodeCallouts RtlSetUserFlagsHeap RtlSetUserValueHeap RtlSizeHeap RtlSplay RtlStartRXact RtlStatMemoryStream RtlStringFromGUID
 RtlSubAuthorityCountSid RtlSubAuthoritySid RtlSubtreePredecessor RtlSubtreeSuccessor RtlSystemTimeToLocalTime RtlTimeFieldsToTime RtlTimeToElapsedTimeFields
 RtlTimeToSecondsSince1970 RtlTimeToSecondsSince1980 RtlTimeToTimeFields RtlTraceDatabaseAdd RtlTraceDatabaseCreate RtlTraceDatabaseDestroy
 RtlTraceDatabaseEnumerate RtlTraceDatabaseFind RtlTraceDatabaseLock RtlTraceDatabaseUnlock RtlTraceDatabaseValidate RtlTryEnterCriticalSection
 RtlUnhandledExceptionFilter2 RtlUnhandledExceptionFilter RtlUnicodeStringToAnsiSize RtlUnicodeStringToAnsiString RtlUnicodeStringToCountedOemString
 RtlUnicodeStringToInteger RtlUnicodeStringToOemSize RtlUnicodeStringToOemString RtlUnicodeToCustomCPN RtlUnicodeToMultiByteN RtlUnicodeToMultiByteSize
 RtlUnicodeToOemN RtlUniform RtlUnlockBootStatusData RtlUnlockHeap RtlUnlockMemoryStreamRegion RtlUnwind RtlUpcaseUnicodeChar RtlUpcaseUnicodeString
 RtlUpcaseUnicodeStringToAnsiString RtlUpcaseUnicodeStringToCountedOemString RtlUpcaseUnicodeStringToOemString RtlUpcaseUnicodeToCustomCPN
 RtlUpcaseUnicodeToMultiByteN RtlUpcaseUnicodeToOemN RtlUpdateTimer RtlUpperChar RtlUpperString RtlUsageHeap RtlValidAcl RtlValidRelativeSecurityDescriptor
 RtlValidSecurityDescriptor RtlValidSid RtlValidateHeap RtlValidateProcessHeaps RtlValidateUnicodeString RtlVerifyVersionInfo RtlWalkFrameChain RtlWalkHeap
 RtlWriteMemoryStream RtlWriteRegistryValue RtlZeroHeap RtlZeroMemory RtlZombifyActivationContext RtlpApplyLengthFunction RtlpEnsureBufferSize
 RtlpNotOwnerCriticalSection RtlpNtCreateKey RtlpNtEnumerateSubKey RtlpNtMakeTemporaryKey RtlpNtOpenKey RtlpNtQueryValueKey RtlpNtSetValueKey
 RtlpUnWaitCriticalSection RtlpWaitForCriticalSection RtlxAnsiStringToUnicodeSize RtlxOemStringToUnicodeSize RtlxUnicodeStringToAnsiSize
 RtlxUnicodeStringToOemSize VerSetConditionMask ZwAcceptConnectPort ZwAccessCheck ZwAccessCheckAndAuditAlarm ZwAccessCheckByType
 ZwAccessCheckByTypeAndAuditAlarm ZwAccessCheckByTypeResultList ZwAccessCheckByTypeResultListAndAuditAlarm ZwAccessCheckByTypeResultListAndAuditAlarmByHandle
 ZwAddAtom ZwAddBootEntry ZwAdjustGroupsToken ZwAdjustPrivilegesToken ZwAlertResumeThread ZwAlertThread ZwAllocateLocallyUniqueId ZwAllocateUserPhysicalPages
 ZwAllocateUuids ZwAllocateVirtualMemory ZwAreMappedFilesTheSame ZwAssignProcessToJobObject ZwCallbackReturn ZwCancelDeviceWakeupRequest ZwCancelIoFile
 ZwCancelTimer ZwClearEvent ZwClose ZwCloseObjectAuditAlarm ZwCompactKeys ZwCompareTokens ZwCompleteConnectPort ZwCompressKey ZwConnectPort ZwContinue
 ZwCreateDebugObject ZwCreateDirectoryObject ZwCreateEvent ZwCreateEventPair ZwCreateFile ZwCreateIoCompletion ZwCreateJobObject ZwCreateJobSet ZwCreateKey
 ZwCreateKeyedEvent ZwCreateMailslotFile ZwCreateMutant ZwCreateNamedPipeFile ZwCreatePagingFile ZwCreatePort ZwCreateProcess ZwCreateProcessEx ZwCreateProfile
 ZwCreateSection ZwCreateSemaphore ZwCreateSymbolicLinkObject ZwCreateThread ZwCreateTimer ZwCreateToken ZwCreateWaitablePort ZwDebugActiveProcess
 ZwDebugContinue ZwDelayExecution ZwDeleteAtom ZwDeleteBootEntry ZwDeleteFile ZwDeleteKey ZwDeleteObjectAuditAlarm ZwDeleteValueKey ZwDeviceIoControlFile
 ZwDisplayString ZwDuplicateObject ZwDuplicateToken ZwEnumerateBootEntries ZwEnumerateKey ZwEnumerateSystemEnvironmentValuesEx ZwEnumerateValueKey
 ZwExtendSection ZwFilterToken ZwFindAtom ZwFlushBuffersFile ZwFlushInstructionCache ZwFlushKey ZwFlushVirtualMemory ZwFlushWriteBuffer ZwFreeUserPhysicalPages
 ZwFreeVirtualMemory ZwFsControlFile ZwGetContextThread ZwGetDevicePowerState ZwGetPlugPlayEvent ZwGetWriteWatch ZwImpersonateAnonymousToken
 ZwImpersonateClientOfPort ZwImpersonateThread ZwInitializeRegistry ZwInitiatePowerAction ZwIsProcessInJob ZwIsSystemResumeAutomatic ZwListenPort ZwLoadDriver
 ZwLoadKey2 ZwLoadKey ZwLockFile ZwLockProductActivationKeys ZwLockRegistryKey ZwLockVirtualMemory ZwMakePermanentObject ZwMakeTemporaryObject
 ZwMapUserPhysicalPages ZwMapUserPhysicalPagesScatter ZwMapViewOfSection ZwModifyBootEntry ZwNotifyChangeDirectoryFile ZwNotifyChangeKey
 ZwNotifyChangeMultipleKeys ZwOpenDirectoryObject ZwOpenEvent ZwOpenEventPair ZwOpenFile ZwOpenIoCompletion ZwOpenJobObject ZwOpenKey ZwOpenKeyedEvent
 ZwOpenMutant ZwOpenObjectAuditAlarm ZwOpenProcess ZwOpenProcessToken ZwOpenProcessTokenEx ZwOpenSection ZwOpenSemaphore ZwOpenSymbolicLinkObject ZwOpenThread
 ZwOpenThreadToken ZwOpenThreadTokenEx ZwOpenTimer ZwPlugPlayControl ZwPowerInformation ZwPrivilegeCheck ZwPrivilegeObjectAuditAlarm
 ZwPrivilegedServiceAuditAlarm ZwProtectVirtualMemory ZwPulseEvent ZwQueryAttributesFile ZwQueryBootEntryOrder ZwQueryBootOptions ZwQueryDebugFilterState
 ZwQueryDefaultLocale ZwQueryDefaultUILanguage ZwQueryDirectoryFile ZwQueryDirectoryObject ZwQueryEaFile ZwQueryEvent ZwQueryFullAttributesFile
 ZwQueryInformationAtom ZwQueryInformationFile ZwQueryInformationJobObject ZwQueryInformationPort ZwQueryInformationProcess ZwQueryInformationThread
 ZwQueryInformationToken ZwQueryInstallUILanguage ZwQueryIntervalProfile ZwQueryIoCompletion ZwQueryKey ZwQueryMultipleValueKey ZwQueryMutant ZwQueryObject
 ZwQueryOpenSubKeys ZwQueryPerformanceCounter ZwQueryPortInformationProcess ZwQueryQuotaInformationFile ZwQuerySection ZwQuerySecurityObject ZwQuerySemaphore
 ZwQuerySymbolicLinkObject ZwQuerySystemEnvironmentValue ZwQuerySystemEnvironmentValueEx ZwQuerySystemInformation ZwQuerySystemTime ZwQueryTimer
 ZwQueryTimerResolution ZwQueryValueKey ZwQueryVirtualMemory ZwQueryVolumeInformationFile ZwQueueApcThread ZwRaiseException ZwRaiseHardError ZwReadFile
 ZwReadFileScatter ZwReadRequestData ZwReadVirtualMemory ZwRegisterThreadTerminatePort ZwReleaseKeyedEvent ZwReleaseMutant ZwReleaseSemaphore
 ZwRemoveIoCompletion ZwRemoveProcessDebug ZwRenameKey ZwReplaceKey ZwReplyPort ZwReplyWaitReceivePort ZwReplyWaitReceivePortEx ZwReplyWaitReplyPort
 ZwRequestDeviceWakeup ZwRequestPort ZwRequestWaitReplyPort ZwRequestWakeupLatency ZwResetEvent ZwResetWriteWatch ZwRestoreKey ZwResumeProcess ZwResumeThread
 ZwSaveKey ZwSaveKeyEx ZwSaveMergedKeys ZwSecureConnectPort ZwSetBootEntryOrder ZwSetBootOptions ZwSetContextThread ZwSetDebugFilterState
 ZwSetDefaultHardErrorPort ZwSetDefaultLocale ZwSetDefaultUILanguage ZwSetEaFile ZwSetEvent ZwSetEventBoostPriority ZwSetHighEventPair ZwSetHighWaitLowEventPair
 ZwSetInformationDebugObject ZwSetInformationFile ZwSetInformationJobObject ZwSetInformationKey ZwSetInformationObject ZwSetInformationProcess
 ZwSetInformationThread ZwSetInformationToken ZwSetIntervalProfile ZwSetIoCompletion ZwSetLdtEntries ZwSetLowEventPair ZwSetLowWaitHighEventPair
 ZwSetQuotaInformationFile ZwSetSecurityObject ZwSetSystemEnvironmentValue ZwSetSystemEnvironmentValueEx ZwSetSystemInformation ZwSetSystemPowerState
 ZwSetSystemTime ZwSetThreadExecutionState ZwSetTimer ZwSetTimerResolution ZwSetUuidSeed ZwSetValueKey ZwSetVolumeInformationFile ZwShutdownSystem
 ZwSignalAndWaitForSingleObject ZwStartProfile ZwStopProfile ZwSuspendProcess ZwSuspendThread ZwSystemDebugControl ZwTerminateJobObject ZwTerminateProcess
 ZwTerminateThread ZwTestAlert ZwTraceEvent ZwTranslateFilePath ZwUnloadDriver ZwUnloadKey ZwUnloadKeyEx ZwUnlockFile ZwUnlockVirtualMemory ZwUnmapViewOfSection
 ZwVdmControl ZwWaitForDebugEvent ZwWaitForKeyedEvent ZwWaitForMultipleObjects ZwWaitForSingleObject ZwWaitHighEventPair ZwWaitLowEventPair ZwWriteFile
 ZwWriteFileGather ZwWriteRequestData ZwWriteVirtualMemory ZwYieldExecution _CIcos _CIlog _CIpow _CIsin _CIsqrt __isascii __iscsym __iscsymf __toascii _alldiv
 _alldvrm _allmul _alloca_probe _allrem _allshl _allshr _atoi64 _aulldiv _aulldvrm _aullrem _aullshr _chkstk _fltused _ftol _i64toa _i64tow _itoa _itow _lfind
 _ltoa _ltow _memccpy _memicmp _snprintf _snwprintf _splitpath _strcmpi _stricmp _strlwr _strnicmp _strupr _tolower _toupper _ui64toa _ui64tow _ultoa _ultow
 _vsnprintf _vsnwprintf _wcsicmp _wcslwr _wcsnicmp _wcsupr _wtoi _wtoi64 _wtol abs atan atoi atol bsearch ceil cos fabs floor isalnum isalpha iscntrl isdigit
 isgraph islower isprint ispunct isspace isupper iswalpha iswctype iswdigit iswlower iswspace iswxdigit isxdigit labs log mbstowcs memchr memcmp memcpy memmove
 memset pow qsort sin sprintf sqrt sscanf strcat strchr strcmp strcpy strcspn strlen strncat strncmp strncpy strpbrk strrchr strspn strstr strtol strtoul
 swprintf tan tolower toupper towlower towupper vDbgPrintEx vDbgPrintExWithPrefix vsprintf wcscat wcschr wcscmp wcscpy wcscspn wcslen wcsncat wcsncmp wcsncpy
 wcspbrk wcsrchr wcsspn wcsstr wcstol wcstombs wcstoul
GDI32
 AbortDoc AbortPath AddFontMemResourceEx AddFontResourceA AddFontResourceExA AddFontResourceExW AddFontResourceTracking AddFontResourceW AngleArc
 AnimatePalette AnyLinkedFonts Arc ArcTo BRUSHOBJ_hGetColorTransform BRUSHOBJ_pvAllocRbrush BRUSHOBJ_pvGetRbrush BRUSHOBJ_ulGetBrushColor BeginPath BitBlt
 CLIPOBJ_bEnum CLIPOBJ_cEnumStart CLIPOBJ_ppoGetPath CancelDC CheckColorsInGamut ChoosePixelFormat Chord ClearBitmapAttributes ClearBrushAttributes
 CloseEnhMetaFile CloseFigure CloseMetaFile ColorCorrectPalette ColorMatchToTarget CombineRgn CombineTransform CopyEnhMetaFileA CopyEnhMetaFileW CopyMetaFileA
 CopyMetaFileW CreateBitmap CreateBitmapIndirect CreateBrushIndirect CreateColorSpaceA CreateColorSpaceW CreateCompatibleBitmap CreateCompatibleDC CreateDCA
 CreateDCW CreateDIBPatternBrush CreateDIBPatternBrushPt CreateDIBSection CreateDIBitmap CreateDiscardableBitmap CreateEllipticRgn CreateEllipticRgnIndirect
 CreateEnhMetaFileA CreateEnhMetaFileW CreateFontA CreateFontIndirectA CreateFontIndirectExA CreateFontIndirectExW CreateFontIndirectW CreateFontW
 CreateHalftonePalette CreateHatchBrush CreateICA CreateICW CreateMetaFileA CreateMetaFileW CreatePalette CreatePatternBrush CreatePen CreatePenIndirect
 CreatePolyPolygonRgn CreatePolygonRgn CreateRectRgn CreateRectRgnIndirect CreateRoundRectRgn CreateScalableFontResourceA CreateScalableFontResourceW
 CreateSolidBrush DPtoLP DdEntry0 DdEntry10 DdEntry11 DdEntry12 DdEntry13 DdEntry14 DdEntry15 DdEntry16 DdEntry17 DdEntry18 DdEntry19 DdEntry1 DdEntry20
 DdEntry21 DdEntry22 DdEntry23 DdEntry24 DdEntry25 DdEntry26 DdEntry27 DdEntry28 DdEntry29 DdEntry2 DdEntry30 DdEntry31 DdEntry32 DdEntry33 DdEntry34 DdEntry35
 DdEntry36 DdEntry37 DdEntry38 DdEntry39 DdEntry3 DdEntry40 DdEntry41 DdEntry42 DdEntry43 DdEntry44 DdEntry45 DdEntry46 DdEntry47 DdEntry48 DdEntry49 DdEntry4
 DdEntry50 DdEntry51 DdEntry52 DdEntry53 DdEntry54 DdEntry55 DdEntry56 DdEntry5 DdEntry6 DdEntry7 DdEntry8 DdEntry9 DeleteColorSpace DeleteDC DeleteEnhMetaFile
 DeleteMetaFile DeleteObject DescribePixelFormat DeviceCapabilitiesExA DeviceCapabilitiesExW DrawEscape Ellipse EnableEUDC EndDoc EndFormPage EndPage EndPath
 EngAcquireSemaphore EngAlphaBlend EngAssociateSurface EngBitBlt EngCheckAbort EngComputeGlyphSet EngCopyBits EngCreateBitmap EngCreateClip
 EngCreateDeviceBitmap EngCreateDeviceSurface EngCreatePalette EngCreateSemaphore EngDeleteClip EngDeletePalette EngDeletePath EngDeleteSemaphore
 EngDeleteSurface EngEraseSurface EngFillPath EngFindResource EngFreeModule EngGetCurrentCodePage EngGetDriverName EngGetPrinterDataFileName EngGradientFill
 EngLineTo EngLoadModule EngLockSurface EngMarkBandingSurface EngMultiByteToUnicodeN EngMultiByteToWideChar EngPaint EngPlgBlt EngQueryEMFInfo
 EngQueryLocalTime EngReleaseSemaphore EngStretchBlt EngStretchBltROP EngStrokeAndFillPath EngStrokePath EngTextOut EngTransparentBlt EngUnicodeToMultiByteN
 EngUnlockSurface EngWideCharToMultiByte EnumEnhMetaFile EnumFontFamiliesA EnumFontFamiliesExA EnumFontFamiliesExW EnumFontFamiliesW EnumFontsA EnumFontsW
 EnumICMProfilesA EnumICMProfilesW EnumMetaFile EnumObjects EqualRgn Escape EudcLoadLinkW EudcUnloadLinkW ExcludeClipRect ExtCreatePen ExtCreateRegion
 ExtEscape ExtFloodFill ExtSelectClipRgn ExtTextOutA ExtTextOutW FONTOBJ_cGetAllGlyphHandles FONTOBJ_cGetGlyphs FONTOBJ_pQueryGlyphAttrs FONTOBJ_pfdg
 FONTOBJ_pifi FONTOBJ_pvTrueTypeFontFile FONTOBJ_pxoGetXform FONTOBJ_vGetInfo FillPath FillRgn FixBrushOrgEx FlattenPath FloodFill FontIsLinked FrameRgn
 GdiAddFontResourceW GdiAddGlsBounds GdiAddGlsRecord GdiAlphaBlend GdiArtificialDecrementDriver GdiCleanCacheDC GdiComment GdiConsoleTextOut
 GdiConvertAndCheckDC GdiConvertBitmap GdiConvertBitmapV5 GdiConvertBrush GdiConvertDC GdiConvertEnhMetaFile GdiConvertFont GdiConvertMetaFilePict
 GdiConvertPalette GdiConvertRegion GdiConvertToDevmodeW GdiCreateLocalEnhMetaFile GdiCreateLocalMetaFilePict GdiDeleteLocalDC GdiDeleteSpoolFileHandle
 GdiDescribePixelFormat GdiDllInitialize GdiDrawStream GdiEndDocEMF GdiEndPageEMF GdiEntry10 GdiEntry11 GdiEntry12 GdiEntry13 GdiEntry14 GdiEntry15 GdiEntry16
 GdiEntry1 GdiEntry2 GdiEntry3 GdiEntry4 GdiEntry5 GdiEntry6 GdiEntry7 GdiEntry8 GdiEntry9 GdiFixUpHandle GdiFlush GdiFullscreenControl GdiGetBatchLimit
 GdiGetBitmapBitsSize GdiGetCharDimensions GdiGetCodePage GdiGetDC GdiGetDevmodeForPage GdiGetLocalBrush GdiGetLocalDC GdiGetLocalFont GdiGetPageCount
 GdiGetPageHandle GdiGetSpoolFileHandle GdiGetSpoolMessage GdiGradientFill GdiInitSpool GdiInitializeLanguagePack GdiIsMetaFileDC GdiIsMetaPrintDC
 GdiIsPlayMetafileDC GdiPlayDCScript GdiPlayEMF GdiPlayJournal GdiPlayPageEMF GdiPlayPrivatePageEMF GdiPlayScript GdiPrinterThunk GdiProcessSetup GdiQueryFonts
 GdiQueryTable GdiRealizationInfo GdiReleaseDC GdiReleaseLocalDC GdiResetDCEMF GdiSetAttrs GdiSetBatchLimit GdiSetLastError GdiSetPixelFormat GdiSetServerAttr
 GdiStartDocEMF GdiStartPageEMF GdiSwapBuffers GdiTransparentBlt GdiValidateHandle GetArcDirection GetAspectRatioFilterEx GetBitmapAttributes GetBitmapBits
 GetBitmapDimensionEx GetBkColor GetBkMode GetBoundsRect GetBrushAttributes GetBrushOrgEx GetCharABCWidthsA GetCharABCWidthsFloatA GetCharABCWidthsFloatW
 GetCharABCWidthsI GetCharABCWidthsW GetCharWidth32A GetCharWidth32W GetCharWidthA GetCharWidthFloatA GetCharWidthFloatW GetCharWidthI GetCharWidthInfo
 GetCharWidthW GetCharacterPlacementA GetCharacterPlacementW GetClipBox GetClipRgn GetColorAdjustment GetColorSpace GetCurrentObject GetCurrentPositionEx
 GetDCBrushColor GetDCOrgEx GetDCPenColor GetDIBColorTable GetDIBits GetDeviceCaps GetDeviceGammaRamp GetETM GetEUDCTimeStamp GetEUDCTimeStampExW
 GetEnhMetaFileA GetEnhMetaFileBits GetEnhMetaFileDescriptionA GetEnhMetaFileDescriptionW GetEnhMetaFileHeader GetEnhMetaFilePaletteEntries
 GetEnhMetaFilePixelFormat GetEnhMetaFileW GetFontAssocStatus GetFontData GetFontLanguageInfo GetFontResourceInfoW GetFontUnicodeRanges GetGlyphIndicesA
 GetGlyphIndicesW GetGlyphOutline GetGlyphOutlineA GetGlyphOutlineW GetGlyphOutlineWow GetGraphicsMode GetHFONT GetICMProfileA GetICMProfileW GetKerningPairs
 GetKerningPairsA GetKerningPairsW GetLayout GetLogColorSpaceA GetLogColorSpaceW GetMapMode GetMetaFileA GetMetaFileBitsEx GetMetaFileW GetMetaRgn
 GetMiterLimit GetNearestColor GetNearestPaletteIndex GetObjectA GetObjectType GetObjectW GetOutlineTextMetricsA GetOutlineTextMetricsW GetPaletteEntries
 GetPath GetPixel GetPixelFormat GetPolyFillMode GetROP2 GetRandomRgn GetRasterizerCaps GetRegionData GetRelAbs GetRgnBox GetStockObject GetStretchBltMode
 GetStringBitmapA GetStringBitmapW GetSystemPaletteEntries GetSystemPaletteUse GetTextAlign GetTextCharacterExtra GetTextCharset GetTextCharsetInfo
 GetTextColor GetTextExtentExPointA GetTextExtentExPointI GetTextExtentExPointW GetTextExtentExPointWPri GetTextExtentPoint32A GetTextExtentPoint32W
 GetTextExtentPointA GetTextExtentPointI GetTextExtentPointW GetTextFaceA GetTextFaceAliasW GetTextFaceW GetTextMetricsA GetTextMetricsW GetTransform
 GetViewportExtEx GetViewportOrgEx GetWinMetaFileBits GetWindowExtEx GetWindowOrgEx GetWorldTransform HT_Get8BPPFormatPalette HT_Get8BPPMaskPalette
 IntersectClipRect InvertRgn IsValidEnhMetaRecord IsValidEnhMetaRecordOffExt LPtoDP LineDDA LineTo MaskBlt MirrorRgn ModifyWorldTransform MoveToEx NamedEscape
 OffsetClipRgn OffsetRgn OffsetViewportOrgEx OffsetWindowOrgEx PATHOBJ_bEnum PATHOBJ_bEnumClipLines PATHOBJ_vEnumStart PATHOBJ_vEnumStartClipLines
 PATHOBJ_vGetBounds PaintRgn PatBlt PathToRegion Pie PlayEnhMetaFile PlayEnhMetaFileRecord PlayMetaFile PlayMetaFileRecord PlgBlt PolyBezier PolyBezierTo
 PolyDraw PolyPatBlt PolyPolygon PolyPolyline PolyTextOutA PolyTextOutW Polygon Polyline PolylineTo PtInRegion PtVisible QueryFontAssocStatus RealizePalette
 RectInRegion RectVisible Rectangle RemoveFontMemResourceEx RemoveFontResourceA RemoveFontResourceExA RemoveFontResourceExW RemoveFontResourceTracking
 RemoveFontResourceW ResetDCA ResetDCW ResizePalette RestoreDC RoundRect STROBJ_bEnum STROBJ_bEnumPositionsOnly STROBJ_bGetAdvanceWidths STROBJ_dwGetCodePage
 STROBJ_vEnumStart SaveDC ScaleViewportExtEx ScaleWindowExtEx SelectBrushLocal SelectClipPath SelectClipRgn SelectFontLocal SelectObject SelectPalette
 SetAbortProc SetArcDirection SetBitmapAttributes SetBitmapBits SetBitmapDimensionEx SetBkColor SetBkMode SetBoundsRect SetBrushAttributes SetBrushOrgEx
 SetColorAdjustment SetColorSpace SetDCBrushColor SetDCPenColor SetDIBColorTable SetDIBits SetDIBitsToDevice SetDeviceGammaRamp SetEnhMetaFileBits
 SetFontEnumeration SetGraphicsMode SetICMMode SetICMProfileA SetICMProfileW SetLayout SetLayoutWidth SetMagicColors SetMapMode SetMapperFlags
 SetMetaFileBitsEx SetMetaRgn SetMiterLimit SetPaletteEntries SetPixel SetPixelFormat SetPixelV SetPolyFillMode SetROP2 SetRectRgn SetRelAbs SetStretchBltMode
 SetSystemPaletteUse SetTextAlign SetTextCharacterExtra SetTextColor SetTextJustification SetViewportExtEx SetViewportOrgEx SetVirtualResolution
 SetWinMetaFileBits SetWindowExtEx SetWindowOrgEx SetWorldTransform StartDocA StartDocW StartFormPage StartPage StretchBlt StretchDIBits StrokeAndFillPath
 StrokePath SwapBuffers TextOutA TextOutW TranslateCharsetInfo UnloadNetworkFonts UnrealizeObject UpdateColors UpdateICMRegKeyA UpdateICMRegKeyW WidenPath
 XFORMOBJ_bApplyXform XFORMOBJ_iGetXform XLATEOBJ_cGetPalette XLATEOBJ_hGetColorTransform XLATEOBJ_iXlate XLATEOBJ_piVector bInitSystemAndFontsDirectoriesW
 bMakePathNameW cGetTTFFromFOT gdiPlaySpoolStream
msvcrt-ruby18
 GetCurrentThreadHandle Init_Array Init_Bignum Init_Binding Init_Comparable Init_Dir Init_Enumerable Init_Exception Init_File Init_GC Init_Hash Init_IO
 Init_Math Init_Numeric Init_Object Init_Precision Init_Proc Init_Random Init_Range Init_Regexp Init_String Init_Struct Init_Thread Init_Time Init_eval
 Init_ext Init_heap Init_load Init_marshal Init_pack Init_process Init_signal Init_stack Init_sym Init_syserr Init_var_tables Init_version NtInitialize
 NtSyncProcess SafeFree acosh asinh atanh chown crypt des_cipher des_setkey dln_find_exe dln_find_file dln_load do_aspawn do_spawn eaccess encrypt endhostent
 endnetent endprotoent endservent erf erfc fcntl flock getegid geteuid getgid getlogin getnetbyaddr getnetbyname getnetent getprotoent getservent gettimeofday
 getuid io_fread ioctl is_ruby_native_thread kill link pipe_exec rb_Array rb_Float rb_Integer rb_String rb_add_event_hook rb_add_method rb_alias
 rb_alias_variable rb_any_to_s rb_apply rb_argv rb_argv0 rb_ary_aref rb_ary_assoc rb_ary_clear rb_ary_cmp rb_ary_concat rb_ary_delete rb_ary_delete_at
 rb_ary_dup rb_ary_each rb_ary_entry rb_ary_freeze rb_ary_includes rb_ary_join rb_ary_new rb_ary_new2 rb_ary_new3 rb_ary_new4 rb_ary_plus rb_ary_pop
 rb_ary_push rb_ary_rassoc rb_ary_reverse rb_ary_shift rb_ary_sort rb_ary_sort_bang rb_ary_store rb_ary_to_ary rb_ary_to_s rb_ary_unshift rb_assoc_new rb_attr
 rb_attr_get rb_autoload rb_autoload_load rb_autoload_p rb_backref_get rb_backref_set rb_backtrace rb_big2dbl rb_big2ll rb_big2long rb_big2str rb_big2ull
 rb_big2ulong rb_big2ulong_pack rb_big_2comp rb_big_and rb_big_clone rb_big_divmod rb_big_lshift rb_big_minus rb_big_mul rb_big_norm rb_big_or rb_big_plus
 rb_big_pow rb_big_rand rb_big_xor rb_block_given_p rb_block_proc rb_bug rb_cArray rb_cBignum rb_cClass rb_cData rb_cDir rb_cFalseClass rb_cFile rb_cFixnum
 rb_cFloat rb_cHash rb_cIO rb_cInteger rb_cModule rb_cNilClass rb_cNumeric rb_cObject rb_cProc rb_cRange rb_cRegexp rb_cString rb_cStruct rb_cSymbol rb_cThread
 rb_cTime rb_cTrueClass rb_call_inits rb_call_super rb_catch rb_check_array_type rb_check_convert_type rb_check_frozen rb_check_inheritable rb_check_safe_obj
 rb_check_safe_str rb_check_string_type rb_check_type rb_class2name rb_class_boot rb_class_inherited rb_class_inherited_p rb_class_init_copy
 rb_class_instance_methods rb_class_name rb_class_new rb_class_new_instance rb_class_path rb_class_private_instance_methods rb_class_protected_instance_methods
 rb_class_public_instance_methods rb_class_real rb_class_tbl rb_clear_cache rb_clear_cache_by_class rb_cmperr rb_cmpint rb_compile_cstr rb_compile_error
 rb_compile_error_append rb_compile_file rb_compile_string rb_const_defined rb_const_defined_at rb_const_defined_from rb_const_get rb_const_get_at
 rb_const_get_from rb_const_list rb_const_set rb_convert_type rb_copy_generic_ivar rb_cstr2inum rb_cstr_to_dbl rb_cstr_to_inum rb_cv_get rb_cv_set
 rb_cvar_defined rb_cvar_get rb_cvar_set rb_data_object_alloc rb_dbl2big rb_dbl_cmp rb_default_rs rb_deferr rb_define_alias rb_define_alloc_func rb_define_attr
 rb_define_class rb_define_class_id rb_define_class_under rb_define_class_variable rb_define_const rb_define_global_const rb_define_global_function
 rb_define_hooked_variable rb_define_method rb_define_method_id rb_define_module rb_define_module_function rb_define_module_id rb_define_module_under
 rb_define_private_method rb_define_protected_method rb_define_readonly_variable rb_define_singleton_method rb_define_variable rb_define_virtual_variable
 rb_detach_process rb_disable_super rb_dvar_curr rb_dvar_defined rb_dvar_push rb_dvar_ref rb_eArgError rb_eEOFError rb_eException rb_eFatal
 rb_eFloatDomainError rb_eIOError rb_eIndexError rb_eInterrupt rb_eLoadError rb_eNameError rb_eNoMemError rb_eNoMethodError rb_eNotImpError rb_eRangeError
 rb_eRuntimeError rb_eScriptError rb_eSecurityError rb_eSignal rb_eStandardError rb_eSyntaxError rb_eSystemCallError rb_eSystemExit rb_eTypeError
 rb_eZeroDivError rb_each rb_enable_super rb_ensure rb_env_path_tainted rb_eof_error rb_eql rb_equal rb_error_frozen rb_eval_cmd rb_eval_string
 rb_eval_string_protect rb_eval_string_wrap rb_exc_fatal rb_exc_new rb_exc_new2 rb_exc_new3 rb_exc_raise rb_exec_end_proc rb_exit rb_extend_object rb_f_abort
 rb_f_exec rb_f_exit rb_f_global_variables rb_f_kill rb_f_lambda rb_f_require rb_f_sprintf rb_f_trace_var rb_f_untrace_var rb_fatal rb_fdopen rb_file_const
 rb_file_expand_path rb_file_open rb_file_s_expand_path rb_file_sysopen rb_find_file rb_find_file_ext rb_fix2int rb_fix2str rb_float_new rb_fopen
 rb_frame_last_func rb_free_generic_ivar rb_frozen_class_p rb_fs rb_funcall rb_funcall2 rb_funcall3 rb_funcall_rescue rb_gc rb_gc_abort_threads
 rb_gc_call_finalizer_at_exit rb_gc_copy_finalizer rb_gc_disable rb_gc_enable rb_gc_finalize_deferred rb_gc_force_recycle rb_gc_mark rb_gc_mark_frame
 rb_gc_mark_global_tbl rb_gc_mark_locations rb_gc_mark_maybe rb_gc_mark_parser rb_gc_mark_threads rb_gc_mark_trap_list rb_gc_register_address rb_gc_stack_start
 rb_gc_start rb_gc_unregister_address rb_generic_ivar_table rb_get_kcode rb_getc rb_gets rb_glob rb_global_entry rb_global_variable rb_globi rb_gv_get
 rb_gv_set rb_gvar_defined rb_gvar_get rb_gvar_set rb_hash rb_hash_aref rb_hash_aset rb_hash_delete rb_hash_delete_if rb_hash_foreach rb_hash_freeze
 rb_hash_new rb_hash_reject_bang rb_hash_select rb_hash_values_at rb_id2name rb_id_attrset rb_include_module rb_inspect rb_inspecting_p rb_int2big rb_int2inum
 rb_intern rb_interrupt rb_invalid_str rb_io_addstr rb_io_binmode rb_io_check_closed rb_io_check_initialized rb_io_check_readable rb_io_check_writable
 rb_io_close rb_io_eof rb_io_flags_mode rb_io_fptr_finalize rb_io_fread rb_io_fwrite rb_io_getc rb_io_gets rb_io_mode_flags rb_io_modenum_flags rb_io_print
 rb_io_printf rb_io_puts rb_io_synchronized rb_io_taint_check rb_io_unbuffered rb_io_ungetc rb_io_wait_readable rb_io_wait_writable rb_io_write rb_is_class_id
 rb_is_const_id rb_is_instance_id rb_is_junk_id rb_is_local_id rb_iter_break rb_iterate rb_iterator_p rb_iv_get rb_iv_set rb_ivar_defined rb_ivar_get
 rb_ivar_set rb_jump_tag rb_kcode rb_last_status rb_lastline_get rb_lastline_set rb_ll2big rb_ll2inum rb_load rb_load_fail rb_load_file rb_load_path
 rb_load_protect rb_loaderror rb_mComparable rb_mEnumerable rb_mErrno rb_mFileTest rb_mGC rb_mKernel rb_mMath rb_mPrecision rb_mProcGID rb_mProcID_Syscall
 rb_mProcUID rb_mProcess rb_make_metaclass rb_mark_end_proc rb_mark_generic_ivar rb_mark_generic_ivar_tbl rb_mark_hash rb_mark_tbl rb_marshal_dump
 rb_marshal_load rb_match_busy rb_mem_clear rb_memcicmp rb_memcmp rb_memerror rb_memsearch rb_method_boundp rb_method_node rb_mod_ancestors
 rb_mod_class_variables rb_mod_const_at rb_mod_const_missing rb_mod_const_of rb_mod_constants rb_mod_include_p rb_mod_included_modules rb_mod_init_copy
 rb_mod_module_eval rb_mod_name rb_mod_remove_const rb_mod_remove_cvar rb_module_new rb_name_class rb_name_error rb_need_block rb_newobj rb_node_newnode
 rb_notimplement rb_num2dbl rb_num2fix rb_num2int rb_num2ll rb_num2long rb_num2ull rb_num2ulong rb_num_coerce_bin rb_num_coerce_cmp rb_num_coerce_relop
 rb_num_zerodiv rb_obj_alloc rb_obj_as_string rb_obj_call_init rb_obj_class rb_obj_classname rb_obj_clone rb_obj_dup rb_obj_freeze rb_obj_id rb_obj_id_obsolete
 rb_obj_infect rb_obj_init_copy rb_obj_instance_eval rb_obj_instance_variables rb_obj_is_instance_of rb_obj_is_kind_of rb_obj_remove_instance_variable
 rb_obj_respond_to rb_obj_singleton_methods rb_obj_taint rb_obj_tainted rb_obj_type rb_obj_untaint rb_origenviron rb_output_fs rb_output_rs rb_p
 rb_parser_append_print rb_parser_while_loop rb_path2class rb_path_check rb_path_end rb_path_last_separator rb_path_next rb_path_skip_prefix rb_proc_exec
 rb_proc_new rb_proc_times rb_progname rb_prohibit_interrupt rb_protect rb_protect_inspect rb_provide rb_provided rb_quad_pack rb_quad_unpack rb_raise
 rb_range_beg_len rb_range_new rb_read_check rb_read_pending rb_reg_adjust_startpos rb_reg_eqq rb_reg_last_match rb_reg_match rb_reg_match2 rb_reg_match_last
 rb_reg_match_post rb_reg_match_pre rb_reg_mbclen2 rb_reg_new rb_reg_nth_defined rb_reg_nth_match rb_reg_options rb_reg_quote rb_reg_regcomp rb_reg_regsub
 rb_reg_search rb_remove_event_hook rb_remove_method rb_require rb_require_safe rb_rescue rb_rescue2 rb_reserved_word rb_respond_to rb_rs rb_scan_args
 rb_secure rb_secure_update rb_set_class_path rb_set_end_proc rb_set_kcode rb_set_safe_level rb_singleton_class rb_singleton_class_attached
 rb_singleton_class_clone rb_source_filename rb_stderr rb_stdin rb_stdout rb_str2cstr rb_str2inum rb_str_append rb_str_associate rb_str_associated
 rb_str_buf_append rb_str_buf_cat rb_str_buf_cat2 rb_str_buf_new rb_str_buf_new2 rb_str_cat rb_str_cat2 rb_str_cmp rb_str_concat rb_str_dump rb_str_dup
 rb_str_dup_frozen rb_str_freeze rb_str_hash rb_str_inspect rb_str_intern rb_str_locktmp rb_str_modify rb_str_new rb_str_new2 rb_str_new3 rb_str_new4
 rb_str_new5 rb_str_plus rb_str_resize rb_str_setter rb_str_split rb_str_substr rb_str_times rb_str_to_dbl rb_str_to_inum rb_str_to_str rb_str_unlocktmp
 rb_str_update rb_str_upto rb_string_value rb_string_value_cstr rb_string_value_ptr rb_struct_alloc rb_struct_aref rb_struct_aset rb_struct_define
 rb_struct_getmember rb_struct_iv_get rb_struct_members rb_struct_new rb_struct_s_members rb_svar rb_sym_all_symbols rb_symname_p rb_sys_fail rb_sys_warning
 rb_syswait rb_tainted_str_new rb_tainted_str_new2 rb_thread_alone rb_thread_atfork rb_thread_create rb_thread_critical rb_thread_current rb_thread_fd_close
 rb_thread_fd_writable rb_thread_group rb_thread_interrupt rb_thread_kill rb_thread_list rb_thread_local_aref rb_thread_local_aset rb_thread_main
 rb_thread_pending rb_thread_polling rb_thread_run rb_thread_schedule rb_thread_select rb_thread_signal_exit rb_thread_signal_raise rb_thread_sleep
 rb_thread_sleep_forever rb_thread_stop rb_thread_tick rb_thread_trap_eval rb_thread_wait_fd rb_thread_wait_for rb_thread_wakeup rb_throw rb_time_interval
 rb_time_new rb_time_timeval rb_to_id rb_to_int rb_trap_exec rb_trap_exit rb_trap_immediate rb_trap_pending rb_trap_restore_mask rb_uint2big rb_uint2inum
 rb_ull2big rb_ull2inum rb_undef rb_undef_alloc_func rb_undef_method rb_values_at rb_w32_accept rb_w32_asynchronize rb_w32_bind rb_w32_close rb_w32_closedir
 rb_w32_cmdvector rb_w32_connect rb_w32_enter_critical rb_w32_fclose rb_w32_fdclr rb_w32_fdisset rb_w32_fdset rb_w32_free_environ rb_w32_get_environ
 rb_w32_get_osfhandle rb_w32_getc rb_w32_getcwd rb_w32_getenv rb_w32_gethostbyaddr rb_w32_gethostbyname rb_w32_gethostname rb_w32_getpeername rb_w32_getpid
 rb_w32_getprotobyname rb_w32_getprotobynumber rb_w32_getservbyname rb_w32_getservbyport rb_w32_getsockname rb_w32_getsockopt rb_w32_ioctlsocket rb_w32_isatty
 rb_w32_leave_critical rb_w32_listen rb_w32_main_context rb_w32_mkdir rb_w32_opendir rb_w32_osid rb_w32_putc rb_w32_readdir rb_w32_recv rb_w32_recvfrom
 rb_w32_rename rb_w32_rewinddir rb_w32_rmdir rb_w32_seekdir rb_w32_select rb_w32_send rb_w32_sendto rb_w32_setsockopt rb_w32_shutdown rb_w32_sleep
 rb_w32_snprintf rb_w32_socket rb_w32_stat rb_w32_strerror rb_w32_telldir rb_w32_times rb_w32_unlink rb_w32_utime rb_w32_vsnprintf rb_waitpid rb_warn
 rb_warning rb_with_disable_interrupt rb_write_error rb_write_error2 rb_yield rb_yield_splat rb_yield_values re_mbctab re_set_syntax ruby__end__seen
 ruby_add_suffix ruby_class ruby_cleanup ruby_current_node ruby_debug ruby_digitmap ruby_dln_librefs ruby_dyna_vars ruby_errinfo ruby_eval_tree
 ruby_eval_tree_begin ruby_exec ruby_finalize ruby_frame ruby_getcwd ruby_glob ruby_globi ruby_ignorecase ruby_in_compile ruby_in_eval ruby_incpush ruby_init
 ruby_init_loadpath ruby_inplace_mode ruby_nerrs ruby_options ruby_parser_stack_on_heap ruby_platform ruby_process_options ruby_prog_init ruby_qsort
 ruby_re_adjust_startpos ruby_re_compile_fastmap ruby_re_compile_pattern ruby_re_copy_registers ruby_re_free_pattern ruby_re_free_registers ruby_re_match
 ruby_re_mbcinit ruby_re_search ruby_re_set_casetable ruby_release_date ruby_run ruby_safe_level ruby_scan_hex ruby_scan_oct ruby_scope ruby_script
 ruby_set_argv ruby_set_current_source ruby_set_stack_size ruby_setenv ruby_show_copyright ruby_show_version ruby_signal_name ruby_sourcefile ruby_sourceline
 ruby_stack_check ruby_stack_length ruby_stop ruby_strdup ruby_strtod ruby_top_self ruby_unsetenv ruby_verbose ruby_version ruby_xcalloc ruby_xfree
 ruby_xmalloc ruby_xrealloc ruby_yychar ruby_yydebug ruby_yylval ruby_yyparse setgid sethostent setkey setnetent setprotoent setservent setuid st_add_direct
 st_cleanup_safe st_copy st_delete st_delete_safe st_foreach st_foreach_safe st_free_table st_init_numtable st_init_numtable_with_size st_init_strtable
 st_init_strtable_with_size st_init_table st_init_table_with_size st_insert st_lookup wait waitpid yyerrflag yynerrs yyval
EOL
	curlibname = nil
	# patch the ruby library name based on the current interpreter
	if OS.current == WinOS and pr = WinOS.find_process(Process.pid) and
			rubylib = pr.modules[1..-1].find { |m| m.path =~ /ruby/ }
		data.sub!(/^msvcrt-ruby18/, File.basename(rubylib.path))
	end
	data.each_line { |l|
		list = l.split
		curlibname = list.shift if l[0, 1] != ' '
		list.each { |export| EXPORT[export] = curlibname }
	}
end
end

