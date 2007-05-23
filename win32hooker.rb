require 'metasm'
require 'metasm-shell'

getdebugprivilege
pids = list_processes
if not pid = ARGV.shift
	puts pids.sort.map { |pid, (name, addr)| "pid #{pid} => #{name} (#{'%08x' % addr})" }
	pid = pids.keys.find { |pid| pids[pid][0] =~ /notepad/i }
	exit if not pid
end
pid = pid.to_i

handle = openprocess(pid)

# read the PE headers
data = read(handle, pids[pid][1], 4096)
pe = Metasm::LoadedPE.decode(data)

data = read(handle, pids[pid][1], pe.coff.optheader.image_size)
pe = Metasm::LoadedPE.decode(data)
pe.coff.decode_imports

target = nil
msgboxw= nil
pe.coff.imports.each { |id|
	id.imports.each_with_index { |i, idx|
		case i.name
		when 'MessageBoxW'
			msgboxw = id.iat[idx]
		when /Write/
			p i
			target = id.iat[idx]
		end
	}
}
raise "target not found" if not target or not msgboxw

myshellcode = <<EOS.encode_edata
shellcode:
push 0
push title
push message
push 0
call msgboxw
ret
title dw 'kikoo lol', 0
message dw 'HI GUISE', 0
EOS

overwritten = read(handle, target, 12)
b = overwritten.decode_blocks(target, target).block[target].list
# puts "overwritten instructions: ", b.map { |i| i.instruction }
hook = "pushad\njmp hook".encode_edata

hookend = "call shellcode\npopad\n"
sz = 0
while sz < hook.virtsize
	di = b.shift
	hookend << di.instruction.to_s << "\n"
	sz += di.bin_length
end
hookend << "jmp hook_done\nshellcode:"
hookend = hookend.encode_edata << myshellcode

injected = alloc(handle, hookend.virtsize)

hook.fixup hook.internal_binding(target).merge('hook' => injected)
hookend.fixup hookend.internal_binding(injected).merge('msgboxw' => msgboxw, 'hook_done' => (target + sz))

write(handle, target, hook.data)
write(handle, injected, hookend.data)

puts "injected:", "at #{'%x' % target}:", hook.data.decode, "at #{'%x' % injected}:", hookend.data[5..-1].decode


closehandle(handle)




BEGIN {
require 'Win32API'

module W32API
	def self.api(lib, name, args)
		args = args.delete(' ').split(//)
		retval = args.pop
		const_set(name, Win32API.new(lib, name, args, retval))
	end
	
	api 'psapi', 'EnumProcesses', 'PIP I'
	api 'psapi', 'EnumProcessModules', 'IPIP I'
	api 'psapi', 'GetModuleBaseName', 'IIPI I'
	api 'kernel32', 'CloseHandle', 'I I'
	api 'kernel32', 'OpenProcess', 'III I'
	api 'kernel32', 'GetLastError', 'I'
	api 'kernel32', 'FormatMessage', 'IPIIPIP I'
	api 'advapi32', 'OpenProcessToken', 'IIP I'
	api 'kernel32', 'GetCurrentProcess', 'I'
	api 'advapi32', 'LookupPrivilegeValueA', 'PPP I'
	api 'advapi32', 'AdjustTokenPrivileges', 'IIPIPP I'
	api 'kernel32', 'VirtualAllocEx', 'IIIII I'
	api 'kernel32', 'ReadProcessMemory', 'IIPIP I'
	api 'kernel32', 'WriteProcessMemory', 'IIPIP I'
	
	
	PROCESS_QUERY_INFORMATION = 0x400
	FORMAT_MESSAGE_FROM_SYSTEM = 0x1000
	PROCESS_VM_READ = 0x10
	TOKEN_ADJUST_PRIVILEGES = 0x20
	TOKEN_QUERY = 0x8
	SE_DEBUG_NAME = 'SeDebugPrivilege'
	SE_PRIVILEGE_ENABLED = 0x2
	PROCESS_ALL_ACCESS = 0x1FFFFF
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40

	def w32err(fun = '')
		errmsg = ' '*512
		if (FormatMessage.call(FORMAT_MESSAGE_FROM_SYSTEM, nil, GetLastError.call, 0, errmsg, errmsg.length, nil) == 0)
			errmsg = 'unknown error'
		else
			errmsg = errmsg[0, errmsg.index(0)] if errmsg.index(0)
		end
		puts "Error with #{fun}: #{errmsg}"
	end
end

class String ; def int ; self.unpack('L').first end end
def new_int ; '    ' end

include W32API

def getdebugprivilege
	htok = new_int
	if (OpenProcessToken.call(GetCurrentProcess.call, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, htok) == 0)
		w32err('OpenProcessToken')
		return
	end
	luid = new_int * 2
	if (LookupPrivilegeValueA.call(nil, SE_DEBUG_NAME, luid) == 0)
		w32err('LookupPrivilegeValue')
		return
	end
	
	# priv.PrivilegeCount = 1;
	# priv.Privileges[0].Luid = luid;
	# priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	priv = ([1] + luid.unpack('L*') + [SE_PRIVILEGE_ENABLED]).pack('L*')
	if (AdjustTokenPrivileges.call(htok.int, 0, priv, priv.length, nil, nil) == 0)
		w32err('AdjustTokenPrivileges')
		return
	end
	puts "getdebugprivilege successful"
end

def list_processes
	tab = " "*4096
	int = new_int
	ret = EnumProcesses.call(tab, tab.length, int)
	if ret == 0
		w32err "EnumProcesses"
		return
	end
	pids = tab[0, int.int].unpack('L*')
	hash = {}
	pids.each { |pid|
		handle = OpenProcess.call(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid)
		mod = new_int
		ret = new_int
		if (handle != 0)
			if (EnumProcessModules.call(handle, mod, mod.length, ret) == 0)
				w32err('EnumProcessModules')
				name = 'unknown'
			else
				name = ' ' * 512
				len = GetModuleBaseName.call(handle, mod.int, name, name.length)
				name = name[0, len]
			end
			CloseHandle.call(handle)
		else
			name = 'unknown'
		end
		hash[pid] = [name, mod.int]
	}
	hash
end

def openprocess(pid)
	if ((handle = OpenProcess.call(PROCESS_ALL_ACCESS, 0, pid)) == 0)
		w32err('OpenProcess')
		return
	end
	handle
end
def closehandle(h)
	CloseHandle.call(h)
end
def alloc(h, len)
	retaddr = VirtualAllocEx.call(h, 0, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if (retaddr == 0)
		w32err('VirtualAllocEx')
		return
	end
	retaddr
end
def read(h, addr, rqlen)
	len = new_int
	str = ' ' * rqlen
	if (ReadProcessMemory.call(h, addr, str, rqlen, len) == 0)
		w32err('ReadProcessMemory')
		return
	end
	len = len.int
	str[len..-1] = ''
	str
end
def write(h, addr, str)
	if (WriteProcessMemory.call(h, addr, str, str.length, nil) == 0)
		w32err('WriteProcessMemory')
		return
	end
end
}
