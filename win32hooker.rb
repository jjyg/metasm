require 'metasm'

getdebugprivilege
if not pid = ARGV.shift
	puts list_processes.sort.map { |k, v| "pid #{k} => #{v}" }
	exit
end

handle = openprocess(pid.to_i)
r = inject(handle, 'Kikoo LOL')
p r
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
		hash[pid] = name
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
def inject(h, str)
	retaddr = VirtualAllocEx.call(h, 0, str.length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if (retaddr == 0)
		w32err('VirtualAllocEx')
		return
	end
	if (WriteProcessMemory.call(h, retaddr, str, str.length, nil) == 0)
		w32err('WriteProcessMemory')
		return
	end
	retaddr
end
}
