require 'metasm'
require 'metasm-shell'

include Metasm
include WinAPI

WinAPI.get_debug_privilege
pids = WinAPI.list_processes

pid = ARGV.shift
pid = Integer(pid) rescue pid
if not pid
	# show list of processes
	puts pids.sort.map { |pid, pr|
		"#{pid}:".ljust(6) +
		if pr.modules and m = pr.modules.first
			('%08x ' % m.addr) + File.basename(m.path)
		else
			'<unknown>'
		end
	}
	exit
end
if not pids[pid]
	exit if not pid = pids.keys.find { |k| pids[k].modules and pids[k].modules.first.path =~ /#{pid}/i }
	puts "using pid #{pid} #{File.basename pids[pid].modules.first.path}"
end

# open target
pid = pid.to_i
raise 'cannot open target process' if not handle = WinAPI.openprocess(PROCESS_ALL_ACCESS, 0, pid)

# virtual string of remote process memory
remote_mem = WindowsRemoteString.new(handle)

mods = pids[pid].modules

# hook iat
pe = Metasm::LoadedPE.decode remote_mem[mods[0].addr, 0x1000000]
pe.coff.decode_imports

# find iat entries
target = nil
target_p = nil
msgboxw_p = nil
pe.coff.imports.each { |id|
	id.imports.each_with_index { |i, idx|
		case i.name
		when 'MessageBoxW'
			msgboxw_p = mods[0].addr + id.iat_p + (pe.coff.optheader.sig == 'PE+' ? 8 : 4) * idx
		when /WriteFile/
			target_p  = mods[0].addr + id.iat_p + (pe.coff.optheader.sig == 'PE+' ? 8 : 4) * idx
			target = id.iat[idx]
		end
	}
}
raise "target not found" if not target or not msgboxw_p

myshellcode = <<EOS.encode_edata
push 0
push title
push message
push 0
call [msgboxw]
jmp  target
	
; strings to display
title dw 'kikoo lol', 0
message dw 'HI GUISE', 0
EOS

injected = WinAPI.virtualallocex(handle, 0, myshellcode.virtsize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
raise 'failed to virtualallocex remote memory' if not injected

myshellcode.fixup myshellcode.binding(injected).merge('msgboxw' => msgboxw_p, 'target' => target)

# write shellcode in remote process
remote_mem[injected, myshellcode.data.length] = myshellcode.data
# rewrite iat entry
iat_h = pe.coff.encode_xword(injected)
remote_mem[target_p, iat_h.data.length] = iat_h.data

WinAPI.closehandle(handle)
