require 'metasm'
require 'metasm-shell'

include Metasm
include WinAPI

WinAPI.get_debug_privilege

# select target
pid = ARGV.shift
pid = Integer(pid) if pid rescue nil
pids = WinAPI.list_processes
if not pid
	puts pids.sort.transpose.last
	exit
end
if not pids[pid]
	abort("target not found !") if not pid = pids.keys.find { |k| pids[k].modules and pids[k].modules.first.path =~ /#{pid}/i }
	puts "using pid #{pid} #{File.basename pids[pid].modules.first.path}"
end

# open target
raise 'cannot open target process' if not handle = WinAPI.openprocess(PROCESS_ALL_ACCESS, 0, pid)

# virtual string of remote process memory
remote_mem = WindowsRemoteString.new(handle)

mods = pids[pid].modules

# hook iat
pe = Metasm::LoadedPE.decode remote_mem[mods[0].addr, 0x1000000]
pe.decode_imports

# find iat entries
target = nil
target_p = nil
msgboxw_p = nil
pe.imports.each { |id|
	id.imports.each_with_index { |i, idx|
		case i.name
		when 'MessageBoxW'
			msgboxw_p = mods[0].addr + id.iat_p + (pe.optheader.sig == 'PE+' ? 8 : 4) * idx
		when /WriteFile/
			target_p  = mods[0].addr + id.iat_p + (pe.optheader.sig == 'PE+' ? 8 : 4) * idx
			target = id.iat[idx]
		end
	}
}
raise "target not found" if not target or not msgboxw_p

myshellcode = <<EOS.encode_edata
pushad
mov esi, dword ptr [esp+20h+8]	; 2nd arg = buffer
mov edi, message
mov ecx, 19
xor eax, eax
copy_again:
lodsb
stosw
loop copy_again

push 0
push title
push message
push 0
call [msgboxw]
popad
jmp  target

.align 4
; strings to display
title dw 'I see what you did there...', 0
message dw 20 dup(?)
EOS

raise 'remote allocation failed' if not injected = WinAPI.virtualallocex(handle, 0, myshellcode.virtsize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
puts "injected malicous code at %x" % injected

myshellcode.fixup myshellcode.binding(injected).merge('msgboxw' => msgboxw_p, 'target' => target)

# write shellcode in remote process
remote_mem[injected, myshellcode.data.length] = myshellcode.data
# rewrite iat entry
iat_h = pe.encode_xword(injected)
remote_mem[target_p, iat_h.data.length] = iat_h.data

WinAPI.closehandle(handle)
