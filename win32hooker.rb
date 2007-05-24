require 'metasm'
require 'metasm-shell'

include Metasm
include WinAPI

WinAPI.get_debug_privilege
pids = WinAPI.list_processes
if not pid = ARGV.shift
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
pid = pid.to_i
puts "opening the target process"
exit if not handle = WinAPI.openprocess(PROCESS_ALL_ACCESS, 0, pid)

remote_mem = WindowsRemoteString.new(handle)

pe_base = pids[pid].modules.first.addr
pe = Metasm::LoadedPE.decode remote_mem[pe_base, 0x1000000]
pe.coff.decode_imports

target = nil
msgboxw= nil
pe.coff.imports.each { |id|
	id.imports.each_with_index { |i, idx|
		case i.name
		when 'MessageBoxW'
			msgboxw = id.iat[idx]
		when /WriteFile/
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

overwritten = remote_mem[target, 12].decode_blocks(target, target).block[target].list
puts "  overwritten instructions: ", overwritten.map { |i| i.instruction }, ''
hook = "pushad\njmp hook".encode_edata

hookend = "hook: call shellcode\npopad\n"
sz = 0
while sz < hook.virtsize
	di = overwritten.shift
	hookend << di.instruction.to_s << "\n"
	sz += di.bin_length
end
hookend << "jmp hook_done"
hookend = hookend.encode_edata << myshellcode

injected = WinAPI.virtualallocex(handle, 0, hookend.virtsize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)

binding = hook.binding(target).merge(hookend.binding(injected)).merge('msgboxw' => msgboxw, 'hook_done' => (target + sz))
hook.fixup binding
hookend.fixup binding

remote_mem[target, hook.data.length] = hook.data
remote_mem[injected, hookend.data.length] = hookend.data

puts "  injected at #{'%x' % target}:", hook.data.decode, '', "  at #{'%x' % injected}:", hookend.data.decode

WinAPI.closehandle(handle)
