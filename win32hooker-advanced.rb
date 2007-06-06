require 'metasm'
require 'metasm-shell'

include Metasm
include WinAPI

# open target
WinAPI.get_debug_privilege
if not pr = WinAPI.find_process((Integer(ARGV.first) rescue ARGV.first))
	puts WinAPI.list_processes.sort_by { |pr| pr.pid }.map { |pr| "#{pr.pid}: #{File.basename(pr.modules.first.path) rescue nil}" }
	exit
end
raise 'cannot open target process' if not handle = WinAPI.openprocess(PROCESS_ALL_ACCESS, 0, pr.pid)

# virtual mapping of remote process memory
remote_mem = WindowsRemoteString.new(handle)

# hook all library functions
hooks = {}
prog = Metasm::Program.new Metasm::Ia32.new
prog.parse <<EOS
main_hook:
 push eax
 mov eax, dword ptr [esp+8]
 mov dword ptr [func_name], eax
 pop eax
 pushad
 mov eax, dword ptr [in_hook]	; yay threadsafe
 test eax, eax
 jnz main_hook_done
 mov dword ptr [in_hook], 1

 push 0
 push dword ptr [func_name]
 push dword ptr [func_name]
 push 0
 call messageboxw

 mov dword ptr [in_hook], 0
main_hook_done:
 popad
 ret 4
	
.align 4
func_name dd 0
in_hook   dd 0
EOS
	
prepare_hook = proc { |mpe, base, export|
	hooklabel = prog.new_unique_label('hook')
	namelabel = prog.new_unique_label('name')
	target = base + export.target
	
	# what we will write to replace the entrypoint
	hooks[target] = "jmp #{hooklabel}".encode_edata
	
	# backup the overwritten instructions
	mpe.encoded.ptr = export.target
	sz = 0
	overwritten = []
	while sz < hooks[target].virtsize
		di = prog.cpu.decode prog, mpe.encoded, target
		break if not di or not di.opcode
		overwritten << di.instruction
		sz += di.bin_length
	end
	puts "overwritten at #{export.name}:", overwritten, '' if $DEBUG
	resumeaddr = target + sz
	
	# append the call-specific shellcode to the main hook code
	prog.parse <<EOS, export.name
#{hooklabel}:
 push #{namelabel}
 call main_hook		; log the call
#{overwritten.join("\n")}		; run the overwritten instructions
 jmp #{resumeaddr}	; get back to original code flow
#{namelabel} dw #{export.name.inspect}, 0
EOS
}
	
msgboxw = nil
pr.modules[1..-1].each { |m|
	next if m.path !~ /user32/i
	puts "handling #{File.basename m.path}" if $VERBOSE
	mpe = Metasm::LoadedPE.decode remote_mem[m.addr, 0x1000000]
	next if not mpe.export or not mpe.export.exports
	text = mpe.sections.find { |s| s.name == '.text' }
	mpe.export.exports.each { |e|
		next if not e.target or not e.name
		e.target = mpe.encoded.export[e.target] if mpe.encoded.export[e.target]
		next if e.target < text.virtaddr or e.target >= text.virtaddr + text.virtsize
		
		msgboxw = m.addr + e.target if e.name == 'MessageBoxW'
		
		prepare_hook[mpe, m.addr, e]
	}
}
	
raise 'Did not find MessageBoxW' if not msgboxw
	
prog.encode
main_page = prog.sections.first.encoded
raise 'remote allocation failed' if not injected_addr = WinAPI.virtualallocex(handle, 0, main_page.virtsize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	
puts "Injecting hooks at #{'%x' % injected_addr}"

binding = {'messageboxw' => msgboxw}
hooks.each { |addr, edata| binding.update edata.binding(addr) }
binding.update main_page.binding(injected_addr)

main_page.fixup(binding)
remote_mem[injected_addr, main_page.data.length] = main_page.data
hooks.each { |addr, edata|
	edata.fixup(binding)
	remote_mem[addr, edata.data.length] = edata.data
}

puts 'done'

WinAPI.closehandle(handle)
