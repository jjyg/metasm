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

if ARGV.shift == 'ltrace'
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
	
	foo = {}
	prepare_hook = proc { |mpe, base, export|
		hooklabel = prog.new_unique_label('hook')
		namelabel = prog.new_unique_label('name')
		foo[hooklabel] = foo[namelabel] = nil	# prevent ruby's collection of names (=> dup label => bad)
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
	mods[1..-1].each { |m|
		next if m.path !~ /user32/i
		puts "handling #{File.basename m.path}" if $VERBOSE
		mpe = Metasm::LoadedPE.decode remote_mem[m.addr, 0x1000000]
		mpe.coff.decode_exports
		next if not mpe.coff.export or not mpe.coff.export.exports
		text = mpe.coff.sections.find { |s| s.name == '.text' }
		mpe.coff.export.exports.each { |e|
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
	injected_addr = WinAPI.virtualallocex(handle, 0, main_page.virtsize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	
	binding = {'messageboxw' => msgboxw}
	hooks.each { |addr, edata| binding.update edata.binding(addr) }
	binding.update main_page.binding(injected_addr)
	
	main_page.fixup(binding)
	remote_mem[injected_addr, main_page.data.length] = main_page.data
	hooks.each { |addr, edata|
		edata.fixup(binding)
		remote_mem[addr, edata.data.length] = edata.data
	}

	puts "Injected hooks at #{'%x' % injected_addr}"
	
else
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
end

WinAPI.closehandle(handle)
