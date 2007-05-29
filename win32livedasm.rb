require 'metasm'
require 'metasm-shell'

include Metasm
include WinAPI

WinAPI.get_debug_privilege

# select target
pids = WinAPI.list_processes
abort("target not found !") if not pid = pids.keys.find { |k| pids[k].modules and pids[k].modules.first.path =~ /notepad/i }

# open target
raise 'cannot open target process' if not handle = WinAPI.openprocess(PROCESS_ALL_ACCESS, 0, pid)

# virtual string of remote process memory
remote_mem = WindowsRemoteString.new(handle)

baseaddr = pids[pid].modules[0].addr

pe = Metasm::LoadedPE.decode remote_mem[baseaddr, 0x100000]

eip = baseaddr + pe.optheader.entrypoint

# use degraded desasm mode
String.cpu.make_call_return

puts pe.encoded[pe.optheader.entrypoint, 0x100].data.decode(eip, eip)

WinAPI.closehandle(handle)
