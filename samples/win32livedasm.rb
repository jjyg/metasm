#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


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

baseaddr = pr.modules[0].addr

pe = Metasm::LoadedPE.decode remote_mem[baseaddr, 0x100000]

eip = baseaddr + pe.optheader.entrypoint

# use degraded desasm mode
String.cpu.make_call_return

puts pe.encoded[pe.optheader.entrypoint, 0x100].data.decode(eip, eip)

WinAPI.closehandle(handle)
