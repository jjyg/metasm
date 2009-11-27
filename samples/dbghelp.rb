#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# a preleminary attempt to use MS dbghelp.dll to retrieve PE symbols


require 'metasm'

dll = 'C:\\Program Files\\Debugging Tools For Windows (x86)\\dbghelp.dll'
SYMOPT = 4|0x80000	# defered_load no_prompt
Metasm::WinAPI.new_api dll, 'SymInitialize', 'III I'
Metasm::WinAPI.new_api dll, 'SymGetOptions', 'I'
Metasm::WinAPI.new_api dll, 'SymSetOptions', 'I I'
Metasm::WinAPI.new_api dll, 'SymSetSearchPath', 'IP I'
Metasm::WinAPI.new_api dll, 'SymLoadModule64', 'IIPIIII I'	# ???ull?
Metasm::WinAPI.new_api dll, 'SymFromAddr', 'IIIPP I'	# handle ull_addr poffset psym

class Tracer < Metasm::WinDbgAPI
	def initialize(*a)
		super(*a)
		loop
		puts 'finished'
	end

	def handler_newprocess(pid, tid, info)
		puts "newprocess: init symsrv"

		h = @hprocess[pid]
		Metasm::WinAPI.syminitialize(h, 0, 0)
		Metasm::WinAPI.symsetoptions(Metasm::WinAPI.symgetoptions|SYMOPT)
		Metasm::WinAPI.symsetsearchpath(h, (ENV['_NT_SYMBOL_PATH'] || 'srv**symbols*http://msdl.microsoft.com/download/symbols').dup)	# dup because ENV is frozen

		Metasm::WinAPI::DBG_CONTINUE
	end

	def handler_loaddll(pid, tid, info)
		pe = Metasm::LoadedPE.load(@mem[pid][info.imagebase, 0x1000000])
		pe.decode_header
		pe.decode_exports
		return if not pe.export
		libname = pe.export.libname
		puts "loaddll: #{libname} @#{'%x' % info.imagebase}"
		h = @hprocess[pid]
		Metasm::WinAPI.symloadmodule64(h, 0, libname, 0, info.imagebase, 0, pe.optheader.image_size)
		# XXX struct should be 0x50 wide but Value is 8 aligned despite pack(4)
		symstruct = [0x58].pack('L') + 0.chr*4*19 + [512].pack('L')	# sizeofstruct, ..., nameszmax
		text = pe.sections.find { |s| s.name == '.text' }
		# XXX should SymEnumSymbols, but win32api callbacks sucks
		text.rawsize.times { |o|
			sym = symstruct + 0.chr*512	# name concat'ed after the struct
			off = 0.chr*8
			if Metasm::WinAPI.symfromaddr(h, info.imagebase+text.virtaddr+o, 0, off, sym) and off.unpack('L').first == 0
				symnamelen = sym[19*4, 4].unpack('L').first
				puts ' %x %s' % [text.virtaddr+o, sym[0x54, symnamelen]]
			end
			puts '  %x/%x' % [o, text.rawsize] if $VERBOSE and o & 0xffff == 0
		}
		puts
	end
end

if $0 == __FILE__
	Metasm::WinOS.get_debug_privilege
	if ARGV.empty?
		# display list of running processes if no target found
		puts Metasm::WinOS.list_processes.sort_by { |pr_| pr_.pid }
		abort 'target needed'
	end
	pid = ARGV.shift.dup
	if pr = Metasm::WinOS.find_process(pid)
		pid = pr.pid
	end
	Tracer.new pid
end
