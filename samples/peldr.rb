#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# Map a PE file under another OS using DynLdr, API imports are redirected to ruby callback for emulation
#

require 'metasm'

class PeLdr
	attr_accessor :pe, :load_address

	def initialize(file)
		dl = Metasm::DynLdr
		@pe = Metasm::PE.decode_file(file)
		@load_address = dl.memory_alloc(@pe.optheader.image_size)
		raise 'malloc' if @load_address == 0xffff_ffff
		
		puts "map sections" if $DEBUG
		dl.memory_write(@load_address, @pe.encoded.data[0, @pe.optheader.headers_size].to_str)
		@pe.sections.each { |s|
			dl.memory_write(@load_address+s.virtaddr, s.encoded.data.to_str)
		}
		
		puts "fixup sections" if $DEBUG
		off = @load_address - @pe.optheader.image_base
		@pe.relocations.to_a.each { |rt|
			base = rt.base_addr
			rt.relocs.each { |r|
				if r.type == 'HIGHLOW'
					ptr = @load_address + base + r.offset
					old = dl.memory_read(ptr, 4).unpack('V').first
					dl.memory_write(ptr, [old + off].pack('V'))
				end
			}
		}

		puts "hook IAT" if $DEBUG
		@iat_cb = {}
		@pe.imports.to_a.each { |id|
			ptr = @load_address + id.iat_p
			id.imports.each { |i|
				n = "#{id.libname}!#{i.name}"
				cb = dl.callback_alloc_c('void x(void);') { raise "unhandled import #{n}" }
				dl.memory_write(ptr, [cb].pack('V'))
				@iat_cb[n] = cb
				ptr += 4
			}
		}
	end

	def hook_import(libname, impname, proto, &b)
		dl = Metasm::DynLdr
		@pe.imports.to_a.each { |id|
			next if id.libname != libname
			ptr = @load_address + id.iat_p
			id.imports.each { |i|
				if i.name == impname
					dl.callback_free(@iat_cb["#{libname}!#{impname}"])
					cb = dl.callback_alloc_c(proto, &b)
					dl.memory_write(ptr, [cb].pack('V'))
				end
				ptr += 4
			}
		}
	end

	def run_init
		ptr = @pe.optheader.entrypoint
		if ptr != 0
			ptr += @load_address
			Metasm::DynLdr.raw_invoke(ptr, [@load_address, 1, 1], 1)
		end
	end
end

if $0 == __FILE__
	l = PeLdr.new('dbghelp.dll')
	l.hook_import('KERNEL32.dll', 'GetSystemTimeAsFileTime', '__stdcall void f(void*);') { |ptr|
		v = ((Time.now - Time.mktime(1971, 1, 1, 0, 0, 0) + 370*365.25*24*60*60) * 1000 * 1000 * 10).to_i
		Metasm::DynLdr.memory_write(ptr, [v & 0xffffffff, (v >> 32 & 0xffffffff)].pack('VV'))
		0
	}
	l.hook_import('KERNEL32.dll', 'GetCurrentProcessId', '__stdcall int f(void);') { Process.pid }
	l.hook_import('KERNEL32.dll', 'GetCurrentThreadId', '__stdcall int f(void);') { Process.pid }
	l.hook_import('KERNEL32.dll', 'GetTickCount', '__stdcall int f(void);') { (Time.now.to_i * 1000) & 0xffff_ffff }
	l.hook_import('KERNEL32.dll', 'QueryPerformanceCounter', '__stdcall int f(void*);') { |ptr|
		v = (Time.now.to_f * 1000 * 1000).to_i
		Metasm::DynLdr.memory_write(ptr, [v & 0xffffffff, (v >> 32 & 0xffffffff)].pack('VV'))
		1
	}

	# at this point it segfaults on "push dword ptr fs:[0]" lol
	# so we need to setup an ldt and blaaargh

	l.run_init
end
