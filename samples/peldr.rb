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
	DL = Metasm::DynLdr

	# load a PE file, setup basic IAT hooks (raises "unhandled lib!import")
	def initialize(file)
		@pe = Metasm::PE.decode_file(file)
		@load_address = DL.memory_alloc(@pe.optheader.image_size)
		raise 'malloc' if @load_address == 0xffff_ffff
		
		puts "map sections" if $DEBUG
		DL.memory_write(@load_address, @pe.encoded.data[0, @pe.optheader.headers_size].to_str)
		@pe.sections.each { |s|
			DL.memory_write(@load_address+s.virtaddr, s.encoded.data.to_str)
		}
		
		puts "fixup sections" if $DEBUG
		off = @load_address - @pe.optheader.image_base
		@pe.relocations.to_a.each { |rt|
			base = rt.base_addr
			rt.relocs.each { |r|
				if r.type == 'HIGHLOW'
					ptr = @load_address + base + r.offset
					old = DL.memory_read(ptr, 4).unpack('V').first
					DL.memory_write(ptr, [old + off].pack('V'))
				end
			}
		}

		puts "hook IAT" if $DEBUG
		@iat_cb = {}
		@pe.imports.to_a.each { |id|
			ptr = @load_address + id.iat_p
			id.imports.each { |i|
				n = "#{id.libname}!#{i.name}"
				cb = DL.callback_alloc_c('void x(void);') { raise "unhandled import #{n}" }
				DL.memory_write(ptr, [cb].pack('V'))
				@iat_cb[n] = cb
				ptr += 4
			}
		}
	end

	# add a specific hook for an IAT function
	# exemple: hook_import('KERNEL32.dll', 'GetProcAddress', '__stdcall int f(int, char*);') { |h, name| puts "getprocaddr #{name}" ; 0 }
	def hook_import(libname, impname, proto, &b)
		@pe.imports.to_a.each { |id|
			next if id.libname != libname
			ptr = @load_address + id.iat_p
			id.imports.each { |i|
				if i.name == impname
					DL.callback_free(@iat_cb["#{libname}!#{impname}"])
					cb = DL.callback_alloc_c(proto, &b)
					DL.memory_write(ptr, [cb].pack('V'))
				end
				ptr += 4
			}
		}
	end

	# run the loaded PE entrypoint
	def run_init
		ptr = @pe.optheader.entrypoint
		if ptr != 0
			ptr += @load_address
			DL.raw_invoke(ptr, [@load_address, 1, 1], 1)
		end
	end

	# maps a TEB/PEB in the current process, sets the fs register to point to it
	def self.setup_teb
		@@teb = DL.memory_alloc(4096)
		@@peb = DL.memory_alloc(4096)
		populate_teb
		populate_peb
		fs = allocate_ldt_entry_teb
		DL.new_func_c('__fastcall void set_fs(int i) { asm("mov fs, ecx"); }') { DL.set_fs(fs) }
	end

	# fills a fake TEB structure
	def self.populate_teb
		set = lambda { |off, val| DL.memory_write(@@teb+off, [val].pack('V')) }
		# the stack will probably never go higher than that whenever in the dll...
		set[0x4, DL.new_func_c('int get_sp(void) { asm("mov eax, esp  and eax, ~0xfff"); }') { DL.get_sp }]
		set[0x8, 0x10000]
		set[0x18, @@teb]
		set[0x30, @@peb]
	end

	def self.populate_peb
		set = lambda { |off, val| DL.memory_write(@@peb+off, [val].pack('V')) }
	end

	# allocate an LDT entry for the teb, returns a value suitable for the fs selector
	def self.allocate_ldt_entry_teb
		entry = 1
		# ldt_entry base_addr size_in_pages
		# 32bits:1 type:2 (0=data) readonly:1 limit_in_pages:1 seg_not_present:1 usable:1
		struct = [entry, @@teb, 1, 0b1_0_1_0_00_1].pack('VVVV')
		Kernel.syscall(123, 1, DL.str_ptr(struct), struct.length)
		(entry << 3) | 7
	end

	setup_teb
end

if $0 == __FILE__
	dl = Metasm::DynLdr
	l = PeLdr.new('dbghelp.dll')
	l.hook_import('KERNEL32.dll', 'GetSystemTimeAsFileTime', '__stdcall void f(void*);') { |ptr|
		v = ((Time.now - Time.mktime(1971, 1, 1, 0, 0, 0) + 370*365.25*24*60*60) * 1000 * 1000 * 10).to_i
		dl.memory_write(ptr, [v & 0xffffffff, (v >> 32 & 0xffffffff)].pack('VV'))
		0
	}
	l.hook_import('KERNEL32.dll', 'GetCurrentProcessId', '__stdcall int f(void);') { Process.pid }
	l.hook_import('KERNEL32.dll', 'GetCurrentThreadId', '__stdcall int f(void);') { Process.pid }
	l.hook_import('KERNEL32.dll', 'GetTickCount', '__stdcall int f(void);') { (Time.now.to_i * 1000) & 0xffff_ffff }
	l.hook_import('KERNEL32.dll', 'QueryPerformanceCounter', '__stdcall int f(void*);') { |ptr|
		v = (Time.now.to_f * 1000 * 1000).to_i
		dl.memory_write(ptr, [v & 0xffffffff, (v >> 32 & 0xffffffff)].pack('VV'))
		1
	}
	l.hook_import('KERNEL32.dll', 'InterlockedCompareExchange', '__stdcall int f(void*, int, int)'+
		'{ asm("mov eax, [ebp+16]  mov ecx, [ebp+12]  mov edx, [ebp+8]  lock cmpxchg [edx], ecx"); }')

	l.run_init
end
