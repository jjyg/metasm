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
	def initialize(file, hooktype=:iat)
		if file.kind_of? Metasm::PE
			@pe = file
		elsif file[0, 2] == 'MZ' and file.length > 0x3c
			@pe = Metasm::PE.decode(file)
		else	# filename
			@pe = Metasm::PE.decode_file(file)
		end
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
					DL.memory_write_int(ptr, old + off)
				end
			}
		}

		@iat_cb = {}
		@eat_cb = {}
		case hooktype
		when :iat
			puts "hook IAT" if $DEBUG
			@pe.imports.to_a.each { |id|
				ptr = @load_address + id.iat_p
				id.imports.each { |i|
					n = "#{id.libname}!#{i.name}"
					cb = DL.callback_alloc_c('void x(void)') { raise "unemulated import #{n}" }
					DL.memory_write_int(ptr, cb)
					@iat_cb[n] = cb
					ptr += 4
				}
			}
		when :eat, :exports
			puts "hook EAT" if $DEBUG
			ptr = @load_address + @pe.export.func_p
			@pe.export.exports.each { |e|
				n = e.name || e.ordinal
				cb = DL.callback_alloc_c('void x(void)') { raise "unemulated export #{n}" }
				DL.memory_write_int(ptr, cb)
				@eat_cb[n] = cb
				ptr += 4
			}
		end
	end

	# reset original expected memory protections for the sections
	# the IAT may reside in a readonly section, so call this only after all hook_imports
	def reprotect_sections
		@pe.sections.each { |s|
			p = ''
			p << 'r' if s.characteristics.include? 'MEM_READ'
			p << 'w' if s.characteristics.include? 'MEM_WRITE'
			p << 'x' if s.characteristics.include? 'MEM_EXECUTE'
			DL.memory_perm(@load_address + s.virtaddr, s.virtsize, p)
		}
	end

	# add a specific hook for an IAT function
	# exemple: hook_import('KERNEL32.dll', 'GetProcAddress', '__stdcall int f(int, char*)') { |h, name| puts "getprocaddr #{name}" ; 0 }
	def hook_import(libname, impname, proto, &b)
		@pe.imports.to_a.each { |id|
			next if id.libname != libname
			ptr = @load_address + id.iat_p
			id.imports.each { |i|
				if i.name == impname
					DL.callback_free(@iat_cb["#{libname}!#{impname}"])
					cb = DL.callback_alloc_c(proto, &b)
					DL.memory_write_int(ptr, cb)
				end
				ptr += 4
			}
		}
	end

	# add a specific hook in the export table
	# exemple: hook_export('ExportedFunc', '__stdcall int f(int, char*)') { |i, p| blabla ; 1 }
	def hook_export(name, proto, &b)
		ptr = @load_address + @pe.export.func_p
		@pe.export.exports.each { |e|
			n = e.name || e.ordinal
			if n == name
				DL.callback_free(@eat_cb[name])
				cb = DL.callback_alloc_c(proto, &b)
				DL.memory_write_int(ptr, cb)
			end
			ptr += 4
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

	# similar to DL.new_api_c for the mapped PE
	def new_api_c(proto)
		proto += ';'    # allow 'int foo()'
		cp = DL.host_cpu.new_cparser
		cp.parse(proto)
		cp.toplevel.symbol.each_value { |v|
			next if not v.kind_of? Metasm::C::Variable      # enums
			if e = pe.export.exports.find { |e_| e_.name == v.name and e_.target }
				DL.new_caller_for(cp, v, v.name.downcase, @load_address + pe.label_rva(e.target))
			end
		}

		cp.numeric_constants.each { |k, v|
			n = k.upcase
			n = "C#{n}" if n !~ /^[A-Z]/
			DL.const_set(n, v) if not DL.const_defined?(n) and v.kind_of? Integer
		}
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
		set = lambda { |off, val| DL.memory_write_int(@@teb+off, val) }
		# the stack will probably never go higher than that whenever in the dll...
		set[0x4, DL.new_func_c('int get_sp(void) { asm("mov eax, esp  and eax, ~0xfff"); }') { DL.get_sp }]
		set[0x8, 0x10000]
		set[0x18, @@teb]
		set[0x30, @@peb]
	end

	def self.populate_peb
		set = lambda { |off, val| DL.memory_write_int(@@peb+off, val) }
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
	heap = {}
	malloc = lambda { |sz| str = 0.chr*sz ; ptr = dl.str_ptr(str) ; heap[ptr] = str ; ptr }
	lasterr = 0

	l = PeLdr.new('dbghelp.dll')

	puts 'dbg@%x' % l.load_address
	l.hook_import('KERNEL32.dll', 'EnterCriticalSection', '__stdcall int f(void*)') { 1 }
	l.hook_import('KERNEL32.dll', 'GetCurrentProcess', '__stdcall int f(void)') { -1 }
	l.hook_import('KERNEL32.dll', 'GetCurrentProcessId', '__stdcall int f(void)') { Process.pid }
	l.hook_import('KERNEL32.dll', 'GetCurrentThreadId', '__stdcall int f(void)') { Process.pid }
	l.hook_import('KERNEL32.dll', 'GetLastError', '__stdcall int f(void)') { lasterr }
	l.hook_import('KERNEL32.dll', 'GetSystemInfo', '__stdcall void f(void*)') { |ptr|
		dl.memory_write(ptr, [0, 0x1000, 0x10000, 0x7ffeffff, 1, 1, 586, 0x10000, 0].pack('V*'))
		1
	}
	l.hook_import('KERNEL32.dll', 'GetSystemTimeAsFileTime', '__stdcall void f(void*)') { |ptr|
		v = ((Time.now - Time.mktime(1971, 1, 1, 0, 0, 0) + 370*365.25*24*60*60) * 1000 * 1000 * 10).to_i
		dl.memory_write(ptr, [v & 0xffffffff, (v >> 32 & 0xffffffff)].pack('VV'))
		1
	}
	l.hook_import('KERNEL32.dll', 'GetTickCount', '__stdcall int f(void)') { (Time.now.to_i * 1000) & 0xffff_ffff }
	l.hook_import('KERNEL32.dll', 'GetVersion', '__stdcall int f(void)') { 0xa28501 }	# xpsp1 (?)
	l.hook_import('KERNEL32.dll', 'GetVersionExA', '__stdcall int f(void*)') { |ptr|
		sz = dl.memory_read(ptr, 4).unpack('V').first
		data = [5, 1, 2600, 2, 'Service pack 3', 3, 0].pack('VVVVa128VV')
		dl.memory_write(ptr+4, data[0, sz-4])
		1
	}
	l.hook_import('KERNEL32.dll', 'HeapAlloc', '__stdcall int f(int, int, int)') { |h, f, sz| malloc[sz] }
	l.hook_import('KERNEL32.dll', 'HeapCreate', '__stdcall int f(int, int, int)') { 1 }
	l.hook_import('KERNEL32.dll', 'HeapFree', '__stdcall int f(int, int, int)') { |h, f, p| heap.delete p ; 1 }
	l.hook_import('KERNEL32.dll', 'InterlockedCompareExchange', '__stdcall int f(int*, int, int)'+
		'{ asm("mov eax, [ebp+16]  mov ecx, [ebp+12]  mov edx, [ebp+8]  lock cmpxchg [edx], ecx"); }')
	l.hook_import('KERNEL32.dll', 'InterlockedExchange', '__stdcall int f(int*, int)'+
		'{ asm("mov eax, [ebp+12]  mov ecx, [ebp+8]  lock xchg [ecx], eax"); }')
	l.hook_import('KERNEL32.dll', 'InitializeCriticalSectionAndSpinCount', '__stdcall int f(int, int)') { 1 }
	l.hook_import('KERNEL32.dll', 'InitializeCriticalSection', '__stdcall int f(void*)') { 1 }
	l.hook_import('KERNEL32.dll', 'LeaveCriticalSection', '__stdcall int f(void*)') { 1 }
	l.hook_import('KERNEL32.dll', 'QueryPerformanceCounter', '__stdcall int f(void*)') { |ptr|
		v = (Time.now.to_f * 1000 * 1000).to_i
		dl.memory_write(ptr, [v & 0xffffffff, (v >> 32 & 0xffffffff)].pack('VV'))
		1
	}
	l.hook_import('KERNEL32.dll', 'SetLastError', '__stdcall void f(int)') { |i| lasterr = i ; 1 }
	l.hook_import('KERNEL32.dll', 'TlsAlloc', '__stdcall int f(void)') { 1 }

	l.hook_import('msvcrt.dll', 'free', 'void f(int)') { |i| heap.delete i ; 0}
	l.hook_import('msvcrt.dll', 'malloc', 'int f(int)') { |i| malloc[i] }
	l.hook_import('msvcrt.dll', 'memset', 'int f(char* p, int c, int n) { while (n--) p[n] = c; return p; }')
	l.hook_import('msvcrt.dll', '??2@YAPAXI@Z', 'int f(int)') { |i| raise 'fuuu' if i > 0x100000 ; malloc[i] } # at some point we're called with a ptr as arg, may be a peldr bug
	l.hook_import('msvcrt.dll', '_initterm', 'void f(void (**p)(void), void*p2) { while(p < p2) { if (*p) (**p)(); p++; } }')
	l.hook_import('msvcrt.dll', '_lock', 'void f(int)') { 0 }
	l.hook_import('msvcrt.dll', '_unlock', 'void f(int)') { 0 }
	l.hook_import('msvcrt.dll', '_wcslwr', 'int f(__int16* p) { int i=-1; while (p[++i]) p[i] |= 0x20; return p; }')
	l.hook_import('msvcrt.dll', '_wcsdup', 'int f(__int16* p)') { |p|
		cp = ''
		until (wc = dl.memory_read(p, 2)) == 0.chr*2
			cp << wc
			p += 2
		end
		cp << wc
		heap[dl.str_ptr(cp)] = cp
		dl.str_ptr(cp)
	}
	l.hook_import('msvcrt.dll', '__dllonexit', 'int f(int, int, int)') { |i, ii, iii| i }

	# generate a fake PE which exports stuff found in k32/ntdll, so that dbghelp may find some exports
	# (it does a GetModuleHandle & parses the PE in memory)
	if true
	elist = Metasm::WindowsExports::EXPORT.map { |k, v| k if v =~ /kernel32/i }.compact
	src = ".libname 'kernel32.dll'\ndummy: int 3\n" + elist.map { |e| ".export #{e.inspect} dummy" }.join("\n")
	k32 = PeLdr.new Metasm::PE.assemble(l.pe.cpu, src).encode_string(:lib), :eat
	else
	k32 = PeLdr.new 'kernel32.dll', :eat
	end
	puts 'k32@%x' % k32.load_address
	k32.reprotect_sections

	if true
	elist = Metasm::WindowsExports::EXPORT.map { |k, v| k if v =~ /ntdll/i }.compact
	src = ".libname 'ntdll.dll'\ndummy: int 3\n" + elist.map { |e| ".export #{e.inspect} dummy" }.join("\n")
	nt = PeLdr.new Metasm::PE.assemble(l.pe.cpu, src).encode_string(:lib), :eat
	else
	nt = PeLdr.new 'ntdll.dll', :eat
	end
	puts 'nt@%x' % nt.load_address
	nt.reprotect_sections
	
	l.hook_import('KERNEL32.dll', 'GetModuleHandleA', '__stdcall int f(char*)') { |ptr|
		s = dl.memory_read_strz(ptr) if ptr != 0
		case s
		when /kernel32/i; k32.load_address
		when /ntdll/i; nt.load_address
		else 0
		end
	}
	l.hook_import('KERNEL32.dll', 'LoadLibraryA', '__stdcall int f(char*)') { |ptr|
		s = dl.memory_read_strz(ptr)
		case s
		when /kernel32/i; k32.load_address
		when /ntdll/i; nt.load_address
		else puts "LoadLibrary #{s.inspect}" ; 0
		end
	}


	l.reprotect_sections

	l.new_api_c <<EOS
#define SYMOPT_CASE_INSENSITIVE         0x00000001
#define SYMOPT_UNDNAME                  0x00000002
#define SYMOPT_DEFERRED_LOADS           0x00000004
#define SYMOPT_NO_CPP                   0x00000008
#define SYMOPT_LOAD_LINES               0x00000010
#define SYMOPT_OMAP_FIND_NEAREST        0x00000020
#define SYMOPT_LOAD_ANYTHING            0x00000040
#define SYMOPT_IGNORE_CVREC             0x00000080
#define SYMOPT_NO_UNQUALIFIED_LOADS     0x00000100
#define SYMOPT_FAIL_CRITICAL_ERRORS     0x00000200
#define SYMOPT_EXACT_SYMBOLS            0x00000400
#define SYMOPT_ALLOW_ABSOLUTE_SYMBOLS   0x00000800
#define SYMOPT_IGNORE_NT_SYMPATH        0x00001000
#define SYMOPT_INCLUDE_32BIT_MODULES    0x00002000
#define SYMOPT_PUBLICS_ONLY             0x00004000
#define SYMOPT_NO_PUBLICS               0x00008000
#define SYMOPT_AUTO_PUBLICS             0x00010000
#define SYMOPT_NO_IMAGE_SEARCH          0x00020000
#define SYMOPT_SECURE                   0x00040000
#define SYMOPT_NO_PROMPTS               0x00080000
#define SYMOPT_DEBUG                    0x80000000

typedef int BOOL;
typedef char CHAR;
typedef unsigned long DWORD;
typedef unsigned __int64 DWORD64;
typedef void *HANDLE;
typedef unsigned __int64 *PDWORD64;
typedef void *PVOID;
typedef unsigned long ULONG;
typedef unsigned __int64 ULONG64;
typedef const CHAR *PCSTR;
typedef CHAR *PSTR;

struct _SYMBOL_INFO {
        ULONG SizeOfStruct;
        ULONG TypeIndex;
        ULONG64 Reserved[2];
        ULONG info;
        ULONG Size;
        ULONG64 ModBase;
        ULONG Flags;
        ULONG64 Value;
        ULONG64 Address;
        ULONG Register;
        ULONG Scope;
        ULONG Tag;
        ULONG NameLen;
        ULONG MaxNameLen;
        CHAR Name[1];
};
typedef struct _SYMBOL_INFO *PSYMBOL_INFO;

typedef __stdcall BOOL (*PSYM_ENUMERATESYMBOLS_CALLBACK)(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext);
__stdcall DWORD SymGetOptions(void);
__stdcall DWORD SymSetOptions(DWORD SymOptions __attribute__((in)));
__stdcall BOOL SymInitialize(HANDLE hProcess __attribute__((in)), PSTR UserSearchPath __attribute__((in)), BOOL fInvadeProcess __attribute__((in)));
__stdcall DWORD64 SymLoadModule64(HANDLE hProcess __attribute__((in)), HANDLE hFile __attribute__((in)), PSTR ImageName __attribute__((in)), PSTR ModuleName __attribute__((in)), DWORD64 BaseOfDll __attribute__((in)), DWORD SizeOfDll __attribute__((in)));
__stdcall BOOL SymSetSearchPath(HANDLE hProcess __attribute__((in)), PSTR SearchPathA __attribute__((in)));
__stdcall BOOL SymFromAddr(HANDLE hProcess __attribute__((in)), DWORD64 Address __attribute__((in)), PDWORD64 Displacement __attribute__((out)), PSYMBOL_INFO Symbol __attribute__((in)) __attribute__((out)));
__stdcall BOOL SymEnumSymbols(HANDLE hProcess __attribute__((in)), ULONG64 BaseOfDll __attribute__((in)), PCSTR Mask __attribute__((in)), PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback __attribute__((in)), PVOID UserContext __attribute__((in)));
EOS


	puts 'run_init'
	l.run_init

	puts 'sym_init'
	dl.syminitialize(42, 0, 0)
	puts 'sym_setopt'
	dl.symsetoptions(dl.symgetoptions|dl::SYMOPT_DEFERRED_LOADS|dl::SYMOPT_NO_PROMPTS)
	puts 'sym_setsearch'
	sympath = ENV['_NT_SYMBOL_PATH'] || 'srv**/tmp/symbols*http://msdl.microsoft.com/download/symbols'
	dl.symsetsearchpath(42, sympath)

	puts 'sym_loadmod'
	tg = PeLdr.new('kernel32.dll')
	dl.symloadmodule64(42, 0, 0, 0, tg.load_address, 0)

	puts 'walk'
	symstruct = [0x58].pack('L') + 0.chr*4*19 + [512].pack('L')     # sizeofstruct, ..., nameszmax
	text = tg.pe.sections.find { |s| s.name == '.text' }
	# SymEnumSymbols
	text.rawsize.times { |o|
		sym = symstruct + 0.chr*512     # name concat'ed after the struct
		off = 0.chr*8
		if dl.symfromaddr(42, tg.load_address+text.virtaddr+o, off, sym) and off.unpack('L').first == 0
			symnamelen = sym[19*4, 4].unpack('L').first
			puts ' %x %s' % [text.virtaddr+o, sym[0x54, symnamelen].inspect]
		end
		puts '  %x/%x' % [o, text.rawsize] if $VERBOSE and o & 0xffff == 0
	}
	puts
end
