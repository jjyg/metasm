#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# This sample creates the dynldr.so ruby shared object that allows interaction with
# native libraries
# x86 only for now

require 'metasm'

module Metasm
module DynLdr
	# basic C defs for ruby internals - probably 1.8/x86 only
	RUBY_H = <<EOS
#line #{__LINE__}
typedef unsigned long VALUE;

struct rb_string_t {
	long flags;
	VALUE klass;
	long len;
	char *ptr;
	union {
		long capa;
		VALUE shared;
	} aux;
};
#define RString(x) ((struct rb_string_t *)(x))

struct rb_array_t {
	long flags;
	VALUE klass;
	long len;
	union {
		long capa;
		VALUE shared;
	} aux;
	VALUE *ptr;
};
#define RArray(x) ((struct rb_array_t *)(x))

#ifdef __PE__
// windows exports data by pointer
// TODO the compiler should handle these details alone
#define IMPMOD *
#else
#define IMPMOD
#endif

// TODO improve autoimport to handle data imports correctly
extern VALUE IMPMOD rb_cObject __attribute__((import));
extern VALUE IMPMOD rb_eRuntimeError __attribute__((import));
extern VALUE IMPMOD rb_eArgError __attribute__((import));

#define Qfalse ((VALUE)0)
#define Qtrue  ((VALUE)2)
#define Qnil   ((VALUE)4)

#define T_STRING 0x07
#define T_ARRAY  0x09
#define T_FIXNUM 0x0a
#define T_MASK   0x3f
#define TYPE(x) (((int)(x) & 1) ? T_FIXNUM : (((int)(x) & 3) || ((unsigned int)(x) < 7)) ? 0x40 : RString(x)->flags & T_MASK)

VALUE rb_uint2inum(unsigned long);
VALUE rb_ull2inum(unsigned long long);
unsigned long rb_num2ulong(VALUE);
VALUE rb_str_new(const char* ptr, long len);	// alloc + memcpy + 0term
VALUE rb_ary_new2(int len);
VALUE rb_float_new(double);

int rb_intern(char *);
VALUE rb_funcall(VALUE recv, int id, int nargs, ...);
VALUE rb_const_get(VALUE, int);
VALUE rb_raise(VALUE, char*);
void rb_define_method(VALUE, char *, VALUE (*)(), int);
void rb_define_const(VALUE, char *, VALUE);
void rb_define_singleton_method(VALUE, char *, VALUE (*)(), int);

EOS

	# generic C source for the native component, ruby glue
	DYNLDR_C = <<EOS
#{RUBY_H}
#line #{__LINE__}

#ifdef __PE__
 __stdcall int LoadLibraryA(char *);
 __stdcall int GetProcAddress(int, char *);

 #define os_load_lib(l) LoadLibraryA(l)
 #define os_load_sym(l, s) GetProcAddress(l, s)
 #define os_load_sym_ord(l, s) GetProcAddress(l, (char*)s)
#endif

#ifdef __ELF__
 #define RTLD_LAZY 1
 int dlopen(char*, int);
 int dlsym(int, char*);

 #define os_load_lib(l) dlopen(l, RTLD_LAZY)
 #define os_load_sym(l, s) dlsym(l, s)
 #define os_load_sym_ord(l, s) 0
#endif

// asm linkage
__int64 do_invoke(int, int, int*);
__int64 do_invoke_stdcall(int, int, int*);
__int64 do_invoke_fastcall(int, int, int*);
double fake_float(void);
extern int *cb_ret_table;
extern void *callback_handler;
extern void *callback_id_0;
extern void *callback_id_1;

static VALUE dynldr;


static VALUE memory_read(VALUE self, VALUE addr, VALUE len)
{
	return rb_str_new((char*)rb_num2ulong(addr), (int)rb_num2ulong(len));
}

static VALUE memory_write(VALUE self, VALUE addr, VALUE val)
{
	char *src = RString(val)->ptr;
	char *dst = (char*)rb_num2ulong(addr);
	int len = RString(val)->len;
	while (len--)
		*dst++ = *src++;
	return val;
}

static VALUE str_ptr(VALUE self, VALUE str)
{
	if (TYPE(str) != T_STRING)
		rb_raise(IMPMOD rb_eArgError, "Invalid ptr");
	return rb_uint2inum((unsigned int)RString(str)->ptr);
}

// load a symbol from a lib byname, byordinal if integral
static VALUE sym_addr(VALUE self, VALUE lib, VALUE func)
{
	int h, p;

	if (TYPE(lib) != T_STRING)
		rb_raise(IMPMOD rb_eArgError, "Invalid lib");
	if (TYPE(func) != T_STRING && TYPE(func) != T_FIXNUM)
		rb_raise(IMPMOD rb_eArgError, "Invalid func");
	
	h = os_load_lib(RString(lib)->ptr);

	if (TYPE(func) == T_FIXNUM)
		p = os_load_sym_ord(h, rb_num2ulong(func));
	else
		p = os_load_sym(h, RString(func)->ptr);

	return rb_uint2inum(p);
}

// invoke a symbol
// args is an array of Integers
// flags: 1 stdcall  2 fastcall  4 ret 64bits  8 ret float
// TODO float args
static VALUE invoke(VALUE self, VALUE ptr, VALUE args, VALUE flags)
{
	if (TYPE(args) != T_ARRAY || RArray(args)->len > 64)
		rb_raise(IMPMOD rb_eArgError, "bad args");
	
	int flags_v = rb_num2ulong(flags);
	int ptr_v = rb_num2ulong(ptr);
	int i, argsz;
	int args_c[64];
	__int64 ret;

	argsz = RArray(args)->len;
	for (i=0 ; i<argsz ; i++)
		args_c[i] = rb_num2ulong(RArray(args)->ptr[i]);

	if (flags_v & 2)
		ret = do_invoke_fastcall(ptr_v, argsz, args_c);	// supercedes stdcall
	else if (flags_v & 1)
		ret = do_invoke_stdcall(ptr_v, argsz, args_c);
	else
		ret = do_invoke(ptr_v, argsz, args_c);
	
	if (flags_v & 4)
		return rb_ull2inum(ret);
	else if (flags_v & 8)
		// fake_float does nothing, to allow the compiler to use ST(0)
		// which was in fact set by ptr_v()
		return rb_float_new(fake_float());
	else
		return rb_uint2inum(ret);
}

// this is the function that is called on behalf of all callbacks
// we're called through callback_handler (asm), itself called from the unique
// callback generated by callback_alloc
// heavy stack magick at work here !
// TODO float args / float retval / ret __int64
static int do_callback_handler(int ori_retaddr, int caller_id, int arg0)
{
	int *addr = &arg0;
	int i, ret;
	VALUE args = rb_ary_new2(8);

	// copy our args to a ruby-accessible buffer
	for (i=0 ; i<8 ; i++)
		RArray(args)->ptr[i] = rb_uint2inum(*addr++);
	RArray(args)->len = 8;

	ret = rb_funcall(dynldr, rb_intern("callback_run"), 2, rb_uint2inum(caller_id), args);

	// dynldr.callback will give us the arity (in bytes) of the callback in args[0]
	// we just put the stack lifting offset in caller_id for the asm stub to use
	caller_id = rb_num2ulong(RArray(args)->ptr[0]);
	
	return rb_num2ulong(ret);
}

int Init_dynldr(void) __attribute__((export_as(Init_<insertfilenamehere>)))	// to patch before parsing to match the .so name
{
	dynldr = rb_const_get(rb_const_get(IMPMOD rb_cObject, rb_intern("Metasm")), rb_intern("DynLdr"));
	rb_define_singleton_method(dynldr, "memory_read",  memory_read, 2);
	rb_define_singleton_method(dynldr, "memory_write", memory_write, 2);
	rb_define_singleton_method(dynldr, "str_ptr", str_ptr, 1);
	rb_define_singleton_method(dynldr, "sym_addr", sym_addr, 2);
	rb_define_singleton_method(dynldr, "raw_invoke", invoke, 3);
	rb_define_const(dynldr, "CALLBACK_TARGET", rb_uint2inum(&callback_handler));
	rb_define_const(dynldr, "CALLBACK_ID_0", rb_uint2inum(&callback_id_0));
	rb_define_const(dynldr, "CALLBACK_ID_1", rb_uint2inum(&callback_id_1));
	return 0;
}
EOS

	# ia32 asm source for the native component: handles ABI stuff
	DYNLDR_ASM_IA32 = <<EOS
.text
do_invoke_fastcall:
	push ebp
	mov ebp, esp
	
	// load ecx/edx, fix arg/argcount
	mov eax, [ebp+16]
	mov ecx, [eax]
	mov edx, [eax+4]
	add eax, 8
	mov [ebp+16], eax

	mov eax,[ebp+12]
	test eax, eax
	jz _do_invoke_call
	dec eax
	test eax, eax
	jz _do_invoke_call
	dec eax
	jmp _do_invoke_copy

do_invoke:
do_invoke_stdcall:
	push ebp
	mov ebp, esp
	mov eax, [ebp+12]
_do_invoke_copy:
	// make room for args
	shl eax, 2
	jz _do_invoke_call
	sub esp, eax
	// copy args
	push esi
	push edi
	push ecx
	mov ecx, [ebp+12]
	mov esi, [ebp+16]
	mov edi, esp
	add edi, 12
	rep movsd
	pop ecx
	pop edi
	pop esi
	// go
_do_invoke_call:
	call dword ptr [ebp+8]
	leave
fake_float:
	ret

// entrypoint for callbacks: to the native api, give the addr of some code
//  that will push a unique cb_identifier and jmp here
callback_handler:
	// stack here: cb_id_retaddr, cb_native_retaddr, cb_native_arg0, ...
	// swap caller retaddr & cb_identifier, fix cb_identifier from the stub
	pop eax		// stuff pushed by the stub
	sub eax, callback_id_1 - callback_id_0	// fixup cb_id_retaddr to get a cb id
	xchg eax, [esp]	// put on stack, retrieve original retaddr
	push eax	// push intended cb retaddr
	call do_callback_handler
	// do_cb_handler puts the nr of bytes we have to pop from the stack in its 1st arg (eg [esp+4] here)
	// stack here: cb_native_retaddr, ruby_popcount, cb_native_arg0, ...
	pop ecx		// get retaddr w/o interfering with retval (incl 64bits eax+edx)
	add esp, [esp]	// pop cb args if stdcall
	add esp, 4	// pop cb_id/popcount
	jmp ecx		// return

// those are valid callback id
// most of the time only 2 cb is used (source: meearse)
// so this prevents dynamic allocation of a whole page for the most common case
callback_id_0: call callback_handler
callback_id_1: call callback_handler
EOS

	# initialization
	# load (build if needed) the binary module
	def self.start
		@callback_addrs = []	# list of all allocated callback addrs (in use or not)
		@callback_table = {}	# addr -> cb structure (inuse only)

		binmodule = find_bin_path

		if not File.exists? binmodule or File.stat(binmodule).mtime < File.stat(__FILE__).mtime
			exe = host_exe.new(host_cpu)
			# compile the C code, but patch the Init export name, which must match the string used in 'require'
			exe.compile_c DYNLDR_C.gsub('<insertfilenamehere>', File.basename(binmodule, '.so'))
			exe.assemble  case exe.cpu
			              when Ia32; DYNLDR_ASM_IA32
				      end
			exe.encode_file(binmodule, :lib)
		end

		require binmodule

		@callback_addrs << CALLBACK_ID_0 << CALLBACK_ID_1
	end

	# find the path of the binary module
	# if none exists, create a path writeable by the current user
	def self.find_bin_path
		fname = ['dynldr', host_arch, host_cpu.shortname].join('-') + '.so'
		dir = File.dirname(__FILE__)
		binmodule = File.join(dir, fname)
		if not File.exists? binmodule or File.stat(binmodule).mtime < File.stat(__FILE__).mtime
			if not dir = find_write_dir
				raise LoadError, "no writeable dir to put the binary ruby module, try to run as root"
			end
			binmodule = File.join(dir, fname)
		end
		binmodule
	end

	# find a writeable directory
	# searches this script directory, $HOME / %APPDATA% / %USERPROFILE%, or $TMP
	def self.find_write_dir
		dir = File.dirname(__FILE__)
		return dir if File.writable? dir
		dir = ENV['HOME'] || ENV['APPDATA'] || ENV['USERPROFILE']
		if File.writable? dir
			dir = File.join(dir, '.metasm')
			Dir.mkdir dir if not File.directory? dir
			return dir
		end
		ENV['TMP'] || ENV['TEMP'] || '.'
	end

	# CPU suitable for compiling code for the current running host
	def self.host_cpu
		@cpu ||=
		case RUBY_PLATFORM
		when /i[3-6]86/; Ia32.new
		else raise LoadError, "Unsupported host platform #{RUBY_PLATFORM}"
		end
	end
	
	# returns whether we run on linux or windows
	def self.host_arch
		case RUBY_PLATFORM
		when /linux/; :linux
		when /mswin/; :windows
		else raise LoadError, "Unsupported host platform #{RUBY_PLATFORM}"
		end
	end

	# ExeFormat suitable as current running host native module
	def self.host_exe
		{ :linux => ELF, :windows => PE }[host_arch]
	end

	# retrieve the library where a symbol is to be found (uses AutoImport)
	def self.lib_from_sym(symname)
		case host_arch
		when :linux; GNUExports::EXPORT
		when :windows; WindowsExports::EXPORT
		end[symname]
	end

	# reads a bunch of C code, creates binding for those according to the prototypes
	# handles enum/defines to define constants
	# For each toplevel method prototype, it generates a ruby method in this module, the name is lowercased
	# For each numeric macro/enum, it also generates an uppercase named constant
	# When such a function is called with a lambda as argument, a callback is created for the duration of the call
	# and destroyed afterwards ; use callback_alloc to get a callback id with longer life span
	def self.new_api_c(proto, fromlib=nil)
		cp = host_cpu.new_cparser
		cp.parse(proto)
		sc = class << self ; self ; end

		cp.toplevel.symbol.each_value { |v|
			next if not v.kind_of? C::Variable	# enums
			lib = fromlib || lib_from_sym(v.name)
			addr = sym_addr(lib, v.name)
			next if addr == 0 or addr == 0xffff_ffff or addr == 0xffffffff_ffffffff

			if not v.type.kind_of? C::Function
				# not a function, simply return the symbol address
				# TODO struct/table access through hash/array ?
				sc.send(:define_method, v.name.downcase) { addr }
				next
			end
			next if v.initializer	# inline & stuff

			flags = 0
			flags |= 1 if v.has_attribute('stdcall')
			flags |= 2 if v.has_attribute('fastcall')
			flags |= 4 if v.type.type.integral? and cp.sizeof(nil, v.type.type) == 8
			flags |= 8 if v.type.type.float?
			puts "new_api_c: load method #{v.name.downcase} from #{lib}" if $DEBUG
			sc.send(:define_method, v.name.downcase) { |*a|
				raise ArgumentError, "bad arg count for #{v.name}: #{a.length} for #{v.type.args.length}" if a.length != v.type.args.length and not v.type.varargs
				auto_cb = []	# list of automatic C callbacks generated from lambdas
				a = a.zip(v.type.args).map { |ra, fa| convert_arg_rb2c(cp, fa, ra, auto_cb) }.flatten
				ret = raw_invoke(addr, a, flags)
				auto_cb.each { |cb| callback_free(cb) }
				ret
			}
		}

		# constant definition from macro/enum
		cp.numeric_constants.each { |k, v|
			n = k.upcase
			n = "C#{n}" if n !~ /^[A-Z]/
			const_set(n, v) if not const_defined?(n) and v.kind_of? Integer
		}
	end

	# ruby object -> integer suitable as arg for raw_invoke
	def self.convert_arg_rb2c(cp, formal, val, auto_cb_list=[])
		val = case val
		when String; str_ptr(val)
		when Proc; cb = callback_alloc_c(cp, formal, val) ; auto_cb_list << cb ; cb
		# TODO when Hash, Array; if formal.type.pointed.kind_of? C::Struct; yadda yadda ; end
		else val.to_i
		end

		if formal and formal.type.integral? and cp.sizeof(formal) == 8 and host_cpu.size == 32
			val = [val & 0xffff_ffff, (val >> 32) & 0xffff_ffff]
			val.reverse! if host_cpu.endianness != :little
		end

		val
	end

	# this method is called from the C part to run the ruby code corresponding to
	# a given C callback allocated by callback_alloc
	def self.callback_run(id, args)
		raise "invalid callback #{'%x' % id} not in #{@callback_table.keys.map { |c| c.to_s(16) }}" if not cb = @callback_table[id]

		rawargs = args.dup
		ra = cb[:proto] ? cb[:proto].args.map { |fa| convert_arg_c2rb(cb[:cparser], fa, rawargs) } : []

		# run it
		ret = cb[:proc].call(*ra)

		# the C code expects to find in args[0] the amount of stack fixing needed for __stdcall callbacks
		args[0] = cb[:abi_stackfix] || 0
		ret
	end

	# C raw cb arg -> ruby object
	def self.convert_arg_c2rb(cp, formal, rawargs)
		val = rawargs.shift
		if formal.type.integral? and cp.sizeof(formal) == 64 and host_cpu.size == 32
			if host.cpu.endianness == :little
				val |= rawargs.shift << 32
			else
				val = (val << 32) | rawargs.shift
			end
		end
		# TODO Expression.make_signed
		val = nil if formal.type.pointer? and val == 0

		val
	end

	# allocate a callback for a given C prototype (string)
	# accepts full C functions (with body)
	def self.callback_alloc(proto, &b)
		cp = host_cpu.new_cparser
		cp.parse(proto)
		v = cp.toplevel.symbol.values.find_all { |v_| v_.type.kind_of? C::Function }.first
		if v.initializer
			# TODO full C callback
			raise 'not implemented'
		else
			callback_alloc_c(cp, v, b)
		end
	end

	# allocates a callback for a given C prototype (C variable, pointer to func accepted)
	def self.callback_alloc_c(cp, proto, b)
		ori = proto
		proto = proto.type if proto and proto.kind_of? C::Variable
		proto = proto.pointed while proto and proto.pointer?
		id = callback_find_id
		cb = {}
		cb[:id] = id
		cb[:proc] = b
		cb[:proto] = proto
		cb[:cparser] = cp
		cb[:abi_stackfix] = proto.args.inject(0) { |s, a| s + [cp.sizeof(a), cp.typesize[:ptr]].max } if ori and ori.has_attribute('stdcall')
		cb[:abi_stackfix] = proto.args[2..-1].to_a.inject(0) { |s, a| s + [cp.sizeof(a), cp.typesize[:ptr]].max } if ori and ori.has_attribute('fastcall')	# supercedes stdcall
		@callback_table[id] = cb
		id
	end

	# releases a callback id, so that it may be reused by a later callback_alloc
	def self.callback_free(id)
		@callback_table.delete id
	end

	# finds a free callback id, allocates a new page if needed
	def self.callback_find_id
		if not id = @callback_addrs.find { |a| not @callback_table[a] }
			cb_page = memory_alloc(4096)
			sc = Shellcode.new(host_cpu, cb_page)
			case sc.cpu
			when Ia32
				addr = cb_page
				nrcb = 128	# TODO should be 4096/5, but the parser/compiler is really too slow
				nrcb.times {
					@callback_addrs << addr
					sc.parse "call #{CALLBACK_TARGET}"
					addr += 5
				}
			end
			sc.assemble
			memory_write cb_page, sc.encode_string
			memory_perm cb_page, 4096, 'rx'
			raise 'callback_alloc bouh' if not id = @callback_addrs.find { |a| not @callback_table[a] }
		end
		id
	end

	# automatically build/load the bin module
	start

	case host_arch
	when :windows

		new_api_c <<EOS
#define PAGE_NOACCESS          0x01     
#define PAGE_READONLY          0x02     
#define PAGE_READWRITE         0x04     
#define PAGE_WRITECOPY         0x08     
#define PAGE_EXECUTE           0x10     
#define PAGE_EXECUTE_READ      0x20     
#define PAGE_EXECUTE_READWRITE 0x40     
#define PAGE_EXECUTE_WRITECOPY 0x80     
#define PAGE_GUARD            0x100     
#define PAGE_NOCACHE          0x200     
#define PAGE_WRITECOMBINE     0x400     

#define MEM_COMMIT           0x1000     
#define MEM_RESERVE          0x2000     
#define MEM_DECOMMIT         0x4000     
#define MEM_RELEASE          0x8000     
#define MEM_FREE            0x10000     
#define MEM_PRIVATE         0x20000     
#define MEM_MAPPED          0x40000     
#define MEM_RESET           0x80000     
#define MEM_TOP_DOWN       0x100000     
#define MEM_WRITE_WATCH    0x200000     
#define MEM_PHYSICAL       0x400000     
#define MEM_LARGE_PAGES  0x20000000     
#define MEM_4MB_PAGES    0x80000000     

__stdcall int VirtualAlloc(int addr, int size, int type, int prot);
__stdcall int VirtualFree(int addr, int size, int freetype);
__stdcall int VirtualProtect(int addr, int size, int prot, int *oldprot);
EOS
		
		# allocate some memory suitable for code allocation (ie VirtualAlloc)
		def self.memory_alloc(sz)
			virtualalloc(nil, sz, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE)
		end
	
		# free memory allocated through memory_alloc
		def self.memory_free(addr)
			virtualfree(addr, 0, MEM_RELEASE)
		end
	
		# change memory permissions - perm in [r rw rx rwx]
		def self.memory_perm(addr, len, perm)
			perm = { 'r' => PAGE_READONLY, 'rw' => PAGE_READWRITE, 'rx' => PAGE_EXECUTE_READ,
				'rwx' => PAGE_EXECUTE_READWRITE }[perm.to_s.downcase]
			virtualprotect(addr, len, perm, str_ptr(0.chr*8))
		end
	
	when :linux
		
		new_api_c <<EOS
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

#define MAP_PRIVATE 0x2
#define MAP_ANONYMOUS 0x20

int mmap(int addr, int length, int prot, int flags, int fd, int offset);
int munmap(int addr, int length);
int mprotect(int addr, int len, int prot);
EOS
		
		# allocate some memory suitable for code allocation (ie mmap)
		def self.memory_alloc(sz)
			@mmaps ||= {}	# save size for mem_free
			a = mmap(nil, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
			@mmaps[a] = sz
			a
		end
	
		# free memory allocated through memory_alloc
		def self.memory_free(addr)
			munmap(addr, @mmaps[addr])
		end
	
		# change memory permissions - perm 'rwx'
		# on PaX-enabled systems, this may need a non-mprotect-restricted ruby interpreter
		def self.memory_perm(addr, len, perm)
			perm = perm.to_s.downcase
			p = 0
			p |= PROT_READ if perm.include? 'r'
			p |= PROT_WRITE if perm.include? 'w'
			p |= PROT_EXEC if perm.include? 'x'
			mprotect(addr, len, p)
		end
	
	end
end
end
