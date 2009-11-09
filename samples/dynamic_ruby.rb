#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# This sample hacks in the ruby interpreter to allow dynamic loading of shellcodes as object methods
# elf/linux/x86 only

require 'metasm'


module Metasm
module RubyHack
	# basic C defs for ruby internals - 1.8 only !
	RUBY_H = <<EOS
typedef unsigned long VALUE;

struct st_table;

struct klass {
	long flags;
	VALUE klass;
	struct st_table *iv_tbl;
	struct st_table *m_tbl;
	VALUE super;
};
#define RClass(x) ((struct klass *)(x))
#define RModule RClass

struct string {
	long flags;
	VALUE klass;
	long len;
	char *ptr;
	union {
		long capa;
		VALUE shared;
	} aux;
};
#define RString(x) ((struct string *)(x))

extern VALUE rb_cObject;
extern VALUE rb_eRuntimeError;
#define Qfalse ((VALUE)0)
#define Qtrue  ((VALUE)2)
#define Qnil   ((VALUE)4)
#define FIX2LONG(x) (((long)x) >> 1)

VALUE rb_uint2inum(unsigned long);
unsigned long rb_num2ulong(VALUE);

VALUE rb_str_new(const char* ptr, long len);	// alloc + memcpy + 0term

int rb_intern(char *);
VALUE rb_const_get(VALUE, int);
VALUE rb_raise(VALUE, char*);
void rb_define_method(VALUE, char *, VALUE (*)(), int);
void rb_define_singleton_method(VALUE, char *, VALUE (*)(), int);


// TODO setup those vars auto or define a standard .import/.export (elf/pe/macho)
#ifdef METASM_TARGET_ELF
asm .global "rb_cObject" undef type=NOTYPE;		// TODO fix elf encoder to not need this
asm .global "rb_eRuntimeError" undef type=NOTYPE;
#endif
EOS

	# create and load a ruby module that allows
	# to use a ruby string as the binary code implementing a ruby method
	# enable the use of .load_binary_method(class, methodname, string)
	def self.load_bootstrap
		c_source = <<EOS
#define METASM_TARGET_ELF

#{RUBY_H}

void mprotect(int, int, int);
asm .global mprotect undef;

static VALUE set_class_method_raw(VALUE self, VALUE klass, VALUE methname, VALUE rawcode, VALUE nparams)
{
	if (RString(methname)->ptr[RString(methname)->len] != 0)
		rb_raise(rb_eRuntimeError, "method name not 0termined");

	char *raw = RString(rawcode)->ptr;
	mprotect(raw & 0xfffff000, ((raw+RString(rawcode)->len+0xfff) & 0xfffff000) - (raw&0xfffff000), 7);	// RWX
	rb_define_method(klass, RString(methname)->ptr, RString(rawcode)->ptr, FIX2LONG(nparams));
	return Qtrue;
}

static VALUE memory_read(VALUE self, VALUE addr, VALUE len)
{
	return rb_str_new((char*)rb_num2ulong(addr), rb_num2ulong(len));
}

static VALUE memory_write(VALUE self, VALUE addr, VALUE val)
{
	char *src = RString(val)->ptr;
	char *dst = (char*)rb_num2ulong(addr);
	unsigned long len = RString(val)->len;
	while (len--)
		*dst++ = *src++;
	return val;
}

static VALUE memory_read_int(VALUE self, VALUE addr)
{
	return rb_uint2inum(*(unsigned long*)rb_num2ulong(addr));
}

static VALUE memory_write_int(VALUE self, VALUE addr, VALUE val)
{
	*(unsigned long*)rb_num2ulong(addr) = rb_num2ulong(val);
	return val;
}

extern void *dlsym(void *handle, char *symname);
#define RTLD_DEFAULT 0
asm .global dlsym undef;

static VALUE dl_dlsym(VALUE self, VALUE symname)
{
	return rb_uint2inum(dlsym(RTLD_DEFAULT, RString(symname)->ptr));
}

int Init_metasm_binload(void)
{
	VALUE metasm = rb_const_get(rb_cObject, rb_intern("Metasm"));
	VALUE rubyhack = rb_const_get(metasm, rb_intern("RubyHack"));
	rb_define_singleton_method(rubyhack, "set_class_method_raw", set_class_method_raw, 4);
	rb_define_singleton_method(rubyhack, "memory_read", memory_read, 2);
	rb_define_singleton_method(rubyhack, "memory_write", memory_write, 2);
	rb_define_singleton_method(rubyhack, "memory_read_int", memory_read_int, 1);
	rb_define_singleton_method(rubyhack, "memory_write_int", memory_write_int, 2);
	rb_define_singleton_method(rubyhack, "dlsym", dl_dlsym, 1);
	return 0;
}
asm .global Init_metasm_binload;

asm .soname "metasm_binload";
asm .nointerp;
asm .pt_gnu_stack rw;
EOS
		
		ELF.compile_c(Ia32.new, c_source).encode_file('metasm_binload.so')
		require 'metasm_binload'
		File.unlink('metasm_binload.so') if not $DEBUG
		# TODO Windows support
		# TODO PaX support (write + mmap, in user-configurable dir?)
	end
	load_bootstrap

	# sets up rawopcodes as the method implementation for class klass
	# rawopcodes must implement the expected ABI or things will break horribly
	# this method is VERY UNSAFE, and breaks everything put in place by the ruby interpreter
	# use with EXTREME CAUTION
	# nargs  arglist
	# -2     self, arg_ary
	# -1     argc, VALUE*argv, self
	# >=0    self, arg0, arg1..
	def self.set_method_binary(klass, methodname, rawopcodes, nargs=-2)
		(@@prevent_gc ||= {})[[klass, methodname]] = rawopcodes
		set_class_method_raw(klass, methodname, rawopcodes, nargs)

		# TODO rawopcodes = EncodedData, put a dlsym hook in the setup_module & resolve extern calls (rb_* ...)
	end

	# same as load_binary_method but with an object and not a class
	def self.set_object_method_binary(obj, *a)
		set_method_binary((class << obj ; self ; end), *a)
	end

	def self.object_pointer(obj)
		(obj.object_id << 1) & 0xffffffff
	end

	def self.[](a, l=nil)
		if a.kind_of? Range
			memory_read(a.begin, a.end-a.begin+(a.exclude_end? ? 0 : 1))
		elsif l
			memory_read(a, l)
		else
			memory_read_int(a)
		end
	end

	def self.[]=(a, l, v=nil)
		l, v = v, l if not v
		if a.kind_of? Range
			memory_write(a.begin, v)
		elsif l
			memory_write(a, v)
		else
			memory_write_int(a, v)
		end
	end
end
end




if __FILE__ == $0

# cnt.times { sys_write str }
src_asm = <<EOS
mov ecx, [ebp+8]
again:
push ecx
mov eax, 4
mov ebx, 1
mov ecx, [ebp+12]
mov edx, [ebp+16]
int 80h
pop ecx
loop again
EOS

src = <<EOS

#{Metasm::RubyHack::RUBY_H}

void doit(int, char*, int);
VALUE foo(VALUE self, VALUE count, VALUE str) {
	doit(FIX2LONG(count), RString(str)->ptr, RString(str)->len);
	return count;
}

void doit(int count, char *str, int strlen) {
	asm(#{src_asm.inspect});
}
EOS

m = Metasm::Shellcode.compile_c(Metasm::Ia32.new, src).encode_string

o = Object.new
Metasm::RubyHack.set_object_method_binary(o, 'bar', m, 2)

puts "test1"
o.bar(4, "blabla\n")
puts "test2"
o.bar(2, "foo\n")

end
