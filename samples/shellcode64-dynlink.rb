#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#    Copyright (C) 2021 Karim Kanso
#
#    Licence is LGPL, see LICENCE in the top-level directory

# this script compiles a source file (asm or C) into a shellcode that will
# dynamically resolve the address of functions it uses
# windows only, supposes the shellcode is run in the address space of a process
# whose PEB allows to find all required libraries.

require 'metasm'

class Shellcode < Metasm::Shellcode
	def tune_cparser(cp)
		super(cp)
		cp.llp64 if @cpu.size == 64
	end
end

sc = Shellcode.new(Metasm::X86_64.new)

case ARGV[0]
when /\.c(pp)?$/i
	src_c = File.read(ARGV[0])
	sc.assemble 'jmp main'
	sc.compile_c <<EOS
#define __MS_X86_64_ABI__
#{src_c}
EOS
when /\.asm$/i
	src = File.read(ARGV[0])
	sc.assemble src
when nil; abort "need sourcefile"
else abort "unknown srcfile extension"
end

# find external symbols needed by the shellcode
ext_syms = sc.encoded.reloc_externals

# resolver code
sc.parse <<EOS
get_libbase:
	push rdi
	mov rax, gs:[0x60]	// peb
	mov rax, [rax+18h]	// peb_ldr
	add rax, 10h		// &inloadorder
libbase_loop:
	mov rax, [rax]		// next
	mov rdi, [rax+12*8]	// basename ptr
	xor edx, edx
	mov dl, [rdi+6]
	shl edx, 8
	mov dl, [rdi+4]
	shl edx, 8
	mov dl, [rdi+2]
	shl edx, 8
	mov dl, [rdi]
	or edx, 0x20202020	// downcase
	cmp edx, ecx
	jnz libbase_loop
	mov rax, [rax+6*8]	// baseaddr
	pop rdi
	ret

hash_name:
	xor eax, eax
	xor edx, edx
	dec rcx
hash_loop:
	ror eax, 0dh
	add eax, edx
	inc rcx
	mov dl, [rcx]
	test dl, dl
	jnz hash_loop
	ret

resolve_proc:
	push rdx
	push rdi
	push rsi
	push rbx
	call get_libbase
	mov rdi, rax		// imagebase
	mov eax, [rax+0x3c]	// coffhdr
	add rax, rdi
	mov esi, [rax+0x88]	// exportdirectory
	add rsi, rdi
	xor rbx, rbx
	dec rbx
resolve_loop:
	inc rbx
	mov ecx, [rsi+0x20]	// name pointer table
	add rcx, rdi
	mov ecx, [rcx+4*rbx]
	add rcx, rdi
	call hash_name
	cmp eax, [rsp+0x18]	// cmp hash(name[i]), arg_2
	jnz resolve_loop
	mov eax, [rsi+0x24]	// ord table
	add rax, rdi
	movzx ecx, word ptr [rax+2*rbx]
	mov eax, [rsi+0x1c]	// addr table
	add rax, rdi
	mov eax, [rax+4*rcx]	// addr[ord[i]]
	add rax, rdi
	pop rbx
	pop rsi
	pop rdi
	pop rdx
	ret
EOS

def hash_name(sym)
	hash = 0
	sym.each_byte { |char|
		hash = (((hash >> 0xd) | (hash << (32-0xd))) + char) & 0xffff_ffff
	}
	hash
end

def lib_name(sym)
	raise "unknown libname for #{sym}" if not lib = Metasm::WindowsExports::EXPORT[sym]
	n = lib.downcase[0, 4].unpack('C*')
	n[0] + (n[1] << 8) + (n[2] << 16) + (n[3] << 24)
end

# encode stub for each symbol
ext_syms.uniq.each { |sym|
	next if sym == 'next_payload'
	sc.parse <<EOS
#{sym}:
	push rcx
	push rdx
	mov ecx, #{lib_name(sym)}
	mov edx, #{hash_name(sym)}
	call resolve_proc
	pop rdx
	pop rcx
	jmp rax
EOS
}

# marker to the next payload if the payload is a stager
sc.assemble "next_payload:"

# output to a file
sc.encode_file 'shellcode-dynlink.raw'

__END__
// sample payload

extern __stdcall int MessageBoxA(int, char*, char*, int);
extern void next_payload(void);

int main(void)
{
	MessageBoxA(0, "Hello, world !", "Hi", 0);
	next_payload();
}
