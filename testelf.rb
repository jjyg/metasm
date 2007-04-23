#!/usr/bin/env ruby

require 'metasm/ia32/parse'
require 'metasm/ia32/encode'
require 'metasm/exe_format/elf'

cpu = Metasm::Ia32.new
prog = Metasm::Program.new cpu

prog.parse DATA.read

prog.encode
pt_gnu_stack = { 'type' => 0x6474e551, 'flags' => %w[R W] }
data = Metasm::ELF.encode prog, 'unstripped' => true, 'elf_interp' => '/lib/ld-linux.so.2', 'additional_segments' => [pt_gnu_stack], 'init' => 'pre_start'

File.open('testelf', 'wb', 0755) { |fd| fd.write data }

__END__
sys_write equ 4
sys_exit  equ 1
stdout    equ 1

syscall macro nr
 mov eax, nr // the syscall number goes in eax
 int 80h
endm

write macro(string, stringlen)
 mov ebx, stdout
 mov ecx, string
 mov edx, stringlen
 syscall(sys_write)
endm

.text
.data
toto:
# if 0 + 1 > 0
 db "toto\n"
#elif defined(STR)
 db STR
#else
 db "lala\n"
#endif
toto_len equ $-toto

convtab db '0123456789ABCDEF'
outbuf	db '0x', 8 dup('0'), '\n'

.text
pre_start:
 write(toto, toto_len)
 ret

start:
.import 'libc.so.6' '_exit', pltexit
.import 'libc.so.6' 'printf', pltprintf

 push dword ptr [printf]
 call hexdump

 call pushstr
 db "kikoolol\n\0"
pushstr:
 push esp
 call pltprintf
 add esp, 8

 push dword ptr [printf]
 call hexdump

 push 0
 call pltexit

hexdump:
 mov ebx, convtab
 mov edx, [esp+4]
 mov ecx, 8
 mov ebp, outbuf+1
 std

charloop:
 mov eax, edx
 and eax, 0xf
 xlat
 mov [ebp+ecx], al
 shl edx, 4
 loop charloop

 cld
 write(outbuf, 11)

 ret 4
