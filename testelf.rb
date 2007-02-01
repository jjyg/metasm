
#!/usr/bin/env ruby

require 'metasm/ia32/parse'
require 'metasm/ia32/encode'
require 'metasm/exe_format/elf'

class Metasm::Instruction
        def inspect() "#<Instruction:%08x #{@opname.inspect} #{@args.inspect}>" % object_id end
        alias to_s inspect
end

cpu = Metasm::Ia32.new
prog = Metasm::Program.new cpu

prog.parse DATA.read

prog.encode
data = Metasm::ELF.encode prog

File.open('testelf', 'wb', 0755) { |fd| fd.write data }

__END__
sys_write equ 4
sys_exit  equ 1
stdout    equ 1

syscall macro nr
 mov eax, nr // the syscall number goes in eax
 int 80h
endm

.text
toto db "toto\n"
toto_len equ $-toto
start:
 call geteip
geteip:
 pop eax

addr macro label
 [eax + label - geteip]
endm

 mov ebx, stdout
 lea ecx, addr(toto)
 mov edx, toto_len
 syscall(sys_write)

 xor ebx, ebx
 syscall(sys_exit)

align 4096-1
db 'x'
