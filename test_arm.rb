#!/usr/bin/env ruby

require 'metasm/ia32/encode'
require 'metasm/ia32/parse'
require 'metasm/exe_format/elf'

cpu = Metasm::Ia32.new
prog = Metasm::Program.new cpu

prog.parse <<EOS
ADD equ 0xA
// add dest, pc + (imm8 ror 2*rorc)
load_reg macro regnum, target
// condition code 4, basic op 2, has imm 1, op 4, setflags 1, dest 4, source1 4, rorc 4, imm 8
dd 0b1110_001 << 25 + (ADD << 21) + 0 << 20 + regnum << 16 + 15 << 12 + 0 << 8 + (target - postlabel - 4)
postlabel:
endm

entry:
; xor_reg(0, 0)
; dd 0xef90_0017	; syscall setuid

load_reg(0, str_bb)
load_reg(1, argv)
load_reg(2, envp)
dd 0xef90_000b		; syscall execve

argv dd str_su, str_t, str_w
envp dd 0
str_bb db '/bin/busybox', 0
str_su db 'su', 0
str_t  db '-', 0
str_w  db 'w', 0
EOS

prog.encode
data = Metasm::ELF.encode prog, 'e_machine' => 'ARM', 'entrypoint' => 'entry', 'no_section_header' => true, 'no_dynamic' => true

File.open('testelf', 'wb', 0755) { |fd| fd.write data }

