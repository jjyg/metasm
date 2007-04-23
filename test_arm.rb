#!/usr/bin/env ruby

require 'metasm/ia32/encode'
require 'metasm/ia32/parse'
require 'metasm/exe_format/elf'

cpu = Metasm::Ia32.new
prog = Metasm::Program.new cpu

prog.parse <<EOS
#include "/usr/include/asm/unistd.h"
entry:

mov eax, __NR_write
mov ebx, 1
mov ecx, string
mov edx, 6
int 80h

mov eax, __NR_exit
mov ebx, 0
int 80h
string db "toto\n\0"
EOS

prog.encode
p prog.sections.first.encoded
opts = { 'entrypoint' => 'entry' }
#opts['e_machine'] = 'ARM'
#opts['no_section_header'] = true
#opts['no_dynamic'] = true
data = Metasm::ELF.encode prog, opts

File.open('testelf', 'wb', 0755) { |fd| fd.write data }

