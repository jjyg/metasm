#!/usr/bin/env ruby

require 'metasm/exe_format/pe'
require 'metasm-shell'

cpu = Metasm::Ia32.new
prog = Metasm::Program.new cpu

prog.parse <<EOS, __FILE__, __LINE__
.text
// .section ".text" r x // base=0x401000
entrypoint:
push 0
push title
push message
push 0
call [MessageBoxA]

xor eax, eax
ret

.import 'user32' 'MessageBoxA'

.data
message db 'kikoo lol', 0
title   db 'blaaa', 0

.bss
db 1024 dup(?)

EOS

prog.encode

pe = Metasm::PE.from_program prog
data = pe.encode
p pe.encoded.reloc if not pe.encoded.reloc.empty?

File.open('testpe.exe', 'wb') { |fd| fd.write data }
