#!/usr/bin/env ruby

require 'metasm/ia32/parse'
require 'metasm/ia32/encode'
require 'metasm/exe_format/pe'

class Metasm::Instruction
        def inspect() "#<Instruction:%08x #{@opname.inspect} #{@args.inspect}>" % object_id end
        alias to_s inspect
end
class Metasm::CPU ; def inspect ; "#<cpu>" end end

cpu = Metasm::Ia32.new
prog = Metasm::Program.new cpu

prog.parse <<EOS, __FILE__, __LINE__
.text
// .section ".text" r x // base=0x401000
start:
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

pe = Metasm::PE.new
pe.coff = Metasm::COFF.from_program prog
data = pe.encode

File.open('testpe.exe', 'wb') { |fd| fd.write data }
