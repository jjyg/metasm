#!/usr/bin/env ruby

require 'metasm'

cpu = Metasm::Ia32.new

exe = Metasm::Program.new cpu
exe.parse <<EOS
.text
call [foobar]
xor eax, eax
ret
.import 'pe-foolib', 'foobar'
EOS
exe.encode
pe = Metasm::PE.from_program(exe)
pe.optheader.image_base = 0x50000
pe.encode_file('pe-testreloc.exe', 'exe')

dll = Metasm::Program.new cpu
dll.parse <<EOS
.text
foobar:
push 0
push msg
push title
push 0
call [MessageBoxA]

xor eax, eax
ret

.import 'user32', 'MessageBoxA'
.export foobar, 'foobar'
EOS
dll.encode
pe = Metasm::PE.from_program(dll)
pe.optheader.image_base = 0x50000
pe.export.libname = 'pe-foolib'
pe.encode_file('pe-foolib.dll', 'dll')
