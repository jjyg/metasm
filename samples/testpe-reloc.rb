#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory



require 'metasm'

cpu = Metasm::Ia32.new

exe = Metasm::Program.new cpu
exe.parse <<EOS
.section '.text' r w x
entrypoint:
call [foobar]
xor eax, eax
ret
.import 'pe-foolib', 'foobar'
EOS
exe.encode
pe = Metasm::PE.from_program(exe)
pe.optheader.image_base = 0x50000
pe.optheader.entrypoint = 'entrypoint'
pe.encode_file('pe-testreloc.exe', 'exe')

dll = Metasm::Program.new cpu
dll.parse <<EOS
.section '.text' r w x
foobar:
push 0
push msg
push title
push 0
call [MessageBoxA]

xor eax, eax
ret

.align 4
msg db 'foo', 0
title db 'bar', 0

.import 'user32', 'MessageBoxA'
.export foobar, 'foobar'
EOS
dll.encode
pe = Metasm::PE.from_program(dll)
pe.optheader.image_base = 0x50000
pe.export.libname = 'pe-foolib'
pe.encode_file('pe-foolib.dll', 'dll')
