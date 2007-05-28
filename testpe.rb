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




require 'metasm/os/main'

pe = Metasm::PE.decode Metasm::VirtualFile.read('testpe.exe')
pe.sections << Metasm::PE::Section.new
pe.sections.last.name = '.hook'
pe.sections.last.characteristics = ['MEM_READ', 'MEM_EXECUTE']
pe.sections.last.encoded = <<EOS.encode_edata
hooked_entrypoint:
push 0
push msg
push msg
push 0
call [MessageBoxA]
jmp entrypoint

.align 4
msg db 'hooked on a feeling', 0
EOS
pe.optheader.entrypoint = 'hooked_entrypoint'
pe.encoded = Metasm::EncodedData.new
pe.encode_header
pe.encode_sections_fixup

p pe.encoded.reloc if not pe.encoded.reloc.empty?

data = pe.encoded.data

File.open('testpe-patch.exe', 'wb') { |fd| fd.write data }
