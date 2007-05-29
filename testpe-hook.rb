#!/usr/bin/env ruby

require 'metasm'
require 'metasm-shell'

# code to run on start
newcode = <<EOS.encode_edata
hooked_entrypoint:
push 0
push title
push msg
push 0
call [MessageBoxA]
jmp entrypoint

.align 4
msg db '(c) David Hasselhoff', 0
title db 'Hooked on a feeling', 0
EOS

# read original file
target = ARGV.shift
pe = Metasm::PE.decode Metasm::VirtualFile.read(target)

# add new section
pe.sections << Metasm::PE::Section.new
pe.sections.last.name = '.hook'
pe.sections.last.characteristics = ['MEM_READ', 'MEM_EXECUTE']
pe.sections.last.encoded = newcode

# patch entrypoint
pe.optheader.entrypoint = 'hooked_entrypoint'

# reencode
pe.encoded = Metasm::EncodedData.new
pe.encode_header
pe.encode_sections_fixup

# save to file
File.open(target.sub('.exe', '-patch.exe'), 'wb') { |fd| fd.write pe.encoded.data }
