#!/usr/bin/env ruby

require 'metasm'

pe = Metasm::PE.assemble Metasm::Ia32.new, <<EOS
.text
.entrypoint
push 0
push title
push message
push 0
call messagebox

xor eax, eax
ret

.import 'user32' MessageBoxA MessageBoxA messagebox

.data
message db 'kikoo lol', 0
title   db 'blaaa', 0
EOS
File.unlink('testpe.exe') if File.exist? 'testpe.exe'
pe.encode_file 'testpe.exe'
require 'pp'
pp pe.encoded.export.sort_by { |k, v| v }
pp pe.encoded.reloc
