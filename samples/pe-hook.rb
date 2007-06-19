#!/usr/bin/env ruby

require 'metasm'
require 'metasm-shell'

# code to run on start
newcode = <<EOS.encode_edata
hook_entrypoint:
pushad
push hook_libname
call [LoadLibraryA]
push hook_funcname
push eax
call [GetProcAddress]

push 0
push hook_title
push hook_msg
push 0
call eax

popad
jmp entrypoint

.align 4
hook_msg db '(c) David Hasselhoff', 0
hook_title db 'Hooked on a feeling', 0
hook_libname db 'user32', 0
hook_funcname db 'MessageBoxA', 0
EOS

# read original file
target = ARGV.shift
pe = Metasm::PE.decode Metasm::VirtualFile.read(target)

# modify last section
s = pe.sections.last
s.encoded.data = s.encoded.data.to_str
s.encoded << newcode
s.virtaddr = s.virtsize = s.rawaddr = s.rawsize = nil

# patch entrypoint
pe.optheader.entrypoint = 'hook_entrypoint'

# reencode
oldhdr = pe.encoded[0, pe.sections.first.rawaddr]
pe.encoded = Metasm::EncodedData.new
pe.encode_header
# bad people store information in unmapped space here (eg import libnames)
pe.encoded << oldhdr[pe.encoded.virtsize..-1] if oldhdr.virtsize > pe.encoded.virtsize
pe.encode_sections_fixup

puts "Unresolved relocations: #{pe.encoded.reloc.inspect}" if not pe.encoded.reloc.empty?

# save to file
File.open(target.sub('.exe', '-patch.exe'), 'wb') { |fd| fd.write pe.encoded.data }
