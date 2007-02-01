#!/usr/bin/env ruby

require 'metasm/ia32/parse'
require 'metasm/ia32/encode'
require 'metasm/exe_format/pe'

cpu = Metasm::Ia32.new

def template(name)
case name
when 'exe'
	spec = ".import 'testrelocdll', 'SomeRandomName'\ncall [SomeRandomName]"
when 'dll'
	spec = ".export start, 'SomeRandomName'"
end
<<EOS
.text
start:

push start
push format
push buffer
call wsprintf
add esp, 4*3

push 0
push title
push buffer
push 0
call messagebox

#{spec}

xor eax, eax
ret

.import 'user32' 'MessageBoxA', messagebox
.import 'user32' 'wsprintfA', wsprintf

.data
format  db '#{name} code address: %08x', 0
title   db '#{name} addr', 0

.bss
buffer  db 1025 dup(?)
EOS
end


# compile main exe
prog = Metasm::Program.new cpu
prog.parse template('exe')
prog.encode
data = Metasm::PE.encode prog, 'prefered_base_address' => 0x400000
File.open('testrelocexe.exe', 'wb') { |fd| fd.write data }


# compile dll
dll = Metasm::Program.new cpu
dll.parse template('dll')
dll.encode
data = Metasm::PE.encode dll, 'pe_target' => :dll, 'edata_dllname' => 'TESTRELOCDLL', 'prefered_base_address' => 0x400000, 'entrypoint' => 'foobar'
File.open('testrelocdll.dll', 'wb') { |fd| fd.write data }

if RUBY_PLATFORM =~ /mswin32/i
	puts "press enter"
	gets
end
