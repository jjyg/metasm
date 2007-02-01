#!/usr/bin/ruby

require 'metasm/ia32/parse'
require 'metasm/ia32/encode'
require 'metasm/exe_format/pe'

cpu = Metasm::Ia32.new
prog = Metasm::Program.new cpu
prog.parse <<EOS
.text
start:
	xor eax, eax
	ret
EOS

prog.encode

rsrc = { 1 => { 1 => File.open('icon.ico', 'rb') { |fd| fd.read } } }

data = Metasm::PE.encode prog, 'resources' => rsrc

File.open('metasm-testrsrc.exe', 'wb') { |fd| fd.write data }
