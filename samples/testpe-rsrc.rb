#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory



require 'metasm'

cpu = Metasm::Ia32.new
prog = Metasm::Program.new cpu
prog.parse <<EOS
.text
start:
	xor eax, eax
	ret
EOS

prog.encode

rsrc = { 1 => { 1 => { 2 => 'xxx' }, 'toto' => { 12 => 'tata' } } }
pe = Metasm::PE.from_program prog
pe.resource = Metasm::COFF::ResourceDirectory.from_hash rsrc
pe.optheader.entrypoint = 'start'

pe.encode_file('pe-testrsrc.exe')
