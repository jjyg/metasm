#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory



require 'metasm'

filename = ARGV.shift || 'testpe.exe'

# load and decode the file
pe = Metasm::PE.decode_file filename, Metasm::Ia32.new

# disassemble instructions
pe.desasm pe.optheader.entrypoint + pe.optheader.image_base

# dump
puts pe.blocks_to_src
