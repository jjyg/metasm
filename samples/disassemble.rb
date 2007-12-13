#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# 
# this script disassembles an executable (elf/pe) and dumps the output
# ruby [-v|-d] disassemble.rb [options] <exe file> [<c header file>]
# options:
#   --no-data		does not display data sections
#   --no-trace-data	does not trace data access (r/w xrefs)
#

require 'metasm'
include Metasm

# parse arguments
no_data = ARGV.delete('--no-data')
no_data_trace = ARGV.delete('--no-trace-data')
exename = ARGV.shift
cheader = ARGV.shift

# load the file
exe = AutoExe.decode_file exename
# set options
d = exe.init_disassembler
d.parse_c_file cheader if cheader
d.trace_data_xref = false if no_data_trace
# do the work
exe.disassemble
# output
d.dump(!no_data)
