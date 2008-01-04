#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# 
# this exemple illustrates the use of the cparser/preprocessor #factorize functionnality:
# it generates code that references to the functions imported by a windows executable, and
# factorizes the windows headers through them
# usage: factorize-imports.rb <exe> <path to visual studio installation> [<additional func names>...]
#

require 'metasm'
include Metasm


pe = PE.decode_file_header(ARGV.shift)
pe.decode_imports
funcnames = pe.imports.map { |id| id.imports.map { |i| i.name } }.flatten.compact.uniq.sort

visualstudiopath = ARGV.shift || '/home/jj/tmp'

funcnames |= ARGV

src = <<EOS
// add the path to the visual studio std headers
#ifdef __METASM__
 #pragma include_dir #{(visualstudiopath+'/VC/platformsdk/include').inspect}
 #pragma include_dir #{(visualstudiopath+'/VC/include').inspect}
 #pragma prepare_visualstudio
 #pragma no_warn_redefinition
 #define _WIN32_WINNT 0x0600	// vista
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

void *fnptr[] = { #{funcnames.join(', ')} };
EOS

puts src if $DEBUG
puts Ia32.new.new_cparser.factorize(src)
