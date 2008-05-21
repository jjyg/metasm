#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# 
# this exemple illustrates the use of the cparser/preprocessor #factorize functionnality:
# we write some code using standard headers, and the factorize call on CParser
# gives us back the macro/C definitions that we use in our code, so that we can
# get rid of the header
# Argument: C file to factorize, [path to visual studio installation]
#

require 'metasm'
include Metasm

abort 'target needed' if not file = ARGV.shift
visualstudiopath = ARGV.shift || File.expand_path('~/tmp/VC')

# to trace only pp macros (using eg an asm source), use Preprocessor#factorize instead

puts Ia32.new.new_cparser.factorize(<<EOS + File.read(file))
// add the path to the visual studio std headers
#ifdef __METASM__
 #pragma include_dir #{(visualstudiopath+'/platformsdk/include').inspect}
 #pragma include_dir #{(visualstudiopath+'/include').inspect}
 #pragma prepare_visualstudio
 #pragma no_warn_redefinition
#endif

EOS

