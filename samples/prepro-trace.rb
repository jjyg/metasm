#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# 
# this exemple illustrates the use of the trace_macro functionnality:
# we write some code using macros defined in a header, and the trace_macro
# gives us back the macro definition that we use in our code, so that we can
# get rid of the header
# TODO same thing with C struct/prototypes
#

require 'metasm/preprocessor'
include Metasm
require 'pp'

visualstudiopath = ARGV.shift || '/mnt/wxp2/apps/VisualStudio8'
p = Preprocessor.new
p.include_search_path << "#{visualstudiopath}/VC/PlatformSDK/Include"
p.include_search_path << "#{visualstudiopath}/VC/include"
puts p.trace_macros(<<EOS)
#define _WIN32
#define _M_IX86
#include <windows.h>
PAGE_READONLY PAGE_READWRITE PAGE_EXECUTE PAGE_EXECUTE_READ PAGE_EXECUTE_READWRITE MEM_COMMIT MEM_RESERVE
EOS

