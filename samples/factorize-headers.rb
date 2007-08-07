#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# 
# this exemple illustrates the use of the cparser/preprocessor #factorize functionnality:
# we write some code using standard headers, and the factorize call on CParser
# gives us back the macro/C definitions that we use in our code, so that we can
# get rid of the header
# Argument: path to visual studio installation
#

require 'metasm/preprocessor'
require 'metasm/parse_c'
include Metasm

visualstudiopath = ARGV.shift || '/mnt/wxp2/apps/VisualStudio8'

# to trace only pp macros (using eg an asm source), use Preprocessor#factorize instead

puts CParser.factorize(<<EOS)
// add the path to the visual studio std headers
#pragma include_dir #{(visualstudiopath+'/VC/platformsdk/include').inspect}
#pragma include_dir #{(visualstudiopath+'/VC/include').inspect}

// those are needed by the VS headers
#pragma no_warn_redefinition
#define _STDC 1
#define _WIN32
#define _M_IX86 500
#define _INTEGRAL_MAX_BITS 64
#define _MSC_VER 1001	// handle pragma_once
#define __int8 char
#define __int16 short
#define __int32 long
#define __int64 long long
#define __w64
// if you have time, you can try #include <windows.h> only :)
struct lconv;	// yay standard headers !
#include <windef.h>
#include <winbase.h>

// now write our code, using preprocessor macros and header-defined variables/types
void *fnptr[] = { &GetProcAddress, &LoadLibrary, &AdjustTokenPrivileges };
int constants[] = { PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
	PAGE_EXECUTE_READWRITE, MEM_COMMIT, MEM_RESERVE };
EXCEPTION_RECORD dummy;
EOS

