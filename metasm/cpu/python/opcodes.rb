#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/python/main'

module Metasm
class Python
	CMP_OP = %w[< <= == != > >= in not_in is is_not exch]

	def addop(name, bin, *args)
		bin = @op_last_bin + 1 if bin == :next
		@op_last_bin = bin

		o = Opcode.new(name)
		o.bin = bin

		args.each { |a|
			o.args << a if @valid_args[a]
			o.props[a] = true if @valid_props[a]
		}
		o.args << :i16 if o.bin >= 90	# HAVE_ARGUMENT

		@opcode_list << o
	end

	# python version: 3.8.0 => 0x03080000 (major, minor, subminor, bytecode iteration)
	# TODO follow python history (Lib/opcode.py)
	def init_opcode_list(py_ver=1)
		@opcode_list = []

		@valid_args[:u8] = true
		@valid_args[:i16] = true
		@valid_args[:cmp] = true

		addop 'STOP_CODE', 0, :stopexec
		addop 'POP_TOP', 1
		addop 'ROT_TWO', 2
		addop 'ROT_THREE', 3
		addop 'DUP_TOP', 4
		addop 'DUP_TOP_TWO', 5 if py_ver > 0
		addop 'ROT_FOUR', :next

		addop 'NOP', 9 if py_ver > 0

		addop 'UNARY_POSITIVE', 10
		addop 'UNARY_NEGATIVE', 11
		addop 'UNARY_NOT', 12
		addop 'UNARY_CONVERT', 13 if py_ver > 0

		addop 'UNARY_INVERT', 15

		addop 'BINARY_MATRIX_MULTIPLY', 16 if py_ver > 0
		addop 'INPLACE_MATRIX_MULTIPLY', 17 if py_ver > 0

		addop 'LIST_APPEND', 18 if py_ver > 0
		addop 'BINARY_POWER', 19

		addop 'BINARY_MULTIPLY', 20
		addop 'BINARY_DIVIDE', 21 if py_ver > 0
		addop 'BINARY_MODULO', 22
		addop 'BINARY_ADD', 23
		addop 'BINARY_SUBTRACT', 24
		addop 'BINARY_SUBSCR', 25
		addop 'BINARY_FLOOR_DIVIDE', 26
		addop 'BINARY_TRUE_DIVIDE', 27
		addop 'INPLACE_FLOOR_DIVIDE', 28
		addop 'INPLACE_TRUE_DIVIDE', 29

		if py_ver <= 0
		addop 'SLICE_0', 30
		addop 'SLICE_1', 31
		addop 'SLICE_2', 32
		addop 'SLICE_3', 33

		addop 'STORE_SLICE_0', 40
		addop 'STORE_SLICE_1', 41
		addop 'STORE_SLICE_2', 42
		addop 'STORE_SLICE_3', 43

		addop 'DELETE_SLICE_0', 50
		addop 'DELETE_SLICE_1', 51
		addop 'DELETE_SLICE_2', 52
		addop 'DELETE_SLICE_3', 53

		addop 'STORE_MAP', 54 if py_ver > 0
		else
		addop 'GET_AITER', 50
		addop 'GET_ANEXT', 51
		addop 'BEFORE_ASYNC_WITH', 52
		addop 'BEGIN_FINALLY', 53
		addop 'END_ASYNC_FOR', 54
		end

		addop 'INPLACE_ADD', 55
		addop 'INPLACE_SUBTRACT', 56
		addop 'INPLACE_MULTIPLY', 57
		addop 'INPLACE_DIVIDE', 58
		addop 'INPLACE_MODULO', 59

		addop 'STORE_SUBSCR', 60
		addop 'DELETE_SUBSCR', 61

		addop 'BINARY_LSHIFT', 62
		addop 'BINARY_RSHIFT', 63
		addop 'BINARY_AND', 64
		addop 'BINARY_XOR', 65
		addop 'BINARY_OR', 66
		addop 'INPLACE_POWER', 67
		addop 'GET_ITER', 68
		addop 'GET_YIELD_FROM_ITER', 69 if py_ver > 0
		addop 'PRINT_EXPR', 70
		if py_ver <= 0
		addop 'PRINT_ITEM', 71
		addop 'PRINT_NEWLINE', 72
		addop 'PRINT_ITEM_TO', 73
		addop 'PRINT_NEWLINE_TO', 74
		else
		addop 'LOAD_BUILD_CLASS', 71
		addop 'YIELD_FROM', 72
		addop 'GET_AWAITABLE', 73
		end
		addop 'INPLACE_LSHIFT', 75
		addop 'INPLACE_RSHIFT', 76
		addop 'INPLACE_AND', 77
		addop 'INPLACE_XOR', 78
		addop 'INPLACE_OR', 79
		if py_ver <= 0
		addop 'BREAK_LOOP', 80
		addop 'WITH_CLEANUP', 81
		addop 'LOAD_LOCALS', 82
		else
		addop 'WITH_CLEANUP_START', 81
		addop 'WITH_CLEANUP_FINISH', 82
		end
		addop 'RETURN_VALUE', 83, :stopexec
		addop 'IMPORT_STAR', 84
		if py_ver <= 0
		addop 'EXEC_STMT', 85
		else
		addop 'SETUP_ANNOTATIONS', 85
		end
		addop 'YIELD_VALUE', 86
		addop 'POP_BLOCK', 87
		addop 'END_FINALLY', 88
		if py_ver <= 0
		addop 'BUILD_CLASS', 89
		else
		addop 'POP_EXCEPT', 89
		end

		#addop 'HAVE_ARGUMENT', 90      #/* Opcodes from here have an argument: */

		addop 'STORE_NAME', 90      #/* Index in name list */
		addop 'DELETE_NAME', 91      #/* "" */
		addop 'UNPACK_SEQUENCE', 92      #/* Number of sequence items */
		addop 'FOR_ITER', 93, :setip
		if py_ver <= 0
		addop 'LIST_APPEND', 94
		else
		addop 'UNPACK_EX', 94
		end

		addop 'STORE_ATTR', 95      #/* Index in name list */
		addop 'DELETE_ATTR', 96      #/* "" */
		addop 'STORE_GLOBAL', 97      #/* "" */
		addop 'DELETE_GLOBAL', 98      #/* "" */
		addop 'DUP_TOPX', 99 if py_ver <= 0      #/* number of items to duplicate */
		addop 'LOAD_CONST', 100     #/* Index in const list */
		addop 'LOAD_NAME', 101     #/* Index in name list */
		addop 'BUILD_TUPLE', 102     #/* Number of tuple items */
		addop 'BUILD_LIST', 103     #/* Number of list items */
		addop 'BUILD_SET', :next if py_ver > 0    #/* Number of set items */
		addop 'BUILD_MAP', :next     #/* Always zero for now */
		addop 'LOAD_ATTR', :next     #/* Index in name list */
		addop 'COMPARE_OP', :next, :cmp     #/* Comparison operator */
		addop 'IMPORT_NAME', :next     #/* Index in name list */
		addop 'IMPORT_FROM', :next     #/* Index in name list */

		addop 'JUMP_FORWARD', 110, :setip, :stopexec     #/* Number of bytes to skip */

		addop 'JUMP_IF_FALSE_OR_POP', 111, :setip #/* Target byte offset from beginning of code */
		addop 'JUMP_IF_TRUE_OR_POP', 112, :setip #/* "" */
		addop 'JUMP_ABSOLUTE', 113, :setip, :stopexec     #/* "" */
		addop 'POP_JUMP_IF_FALSE', 114, :setip   #/* "" */
		addop 'POP_JUMP_IF_TRUE', 115, :setip    #/* "" */

		addop 'LOAD_GLOBAL', 116     #/* Index in name list */

		addop 'CONTINUE_LOOP', 119     #/* Start of loop (absolute) */
		addop 'SETUP_LOOP', 120     #/* Target address (relative) */
		addop 'SETUP_EXCEPT', 121     #/* "" */
		addop 'SETUP_FINALLY', 122, :setip     #/* "" */

		addop 'LOAD_FAST', 124     #/* Local variable number */
		addop 'STORE_FAST', 125     #/* Local variable number */
		addop 'DELETE_FAST', 126     #/* Local variable number */

		addop 'RAISE_VARARGS', 130     #/* Number of raise arguments (1, 2 or 3) */
		#/* CALL_FUNCTION_XXX opcodes defined below depend on this definition */
		addop 'CALL_FUNCTION', 131, :u8, :u8, :setip     #/* #args + (#kwargs<<8) */
		addop 'MAKE_FUNCTION', 132     #/* #defaults */
		addop 'BUILD_SLICE', 133     #/* Number of items */

		addop 'MAKE_CLOSURE', 134     #/* #free vars */
		addop 'LOAD_CLOSURE', 135     #/* Load free variable from closure */
		addop 'LOAD_DEREF', 136     #/* Load and dereference from closure cell */
		addop 'STORE_DEREF', 137     #/* Store into cell */
		addop 'DELETE_DEREF', 138

		addop 'CALL_FUNCTION_VAR', 140, :u8, :u8, :setip if py_ver > 0 #/* #args + (#kwargs<<8) */
		addop 'CALL_FUNCTION_KW', 141, :u8, :u8, :setip  #/* #args + (#kwargs<<8) */
		addop 'CALL_FUNCTION_VAR_KW', 142, :u8, :u8, :setip if py_ver <= 0  #/* #args + (#kwargs<<8) */
		addop 'CALL_FUNCTION_EX', 142, :setip if py_ver > 0  #/* #args + (#kwargs<<8) */

		addop 'SETUP_WITH', 143

		if py_ver > 0
		addop 'EXTENDED_ARG', 144	#/* Support for opargs more than 16 bits long */
		addop 'LIST_APPEND', 145

		addop 'SET_ADD', 146
		addop 'MAP_ADD', 147

		addop 'LOAD_CLASSDEREF', 148

		addop 'BUILD_LIST_UNPACK', 149
		addop 'BUILD_MAP_UNPACK', 150
		addop 'BUILD_MAP_UNPACK_WITH_CALL', 151
		addop 'BUILD_TUPLE_UNPACK', 152
		addop 'BUILD_SET_UNPACK', 153

		addop 'SETUP_ASYNC_WITH', 154

		addop 'FORMAT_VALUE', 155
		addop 'BUILD_CONST_KEY_MAP', 156
		addop 'BUILD_STRING', 157
		addop 'BUILD_TUPLE_UNPACK_WITH_CALL', 158

		addop 'LOAD_METHOD', 160
		addop 'CALL_METHOD', 161
		addop 'CALL_FINALLY', 162
		addop 'POP_FINALLY', 163
		end
	end
end
end
