#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/python/main'

module Metasm
class Python
	def addop(name, bin, *args)
		o = Opcode.new(name)
		o.bin = bin

		if bin >= 90 and args.empty?	# HAVE_ARGUMENT
			o.args << :i16
		end

		o.args.concat(args & @valid_args)
		(args & @valid_props).each { |p| o.props[p] = true }
		@opcode_list << o
	end

	def init_opcode_list
		@opcode_list = []

		@valid_props = [:setip, :saveip, :stopexec]
		@valid_args = [:i16]

		addop 'STOP_CODE', 0, :stopexec
		addop 'POP_TOP', 1
		addop 'ROT_TWO', 2
		addop 'ROT_THREE', 3
		addop 'DUP_TOP', 4
		addop 'ROT_FOUR', 5
		addop 'NOP', 9

		addop 'UNARY_POSITIVE', 10
		addop 'UNARY_NEGATIVE', 11
		addop 'UNARY_NOT', 12
		addop 'UNARY_CONVERT', 13

		addop 'UNARY_INVERT', 15

		addop 'BINARY_POWER', 19

		addop 'BINARY_MULTIPLY', 20
		addop 'BINARY_DIVIDE', 21
		addop 'BINARY_MODULO', 22
		addop 'BINARY_ADD', 23
		addop 'BINARY_SUBTRACT', 24
		addop 'BINARY_SUBSCR', 25
		addop 'BINARY_FLOOR_DIVIDE', 26
		addop 'BINARY_TRUE_DIVIDE', 27
		addop 'INPLACE_FLOOR_DIVIDE', 28
		addop 'INPLACE_TRUE_DIVIDE', 29

		addop 'SLICE', 30
		#/* Also uses 31-33 */

		addop 'STORE_SLICE', 40
		#/* Also uses 41-43 */

		addop 'DELETE_SLICE', 50
		#/* Also uses 51-53 */

		addop 'STORE_MAP', 54
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

		addop 'PRINT_EXPR', 70
		addop 'PRINT_ITEM', 71
		addop 'PRINT_NEWLINE', 72
		addop 'PRINT_ITEM_TO', 73
		addop 'PRINT_NEWLINE_TO', 74
		addop 'INPLACE_LSHIFT', 75
		addop 'INPLACE_RSHIFT', 76
		addop 'INPLACE_AND', 77
		addop 'INPLACE_XOR', 78
		addop 'INPLACE_OR', 79
		addop 'BREAK_LOOP', 80
		addop 'WITH_CLEANUP', 81
		addop 'LOAD_LOCALS', 82
		addop 'RETURN_VALUE', 83
		addop 'IMPORT_STAR', 84
		addop 'EXEC_STMT', 85
		addop 'YIELD_VALUE', 86
		addop 'POP_BLOCK', 87
		addop 'END_FINALLY', 88
		addop 'BUILD_CLASS', 89

		#addop 'HAVE_ARGUMENT', 90      #/* Opcodes from here have an argument: */

		addop 'STORE_NAME', 90      #/* Index in name list */
		addop 'DELETE_NAME', 91      #/* "" */
		addop 'UNPACK_SEQUENCE', 92      #/* Number of sequence items */
		addop 'FOR_ITER', 93
		addop 'LIST_APPEND', 94

		addop 'STORE_ATTR', 95      #/* Index in name list */
		addop 'DELETE_ATTR', 96      #/* "" */
		addop 'STORE_GLOBAL', 97      #/* "" */
		addop 'DELETE_GLOBAL', 98      #/* "" */
		addop 'DUP_TOPX', 99      #/* number of items to duplicate */
		addop 'LOAD_CONST', 100     #/* Index in const list */
		addop 'LOAD_NAME', 101     #/* Index in name list */
		addop 'BUILD_TUPLE', 102     #/* Number of tuple items */
		addop 'BUILD_LIST', 103     #/* Number of list items */
		addop 'BUILD_SET', 104     #/* Number of set items */
		addop 'BUILD_MAP', 105     #/* Always zero for now */
		addop 'LOAD_ATTR', 106     #/* Index in name list */
		addop 'COMPARE_OP', 107     #/* Comparison operator */
		addop 'IMPORT_NAME', 108     #/* Index in name list */
		addop 'IMPORT_FROM', 109     #/* Index in name list */
		addop 'JUMP_FORWARD', 110     #/* Number of bytes to skip */

		addop 'JUMP_IF_FALSE_OR_POP', 111 #/* Target byte offset from beginning of code */
		addop 'JUMP_IF_TRUE_OR_POP', 112 #/* "" */
		addop 'JUMP_ABSOLUTE', 113     #/* "" */
		addop 'POP_JUMP_IF_FALSE', 114   #/* "" */
		addop 'POP_JUMP_IF_TRUE', 115    #/* "" */

		addop 'LOAD_GLOBAL', 116     #/* Index in name list */

		addop 'CONTINUE_LOOP', 119     #/* Start of loop (absolute) */
		addop 'SETUP_LOOP', 120     #/* Target address (relative) */
		addop 'SETUP_EXCEPT', 121     #/* "" */
		addop 'SETUP_FINALLY', 122     #/* "" */

		addop 'LOAD_FAST', 124     #/* Local variable number */
		addop 'STORE_FAST', 125     #/* Local variable number */
		addop 'DELETE_FAST', 126     #/* Local variable number */

		addop 'RAISE_VARARGS', 130     #/* Number of raise arguments (1, 2 or 3) */
		#/* CALL_FUNCTION_XXX opcodes defined below depend on this definition */
		addop 'CALL_FUNCTION', 131     #/* #args + (#kwargs<<8) */
		addop 'MAKE_FUNCTION', 132     #/* #defaults */
		addop 'BUILD_SLICE', 133     #/* Number of items */

		addop 'MAKE_CLOSURE', 134     #/* #free vars */
		addop 'LOAD_CLOSURE', 135     #/* Load free variable from closure */
		addop 'LOAD_DEREF', 136     #/* Load and dereference from closure cell */ 
		addop 'STORE_DEREF', 137     #/* Store into cell */ 

		#/* The next 3 opcodes must be contiguous and satisfy (CALL_FUNCTION_VAR - CALL_FUNCTION) & 3 == 1  */
		addop 'CALL_FUNCTION_VAR', 140  #/* #args + (#kwargs<<8) */
		addop 'CALL_FUNCTION_KW', 141  #/* #args + (#kwargs<<8) */
		addop 'CALL_FUNCTION_VAR_KW', 142  #/* #args + (#kwargs<<8) */

		addop 'SETUP_WITH', 143

		#/* Support for opargs more than 16 bits long */
		addop 'EXTENDED_ARG', 145

		addop 'SET_ADD', 146
		addop 'MAP_ADD', 147
	end
end
end
