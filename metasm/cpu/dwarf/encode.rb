#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/dwarf/opcodes'
require 'metasm/parse'

module Metasm
class Dwarf
	def parse_argument(lexer)
		lexer = AsmPreprocessor.new(lexer) if lexer.kind_of? String
		lexer.skip_space
		return if not tok = lexer.readtok

		if tok.raw =~ /^r(\d+)/
			Reg.new($1.to_i)
		else
			lexer.unreadtok tok
			expr = Expression.parse(lexer)
			lexer.skip_space
			expr
		end
	end

	def parse_arg_valid?(o, spec, arg)
		# TODO check :reg and :imm spec, :uXX range
		spec and arg
	end


	def encode_instr_op(program, i, op)
		ed = EncodedData.new([op.bin].pack('C*'))
		op.args.zip(i.args).each { |oa, ia|
			case oa
			when :reg
			when :imm; raise "TODO encode imm"
			when :i8, :u8, :i16, :u16, :i32, :u32, :i64, :u64; ed << ia.encode(oa, @endianness)
			when :addr; ed << ia.encode("u#@size".to_sym, @endianness)
			when :uleb; ed << ia.encode_leb(false)
			when :sleb; ed << ia.encode_leb(true)
			else raise "TODO encode op #{oa} #{ia}"
			end
		}
		ed
	end
end
end
