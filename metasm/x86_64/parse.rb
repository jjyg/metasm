#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/x86_64/opcodes'
require 'metasm/x86_64/encode'
require 'metasm/parse'

module Metasm
class X86_64
	def parse_parser_instruction(lexer, instr)
		case instr.raw.downcase
		when '.mode', '.bits'
			if tok = lexer.readtok and tok.type == :string and tok.raw == '64'
				lexer.skip_space
				raise instr, 'syntax error' if ntok = lexer.nexttok and ntok.type != :eol
			else
				raise instr, 'invalid cpu mode, 64bit only'
			end
		else super(lexer, instr)
		end
	end

	def parse_prefix(i, pfx)
		super(i, pfx) or (i.prefix[:sz] = 64 if pfx == 'code64')
	end

	# parses an arbitrary x64 instruction argument
	def parse_argument(lexer)
		# reserved names (registers/segments etc)
		@args_token ||= [Reg, SimdReg, SegReg, DbgReg, CtrlReg].map { |a| a.s_to_i.keys }.flatten.inject({}) { |h, e| h.update e => true }

		lexer.skip_space
		return if not tok = lexer.readtok

		if ret = ModRM.parse(lexer, tok, self)
			ret
		elsif @args_token[tok.raw]
			[Reg, SimdReg, SegReg, DbgReg, CtrlReg].each { |a|
				return a.from_str(tok.raw) if a.s_to_i.has_key? tok.raw
			}
			raise tok, 'internal error'
		else
			lexer.unreadtok tok
			expr = Expression.parse(lexer)
			lexer.skip_space

			# may be a farptr
			if expr and ntok = lexer.readtok and ntok.type == :punct and ntok.raw == ':'
				raise tok, 'invalid farptr' if not addr = Expression.parse(lexer)
				Farptr.new expr, addr
			else
				lexer.unreadtok ntok
				Expression[expr.reduce] if expr
			end
		end
	end

	# check if the argument matches the opcode's argument spec
	# TODO check ah vs dil/r15 ; push32
	# XXX imm range?
	def parse_arg_valid?(o, spec, arg)
		super(o, spec, arg)
	end
end
end
