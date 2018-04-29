#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/webasm/opcodes'
require 'metasm/parse'

module Metasm
class WebAsm
	def parse_argument(lexer)
		lexer = AsmPreprocessor.new(lexer) if lexer.kind_of? String
		lexer.skip_space
		return if not tok = lexer.readtok

		if tok.type == :punct and tok.raw == '['
			# Memref or BrTable
			ary = []
			loop do
				# XXX empty array for BrTable ?
				ary << parse_argument(lexer)
				raise tok, 'bad ptr' if not ary.last.kind_of?(Expression)
				lexer.skip_space
				tok2 = lexer.readtok
				if tok2 and tok2.type == :punct and tok2.raw == ']'
					break
				elsif not tok2 or tok2.type != :punct or tok2.raw != ','
					raise tok, "unexpected #{tok2 ? 'eof' : tok2.raw}"
				end
			end
			lexer.skip_space
			tok2 = lexer.readtok
			if tok2 and tok2.type == :string and tok2.raw == 'or'
				# BrTable
				df = parse_argument(lexer)
				BrTable.new(ary, df)
			else
				raise tok, 'bad Memref/BrTable' if ary.length != 1
				lexer.unreadtok(tok2) if tok2
				Memref.new(ary[0])
			end
		elsif WasmFile::TYPE.index(tok.raw)
			BlockSignature.new(WasmFile::TYPE.index(tok.raw))
		else
			lexer.unreadtok tok
			expr = Expression.parse(lexer)
			lexer.skip_space
			expr
		end
	end

	def parse_arg_valid?(o, spec, arg)
		spec and arg
	end

	def parse_instruction_mnemonic(lexer)
		return if not tok = lexer.readtok
		tok = tok.dup
		while ntok = lexer.nexttok and ntok.type == :punct and (ntok.raw == '.' or ntok.raw == '/')
			tok.raw << lexer.readtok.raw
			ntok = lexer.readtok
			raise tok, 'invalid opcode name' if not ntok or ntok.type != :string
			tok.raw << ntok.raw
		end

		raise tok, 'invalid opcode' if not opcode_list_byname[tok.raw]
		tok
	end

	def encode_uleb(val, signed=false)
		# TODO labels ?
		v = Expression[val].reduce
		raise "need numeric value for #{val}" if not v.kind_of?(::Integer)
		out = EncodedData.new
		while v > 0x7f or v < -0x40 or (signed and v > 0x3f)
			out << Expression[0x80 | (v&0x7f)].encode(:u8, @endianness)
			v >>= 7
		end
		out << Expression[v & 0x7f].encode(:u8, @endianness)
	end

	def encode_instr_op(program, i, op)
		ed = EncodedData.new([op.bin].pack('C*'))
		op.args.zip(i.args).each { |oa, ia|
			case oa
			when :f32; ed << ia.encode(:u32, @endianness)
			when :f64; ed << ia.encode(:u64, @endianness)
			when :memoff; ed << encode_uleb(ia.off)
			when :uleb; ed << encode_uleb(ia)
			when :sleb; ed << encode_uleb(ia, true)
			when :blocksig
				ia = ia.id if ia.kind_of?(BlockSignature)
				ed << encode_uleb(ia, true)
			when :br_table
				ed << encode_uleb(ia.ary.length)
				ia.ary.each { |a| ed << encode_uleb(a) }
				ed << encode_uleb(ia.default)
			end
		}
		ed
	end
end
end
