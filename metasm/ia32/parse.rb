require 'metasm/ia32/opcodes'
require 'metasm/ia32/encode'
require 'metasm/parse'

module Metasm
class Ia32
class ModRM
	# must be called after simple Reg/Seg parser
	# will raise if no modrm is found
	def self.parse(lexer)
		tok = lexer.readtok
		if tok =~ /^(?:byte|[dqo]?word|_(\d+)bits)$/
			ptsz = 
			if $1
				$1.to_i
			else
				case tok
				when  'byte':   8
				when  'word':  16
				when 'dword':  32
				when 'qword':  64
				when 'oword': 128
				else raise lexer, 'mrm: bad ptr size specifier'
				end
			end

			tok = lexer.readtok
			tok = lexer.readtok if tok == 'ptr'
		end
		if tok =~ /^[cdefgs]s$/
			raise lexer, 'bad modrm' if lexer.readtok != :':'
			seg = SegReg.new(SegReg.s_to_i[tok])
			tok = lexer.readtok
		end

		if tok != :'['
			raise lexer, 'not a modrm' if ptsz or seg
			lexer.unreadtok tok
			return
		end

		# support fasm syntax [fs:eax]
		if lexer.nexttok =~ /^[cdefgs]s$/
			tok = lexer.readtok
			raise lexer, 'bad modrm' if lexer.readtok != :':'
			seg = SegReg.new(SegReg.s_to_i[tok])
		end

		content = Expression.parse(lexer)
		raise(lexer, 'bad modrm') if not content or lexer.readtok != :']'

		regify = proc { |o|
			case o
			when Expression
				o.lexpr = regify[o.lexpr]
				o.rexpr = regify[o.rexpr]
				o
			when String
				if Reg.s_to_i.has_key? o
					Reg.new(*Reg.s_to_i[o])
				else o
				end
			else o
			end
		}

		s = i = b = imm = nil

		walker = proc { |o|
			case o
			when nil
			when Reg
				if b
					raise lexer, 'mrm: too many regs' if i
					i = o
					s = 1
				else
					b = o
				end
			when Expression
				if o.op == :* and (o.rexpr.kind_of? Reg or o.lexpr.kind_of? Reg)
					raise lexer, 'mrm: too many index' if i
					s = o.lexpr
					i = o.rexpr
					s, i = i, s if s.kind_of? Reg
					raise lexer, 'mrm: bad scale' unless s.kind_of? Integer
				elsif o.op == :+
					walker[o.lexpr]
					walker[o.rexpr]
				else
					imm = Expression[imm, :+, o]
				end
			else
				imm = Expression[imm, :+, o]
			end
		}

		walker[regify[content.reduce]]

		raise lexer, 'mrm: reg in imm' if imm.kind_of? Expression and not imm.externals.grep(Reg).empty?

		adsz = b ? b.sz : i ? i.sz : lexer.cpu.size
		new adsz, ptsz, s, i, b, imm, seg
	end
end


	def parse_parser_instruction(lexer, instr)
		case instr.downcase
		when '.mode', '.bits'
			case lexer.nexttok
			when 16, 32: @size = lexer.readtok
			else raise lexer, "Invalid IA32 .mode #{tok.inspect}"
			end
		else super
		end
	end

	def parse_prefix(i, pfx)
		# XXX check for redefinition
		case pfx
		when 'lock': i.prefix[:lock] = true
		when 'rep':            i.prefix[:rep] = 'rep'
		when 'repe', 'repz':   i.prefix[:rep] = 'repz'
		when 'repne', 'repnz': i.prefix[:rep] = 'repnz'
		end
	end

	def parse_argument(lexer)
		@args_token ||= (Argument.double_list + Argument.simple_list).map { |a| a.s_to_i.keys }.flatten.inject({}) { |h, e| h.update e => true }
		 
		tok = lexer.readtok

		# fp reg
		if tok == 'ST' and lexer.nexttok == :'('
			tok << lexer.readtok.to_s
			raise lexer, 'bad FP reg' if not lexer.nexttok.kind_of? Integer
			tok << lexer.readtok.to_s
			raise lexer, 'bad FP reg' if not lexer.nexttok == :')'
			tok << lexer.readtok.to_s
		end

		if @args_token[tok]
			Argument.double_list.each { |a|
				return a.new(*a.s_to_i[tok]) if a.s_to_i.has_key? tok
			}
			Argument.simple_list.each { |a|
				return a.new( a.s_to_i[tok]) if a.s_to_i.has_key? tok
			}
			raise lexer, "Internal ia32 argument parser error: bad args_token #{tok.inspect}"
		else
			lexer.unreadtok tok
			return tok if tok = ModRM.parse(lexer)

			tok = Expression.parse(lexer)

			if lexer.nexttok == :':' and (tt = tok.reduce).kind_of? Integer
				lexer.readtok
				tok = Expression.parse lexer
				Farptr.new tt, tok
			else
				tok
			end
		end
	end

	def parse_arg_valid?(o, spec, arg)
		case spec
		when :reg
			arg.class == Reg and
				if not o.fields[:w] or o.name == 'movsx' or o.name == 'movzx'
					arg.sz >= 16
				else true
				end
		when :modrm
			(arg.class == ModRM   or arg.class == Reg) and
				if not o.fields[:w]
					!arg.sz or arg.sz >= 16
				elsif o.name == 'movsx' or o.name == 'movzx'
					!arg.sz or arg.sz <= 16
				else true
				end
		when :i:        arg.kind_of? Expression
		when :imm_val1: arg.kind_of? Expression and arg.reduce == 1
		when :imm_val3: arg.kind_of? Expression and arg.reduce == 3
		when :reg_eax:  arg.class == Reg     and arg.val == 0
		when :reg_cl:   arg.class == Reg     and arg.val == 1 and arg.sz == 8
		when :reg_dx:   arg.class == Reg     and arg.val == 2 and arg.sz == 16
		when :seg3:     arg.class == SegReg
		when :seg2:     arg.class == SegReg  and arg.val < 4
		when :seg2A:    arg.class == SegReg  and arg.val < 4 and arg.val != 1
		when :eeec:     arg.class == CtrlReg
		when :eeed:     arg.class == DbgReg
		when :modrmA:   arg.class == ModRM
		when :mrm_imm:  arg.class == ModRM   and not arg.s and not arg.i and not arg.b
		when :farptr:   arg.class == Farptr
		when :regfp:    arg.class == FpReg
		when :regfp0:   arg.class == FpReg   and (arg.val == nil or arg.val == 0)	# XXX optionnal
		when :modrmmmx: arg.class == ModRM   or (arg.class == SimdReg and arg.sz == 64)
		when :regmmx:   arg.class == SimdReg and arg.sz == 64
		when :modrmxmm: arg.class == ModRM   or (arg.class == SimdReg and arg.sz == 128)
		when :regxmm:   arg.class == SimdReg and arg.sz == 128
		when :i8, :u8, :u16:
			arg.kind_of? Expression or Expression.in_range?(arg, spec)
		else raise EncodeException, "Internal error: unknown argument specification #{spec.inspect}"
		end
	end
end
end
