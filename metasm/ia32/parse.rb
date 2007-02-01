require 'metasm/ia32/opcodes'
require 'metasm/ia32/encode'
require 'metasm/parse'

module Metasm
class Ia32
class ModRM
	# must be called after simple Reg/Seg parser
	# will raise if no modrm is found
	def self.parse(pgm)
		tok = pgm.readtok
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
				else raise pgm, 'mrm: bad ptr size specifier'
				end
			end

			tok = pgm.readtok
			tok = pgm.readtok if tok == 'ptr'
		end
		if tok =~ /^[cdefgs]s$/
			raise pgm, 'bad modrm' if pgm.readtok != :':'
			seg = SegReg.new(SegReg.s_to_i[tok])
			tok = pgm.readtok
		end

		if tok != :'['
			raise pgm, 'not a modrm' if ptsz or seg
			pgm.unreadtok tok
			return
		end

		# support fasm syntax [fs:eax]
		if pgm.nexttok =~ /^[cdefgs]s$/
			tok = pgm.readtok
			raise pgm, 'bad modrm' if pgm.readtok != :':'
			seg = SegReg.new(SegReg.s_to_i[tok])
		end

		content = Expression.parse(pgm)
		raise(pgm, 'bad modrm') if not content or pgm.readtok != :']'

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
					raise pgm, 'mrm: too many regs' if i
					i = o
					s = 1
				else
					b = o
				end
			when Expression
				if o.op == :* and (o.rexpr.kind_of? Reg or o.lexpr.kind_of? Reg)
					raise pgm, 'mrm: too many index' if i
					s = o.lexpr
					i = o.rexpr
					s, i = i, s if s.kind_of? Reg
					raise pgm, 'mrm: bad scale' unless s.kind_of? Integer
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

		raise pgm, 'mrm: reg in imm' if imm.kind_of? Expression and not imm.externals.grep(Reg).empty?

		adsz = b ? b.sz : i ? i.sz : pgm.cpu.size
		new adsz, ptsz, s, i, b, imm, seg
	end
end


	def parse_parser_instruction(pgm, instr)
		case instr.downcase
		when '.mode', '.bits'
			case pgm.nexttok
			when 16, 32: @size = pgm.readtok
			else raise pgm, "Invalid IA32 .mode #{tok.inspect}"
			end
		else super
		end
	end

	def parse_prefix(i, pfx)
		# XXX check for redefinition
		case pfx
		when 'lock': i.pfx[:lock] = true
		when 'rep':            i.pfx[:rep] = :rep
		when 'repe', 'repz':   i.pfx[:rep] = :repz
		when 'repne', 'repnz': i.pfx[:rep] = :repnz
		end
	end

	def parse_argument(pgm)
		@args_token ||= (Argument.double_list + Argument.simple_list).map { |a| a.s_to_i.keys }.flatten.inject({}) { |h, e| h.update e => true }
		 
		tok = pgm.readtok

		# fp reg
		if tok == 'ST' and pgm.nexttok == :'('
			tok << pgm.readtok.to_s
			raise pgm, 'bad FP reg' if not pgm.nexttok.kind_of? Integer
			tok << pgm.readtok.to_s
			raise pgm, 'bad FP reg' if not pgm.nexttok == :')'
			tok << pgm.readtok.to_s
		end

		if @args_token[tok]
			Argument.double_list.each { |a|
				return a.new(*a.s_to_i[tok]) if a.s_to_i.has_key? tok
			}
			Argument.simple_list.each { |a|
				return a.new( a.s_to_i[tok]) if a.s_to_i.has_key? tok
			}
			raise pgm, "Internal ia32 argument parser error: bad args_token #{tok.inspect}"
		else
			pgm.unreadtok tok
			return tok if tok = ModRM.parse(pgm)

			tok = Expression.parse(pgm)

			if pgm.nexttok == :':' and (tt = tok.reduce).kind_of? Integer
				pgm.readtok
				tok = Expression.parse pgm
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

	def parse_instruction_fixup(pgm, i)
		# convert label name for jmp/call/loop to relative offset
		if @opcode_list_byname[i.opname].first.props[:setip] and i.args.first.kind_of? Expression and not i.args.first.reduce.kind_of? Integer	# XXX jmp 0x43040211 ?
			postlabel = pgm.new_unique_label
			i.args[0] = Expression[i.args.first, :-, postlabel]
			pgm.unreadtok postlabel, :':'
		end
	end


	def parse_jmp_import_label(pgm, ifunc)	# XXX sucks hard
		pgm.unreadtok 'jmp', :'[', ifunc, :']', :eol
		parse_instruction(pgm)
	end
end
end
