#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/arm64/opcodes'
require 'metasm/parse'

module Metasm
class ARM64
	def parse_arg_valid?(o, spec, arg)
		# Ripped from IA32, Don't think it's required?
		# if o.name == 'mov' or o.name == 'movz' or o.name == 'movk'
		# 	if not arg.kind_of?(Reg) # and not arg.kind_of?(ModRM)
		# 		return
		# 	elsif not arg.sz
		# 		puts "ambiguous arg size for indirection in #{o.name}" if $VERBOSE
		# 		return
		# 	elsif spec == :rt	|| spec == :rm # old comment: reg=dst, modrm=src (smaller)
		# 		return (arg.kind_of?(Reg) and arg.sz >= 32)
		# 	elsif o.props[:argsz]
		# 		return arg.sz == o.props[:argsz]
		# 	else
		# 		return arg.sz == 16
		# 	end
		# end
		# elsif o.name == 'crc32'
		# 	if not arg.kind_of?(Reg) and not arg.kind_of?(ModRM)
		# 		return
		# 	elsif not arg.sz
		# 		puts "ambiguous arg size for indirection in #{o.name}" if $VERBOSE
		# 		return
		# 	elsif spec == :reg
		# 		return (arg.kind_of?(Reg) and arg.sz >= 32)
		# 	elsif o.props[:argsz]
		# 		return arg.sz == o.props[:argsz]
		# 	else
		# 		return arg.sz >= 16
		# 	end
		# end

		# return false if arg.kind_of? ModRM and arg.adsz and o.props[:adsz] and arg.adsz != o.props[:adsz]

		cond = true
		if s = o.props[:argsz] and (arg.kind_of? Reg) # or arg.kind_of? ModRM)
			cond = (!arg.sz or arg.sz == s or spec == :reg_dx)
		end

		cond and
		case spec
		when :rd, :rs, :rn, :rm, :rt;
			(arg.kind_of? Reg and (arg.sz == 32 or arg.sz == 64 or o.props[:argsz])) or
				# TODO: Needs tightened up, can allow assigning to immediate values which is wrong - and the in_range? check is most likely wrong too
				(arg.kind_of?(Expression) && Expression.in_range?(arg, spec) != false)	# true or nil allowed
		# when :reg; arg.kind_of? Reg and (arg.sz >= 16 or o.props[:argsz])
		# when :modrm; (arg.kind_of? ModRM or arg.kind_of? Reg) and (!arg.sz or arg.sz >= 16 or o.props[:argsz]) and (!o.props[:modrmA] or arg.kind_of? ModRM) and (!o.props[:modrmR] or arg.kind_of? Reg)
		# when :i;        arg.kind_of? Expression
		# when :imm_val1; arg.kind_of? Expression and arg.reduce == 1
		# when :imm_val3; arg.kind_of? Expression and arg.reduce == 3
		# when :reg_eax;  arg.kind_of? Reg     and arg.val == 0 and (arg.sz >= 16 or o.props[:argsz])
		# when :reg_cl;   arg.kind_of? Reg     and arg.val == 1 and arg.sz == 8
		# when :reg_dx;   arg.kind_of? Reg     and arg.val == 2 and arg.sz == 16
		# when :seg3;     arg.kind_of? SegReg
		# when :seg3A;    arg.kind_of? SegReg  and arg.val > 3
		# when :seg2;     arg.kind_of? SegReg  and arg.val < 4
		# when :seg2A;    arg.kind_of? SegReg  and arg.val < 4 and arg.val != 1
		# when :eeec;     arg.kind_of? CtrlReg
		# when :eeed;     arg.kind_of? DbgReg
		# when :eeet;     arg.kind_of? TstReg
		# when :mrm_imm;  arg.kind_of? ModRM   and not arg.s and not arg.i and not arg.b
		# when :farptr;   arg.kind_of? Farptr
		# when :regfp;    arg.kind_of? FpReg
		# when :regfp0;   arg.kind_of? FpReg   and (arg.val == nil or arg.val == 0)
		# when :modrmmmx; arg.kind_of? ModRM   or (arg.kind_of? SimdReg and (arg.sz == 64 or (arg.sz == 128 and o.props[:xmmx]))) and (!o.props[:modrmA] or arg.kind_of? ModRM) and (!o.props[:modrmR] or arg.kind_of? SimdReg)
		# when :regmmx;   arg.kind_of? SimdReg and (arg.sz == 64 or (arg.sz == 128 and o.props[:xmmx]))
		# when :modrmxmm; arg.kind_of? ModRM   or (arg.kind_of? SimdReg and arg.sz == 128) and (!o.props[:modrmA] or arg.kind_of? ModRM) and (!o.props[:modrmR] or arg.kind_of? SimdReg)
		# when :regxmm;   arg.kind_of? SimdReg and arg.sz == 128
		# when :modrmymm; arg.kind_of? ModRM   or (arg.kind_of? SimdReg and arg.sz == 256) and (!o.props[:modrmA] or arg.kind_of? ModRM) and (!o.props[:modrmR] or arg.kind_of? SimdReg)
		# when :regymm;   arg.kind_of? SimdReg and arg.sz == 256

		# when :vexvreg;  arg.kind_of? Reg and arg.sz == @size
		# when :vexvxmm, :i4xmm;  arg.kind_of? SimdReg and arg.sz == 128
		# when :vexvymm, :i4ymm;  arg.kind_of? SimdReg and arg.sz == 256

		# when :i8, :u8, :u16,
		when :il18_5, :i16_5, :rm_lsl_i5, :rm_asr_i5, :rm_lsr_i5, :rm_lsl_i6, :rm_lsr_i6, :rm_asr_i6, :bitmask_imm
			arg.kind_of? Expression and
			(o.props[:setip] or Expression.in_range?(arg, spec) != false)	# true or nil allowed
		else
			raise EncodeError, "Internal error: unknown argument specification #{spec.inspect}"
		end
	end

	def parse_argregclasslist
		[Reg]
	end

	def parse_argument(lexer)
		lexer = AsmPreprocessor.new(lexer) if lexer.kind_of? String

		# reserved names (registers/segments etc)
		@args_token ||= parse_argregclasslist.map { |a| a.s_to_i.keys }.flatten.inject({}) { |h, e| h.update e => true }
		lexer.skip_space
		return if not tok = lexer.readtok

		# parse immediate values, i.e. 'mov x0, #255' or `mov x0, #0xFF`
		# if tok.type == :punct and tok.raw == '#'
		# 	lexer.skip_space
		# 	if not nntok = lexer.readtok or nntok.type != :string or nntok.raw !~ /^[0-9]$/
		# 		raise tok, 'invalid immediate value'
		# 	else
		# 		# tok.raw << nntok.raw
		# 		# require 'pry-byebug'; binding.pry
		# 		# puts 'aaa'
		# 	end
		# end

		# if tok.type == :string and tok.raw == 'ST'
		# 	lexer.skip_space
		# 	if ntok = lexer.readtok and ntok.type == :punct and ntok.raw == '('
		# 		lexer.skip_space
		# 		if not nntok = lexer.readtok or nntok.type != :string or nntok.raw !~ /^[0-9]$/ or
		# 				not ntok = (lexer.skip_space; lexer.readtok) or ntok.type != :punct or ntok.raw != ')'
		# 			raise tok, 'invalid FP register'
		# 		else
		# 			tok.raw << '(' << nntok.raw << ')'
		# 			fpr = parse_argregclasslist.last
		# 			if fpr.s_to_i.has_key? tok.raw
		# 				return fpr.new(fpr.s_to_i[tok.raw])
		# 			else
		# 				raise tok, 'invalid FP register'
		# 			end
		# 		end
		# 	else
		# 		lexer.unreadtok ntok
		# 	end
		# end

		# XXX: Not supported / might need to be renamed
		#if ret = parse_modrm(lexer, tok, self)
		#	ret
		#els
		if @args_token[tok.raw]
			parse_argregclasslist.each { |a|
				return a.from_str(tok.raw) if a.s_to_i.has_key? tok.raw
			}
			raise tok, 'internal error'
		else
			# parse immediate values, i.e. 'mov x0, #255' or `mov x0, #0xFF`
			unless tok.type == :punct and tok.raw == '#'
				lexer.unreadtok tok
			end
			lexer.skip_space
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
end
end
