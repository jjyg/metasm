#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ia32/parse'
require 'metasm/compile_c'

module Metasm
class Ia32
	class CState
		# the automatic variable offsets
		attr_accessor :offset
		# the current function
		attr_accessor :func
		# the current register values (reg => CExpression)
		attr_accessor :regs
		# the registers used
		attr_accessor :dirty
		# the register currently in use by our caller
		attr_accessor :used
		# the uncommited variable assignment (reg => Variable)
		attr_accessor :pending

		attr_accessor :no_saved_ebp

		def initialize(offset, func)
			@offset, @func = offset, func
			@regs, @dirty, @used, @pending = {}, [], [], {}
		end
	end

	# returns a new State
	def compile_c_pre_prolog(exe, cp, src, func, offset)
		CState.new(offset, func)
	end

	# returns a new register, put it in state.used
	def compile_c_findreg(cp, src, state)
		reg = [:eax, :ebx, :ecx, :edx, :edi, :esi].find { |r| not state.used.include? r and not state.pending.include? r }
		if not reg
			if not reg = state.pending.keys.first
				raise 'need more register (or a better compiler?)'
			end
			var = state.pending.delete(reg)
			src << "push #{reg}"
			e = compile_c_findvaraddr(cp, src, state, var, reg)
			src << "pop #{cp.sizeof(var) == 1 ? 'byte' : 'dword'} ptr [#{e}]"
		end

		state.used << reg
		state.dirty |= [reg] if not [:eax].include? reg
		reg
	end

	def compile_c_flushregs(cp, src, state)
		state.pending.keys.each { |reg|
			var = state.pending.delete(reg)
			src << "push #{reg}"
			e = compile_c_findvaraddr(cp, src, state, var, reg)
			src << "pop #{cp.sizeof(var) == 1 ? 'byte' : 'dword'} ptr [#{e}]"
		}
	end
		
	def compile_c_findvaraddr(cp, src, state, expr, reg)
		case e = state.offset[expr]
		when CParser::CExpression
			# automatic, dynamic address
			src << "; find dynamic addr of #{expr.name} in #{reg}"
			e = "ebp-#{reg}"
		when ::Integer
			# automatic
			e = "ebp-#{e}"
		when nil
			# static
			# XXX choice for position-independant code
			if false
			src << 'push eax' if reg != :eax and state.used.include? :eax
			src << "call metasm_intern_geteip"
			src << "mov #{reg}, eax" if reg != :eax
			src << 'pop eax' if reg != 'eax' and state.used.include? :eax
			src << "add #{reg}, #{expr.name} - metasm_intern_geteip"
			e = reg
			else
			e = expr.name
			end
		end
		e
	end

	# compiles a c expression, updates state
	# returns the register containing the value
	# TODO XXX floating point (or anything other than int)
	def compile_c_cexpr_inner(cp, src, state, expr)
		case expr
		when CParser::Variable
			if not reg = state.pending.keys.find { |r| state.pending[r] == expr }
				reg = compile_c_findreg(cp, src, state)
				e = compile_c_findvaraddr(cp, src, state, expr, reg)
				if expr.type.kind_of? CParser::Array
					src << (state.offset[expr] ? "lea #{reg}, [#{e}]" : "mov #{reg}, #{e}") if e != reg
				else
					src << "mov #{reg}, [#{e}]"
				end
			end
			return reg
		when ::Integer
			return expr
		end
		if not expr.lexpr
			case expr.op
			when nil
				# TODO movzx etc
				reg = compile_c_cexpr_inner(cp, src, state, expr.rexpr)
			when :+
				reg = compile_c_cexpr_inner(cp, src, state, expr.rexpr)
			when :-
				reg = compile_c_cexpr_inner(cp, src, state, expr.rexpr)
				src << "neg #{reg}"
			when :*
				case expr.rexpr
				when CParser::CExpression
					case expr.op
					when :'+', :'*'
						src << '; TODO optimize dereference'
					end
				end
				reg = compile_c_cexpr_inner(cp, src, state, expr.rexpr)
				src << "mov #{reg}, [#{reg}]"
			when :&
				reg = compile_c_findreg(cp, src, state)
				e = compile_c_findvaraddr(cp, src, state, expr.rexpr, reg)
				src << (state.offset[expr.rexpr] ? "lea #{reg}, [#{e}]" : "mov #{reg}, #{e}") if e != reg
			else
				src << "; wtf? #{expr.inspect}"
			end
			return reg
		elsif not expr.rexpr
			case expr.op
			when :'++', :'--'
				op = expr.op == :'++' ? 'inc' : 'dec'
				case expr.lexpr
				when CParser::Variable
					reg = compile_c_cexpr_inner(cp, src, state, expr.lexpr)
					src << "#{op} #{reg}"
					state.pending[reg] = expr.lexpr
				when CParser::CExpression
					if expr.lexpr.op == :'*' and not expr.lexpr.lexpr
						reg = compile_c_cexpr_inner(cp, src, state, expr.lexpr.rexpr)
						src << "#{op} [#{reg}]"
						state.used.delete reg
						reg = nil
					else
						src << "; bad lvalue? #{expr.inspect}"
					end
				end
			else
				src << "; wtf? #{expr.inspect}"
			end
			return reg
		end
		case expr.op
		when :funcall
			expr.rexpr.reverse_each { |arg|
				reg = compile_c_cexpr_inner(cp, src, state, arg)
				src << "push #{reg}"
				state.used.delete reg
			}
			compile_c_flushregs(cp, src, state)
			if expr.lexpr.kind_of? CParser::Variable
				src << "call #{expr.lexpr.name}"
				if not expr.lexpr.attributes.to_a.include? 'stdcall'
					retargs = expr.rexpr.length * 4	# booh	(varargs)
					src << "add esp, #{retargs}" if retargs > 0
				end
			else
				# declspec ?
				reg = compile_c_cexpr_inner(cp, src, state, expr.lexpr)
				src << "call #{reg}"
				state.used.delete reg
			end
			:eax
#		when :'/'
#		when :'/='
#		when :'*'
#		when :'*='
#		when :'%'
#		when :'%='
		when *BASIC_OPS.keys
			# TODO shr/shar
			rl = compile_c_cexpr_inner(cp, src, state, expr.lexpr)
			rr = compile_c_cexpr_inner(cp, src, state, expr.rexpr)
			src << "#{BASIC_OPS[expr.op]} #{rl}, #{rr}"
			state.used.delete rr
			rl
		when *BASIC_OPS_LVALUE.keys
			rl = compile_c_cexpr_inner(cp, src, state, expr.lexpr)
			rr = compile_c_cexpr_inner(cp, src, state, expr.rexpr)
			state.used.delete rr
			case expr.lexpr
			when CParser::Variable
				src << "#{BASIC_OPS_LVALUE[expr.op]} #{rl}, #{rr}"
				state.pending[rl] = expr.lexpr
			when CParser::CExpression
				if expr.lexpr.op == :'*' and not expr.lexpr.lexpr
					src << "#{BASIC_OPS_LVALUE[expr.op]} [#{rl}], #{rr}"
					state.used.delete rl
					rl = nil
				else
					src << "; bad lvalue? #{expr.inspect}"
				end
			end
			rl
		else
			src << "; wtf? #{expr.inspect}"
		end
	end

	BASIC_OPS = { :+ => 'add', :- => 'sub', :^ => 'xor', :| => 'or', :& => 'and', :<< => 'shl', :>> => 'shr' }
	BASIC_OPS_LVALUE = { :'=' => 'mov', :'+=' => 'add', :'-=' => 'sub', :'^=' => 'xor',
		:'|=' => 'or', :'&=' => 'and', :'<<=' => 'shl', :'>>=' => 'shr' }

	def compile_c_cexpr(exe, cp, src, state, expr)
		src << "; #{expr.dump(state.func.initializer)[0].join}"
		compile_c_cexpr_inner(cp, src, state, expr)
	end

	def compile_c_decl(exe, cp, src, state, var)
		if var.type.kind_of? CParser::Array and
				var.type.length.kind_of? CParser::CExpression
			reg = compile_c_cexpr_inner(cp, src, state, var.type.length)
			src << "sub esp, #{reg}"
			# TODO
		end
	end

	def compile_c_ifgoto(exe, cp, src, state, expr, dst)
		case expr.op
		when :<, :>, :<=, :>=, :==, :'!='
			rl = compile_c_cexpr_inner(cp, src, state, stmt.lexpr)
			rr = compile_c_cexpr_inner(cp, src, state, stmt.rexpr)
			state.used.delete rl
			state.used.delete rr
			src << "cmp #{rl}, #{rr}"	# XXX eax/ax/al
			jop = { :== => 'jz', :'!=' => 'jnz' }
			if expr.lexpr.type.kind_of? CParser::BaseType and expr.lexpr.type.specifier == :unsigned
				jop.update :< => 'jg', :> => 'jl', :<= => 'jge', :>= => 'jle'
			else
				jop.update :< => 'jb', :> => 'ja', :<= => 'jbe', :>= => 'jae'
			end
			src << "#{jop[expr.op]} dst"
		when :'!'
			reg = compile_c_cexpr_inner(cp, src, state, stmt.test)
			state.used.delete reg
			src << "test #{reg}, #{reg}"
			src << "jz #{dst}"
		when :'&&'
			src << "; test &&"
		when :'||'
			compile_c_ifgoto(exe, cp, src, state, expr.lexpr, dst)
			compile_c_ifgoto(exe, cp, src, state, expr.rexpr, dst)
		else
			reg = compile_c_cexpr_inner(cp, src, state, stmt.test)
			state.used.delete(reg)
			src << "test #{reg}, #{reg}"
			src << "jnz #{dst}"
		end
	end

	# removes cases
	def compile_c_switch(exe, cp, src, state, stmt)
		src << "; switch"
	end

	def compile_c_goto(exe, cp, src, state, target)
		src << "jmp #{target}"
	end

	def compile_c_return(exe, cp, src, state, expr)
		reg = compile_c_cexpr_inner(cp, src, state, expr)
		state.used.delete reg
		src << "mov eax, #{reg}" if reg != :eax
	end

	def compile_c_prolog(exe, cp, src, func, state)
		localspc = state.offset.values.grep(::Integer).max
		if localspc
			src << "push ebp"
			src << "mov ebp, esp"
			src << "sub esp, #{localspc}"
		else
			state.no_saved_ebp = true
		end
		state.dirty.each { |reg|
			src << "push #{reg}"
		}
	end

	def compile_c_epilog(exe, cp, src, func, state)
		#src << "; restore esp from dynarrays"
		state.dirty.reverse_each { |reg|
			src << "pop #{reg}"
		}
		if not state.no_saved_ebp
			src << "mov esp, ebp"
			src << "pop ebp"
		end
		if func.attributes.to_a.include? 'stdcall' and
				(retargs = func.type.args.length * 4) > 0	# booh
			src << "ret #{retargs}"
		else
			src << 'ret'
		end
	end
end
end
