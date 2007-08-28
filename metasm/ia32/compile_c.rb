#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ia32/parse'
require 'metasm/compile_c'

module Metasm
class Ia32
	# returns a new State
	def compile_c_pre_prolog(exe, cp, src, func, offsets)
		state = {}
		state[:off] = offsets
		state[:func] = func
		state[:cache] = {}
		state[:dirty] = []
		state
	end


	def compile_c_cexpr_inner(cp, src, state, expr)
		case expr
		when CParser::CExpression
			case expr.op
			when :funcall
				expr.rexpr.reverse_each { |arg|
					compile_c_cexpr_inner(cp, src, state, arg)
					src << 'push eax'
				}
				if expr.lexpr.kind_of? CParser::Variable
					src << "call #{expr.lexpr.name}"
					if not expr.lexpr.attributes.to_a.include? 'stdcall'
						retargs = expr.lexpr.type.args.map { |a| cp.sizeof(a) }.inject(0) { |a, b|
							a + (b + 3)/4 * 4
						}
						src << "add esp, #{retargs}" if retargs > 0
					end
				else
					compile_c_cexpr_inner(cp, src, state, expr.lexpr)
					src << 'call eax'
					# declspec ?
				end
			when :&
				if not expr.lexpr
					if o = state[:off][expr.lexpr]
						src << "lea eax, [ebp-#{o}]"
					else
						src << "mov eax, #{expr.lexpr.name}"
					end
				else
					compile_c_cexpr_inner(cp, src, state, expr.rexpr)
					src << 'push eax'
					compile_c_cexpr_inner(cp, src, state, expr.lexpr)
					src << 'pop ebx'
					state[:dirty] |= ['ebx']
					src << 'and eax, ebx'
				end
			when :*
				if not expr.lexpr
					compile_c_cexpr_inner(cp, src, state, expr.rexpr)
					src << 'mov eax, [eax]'
				else
					compile_c_cexpr_inner(cp, src, state, expr.lexpr)
					src << 'push eax'
					compile_c_cexpr_inner(cp, src, state, expr.rexpr)
					src << 'pop edx'
					state[:dirty] |= ['edx']
					src << 'mul edx'
				end
			when :'/', :'*', :'%', *BASIC_OPS.keys
				if not expr.lexpr
					if expr.op == :-
						src << 'neg eax'
					end
				else
					compile_c_cexpr_inner(cp, src, state, expr.rexpr)
					src << 'push eax'
					compile_c_cexpr_inner(cp, src, state, expr.lexpr)
					src << 'pop ebx'
					state[:dirty] |= ['ebx']
					src << "#{BASIC_OPS[expr.op]} eax, ebx"
				end
			when :'/=', :'*=', :'%=', *BASIC_OPS_LVALUE.keys
				if expr.lexpr.kind_of? CParser::Variable
					if o = state[:off][expr.lexpr]
						o = "[ebp-#{o}]"
					else
						o = "[#{expr.lexpr.name}]"
					end
				end
				a = 'eax'
				case expr.lexpr.type
				when CParser::BaseType
					case expr.lexpr.type.name
					when :__int8: a = 'al'
					when :__int16: a = 'ax'
					end
				end
				compile_c_cexpr_inner(cp, src, state, expr.rexpr)
				if o
					src << "#{BASIC_OPS_LVALUE[expr.op]} #{o}, #{a}"
				else
					if not expr.lexpr.kind_of? CParser::CExpression or expr.lexpr.lexpr or expr.lexpr.op != :'*'
						src << "; #{BASIC_OPS_LVALUE[expr.op]} #{expr.lexpr.inspect}, #{a}"
					else
						src << "push eax"
						compile_c_cexpr_inner(cp, src, state, expr.lexpr.rexpr)
						case expr.lexpr.rexpr.type
						when CParser::BaseType
							case expr.lexpr.rexpr.type.name
							when :__int8: o = 'byte'
							when :__int16: o = 'word'
							when :__int32: o = 'dword'
							when :__int64: o = 'qword'
							end
						end
						src << "pop #{o} ptr [eax]"
					end
				end
			when :'++'
				src << "; #{(expr.lexpr || expr.rexpr).inspect} ++"
			when :'--'
				src << "; #{(expr.lexpr || expr.rexpr).inspect} --"
			when nil
				compile_c_cexpr_inner(cp, src, state, expr.rexpr)
			else
				src << "; mov eax, expr #{expr.inspect}"
			end
		when CParser::Variable
			if o = state[:off][expr]
				o = "[ebp-#{o}]"
			else
				o = "[#{expr.name}]"
			end
			a = 'eax'
			case expr.type
			when CParser::BaseType
				case expr.type.name
				when :__int8: a = 'al'
				when :__int16: a = 'ax'
				end
			end
			src << "mov #{a}, #{o}"
		else
			src << "mov eax, #{expr.inspect}"
		end
	end

	BASIC_OPS = { :+ => 'add', :- => 'sub', :^ => 'xor', :| => 'or', :& => 'and' }
	BASIC_OPS_LVALUE = { :'=' => 'mov', :'+=' => 'add', :'-=' => 'sub', :'^=' => 'xor',
		:'|=' => 'or', :'&=' => 'and' }
	def compile_c_cexpr(exe, cp, src, state, expr)
		src << "; #{expr.dump(state[:func].initializer)[0].join}"
		case expr.lexpr
		when CParser::Variable
			if o = state[:off][expr.lexpr]
				o = "[ebp-#{o}]"
			else
				o = "[#{expr.lexpr.name}]"
			end
			case expr.lexpr.type
			when CParser::BaseType
				case expr.lexpr.type.name
				when :__int8
					o = "byte ptr #{o}"
					a = 'al'
				when :__int16
					o = "word ptr #{o}"
					a = 'ax'
				when :__int32
					o = "dword ptr #{o}"
					a = 'eax'
				end
			end
		end
		case expr.op
		when :'*=', :'/=', :'%=', *BASIC_OPS_LVALUE.keys
			if o
				compile_c_cexpr_inner(cp, src, state, expr.rexpr)
				case expr.op
				when *BASIC_OPS
					src << "#{BASIC_OPS_LVALUE[expr.op]} #{o}, #{a}"
				when :'%='
					src << "div #{o}"
					src << "mov edx, #{o}"
					state[:dirty] |= ['edx']
				when :'*='
					src << "mul #{o}"
					state[:dirty] |= ['edx']
				when :'/='
					src << "div #{o}"
					state[:dirty] |= ['edx']
				end
			else
				compile_c_cexpr_inner(cp, src, state, expr)
			end
		else
			compile_c_cexpr_inner(cp, src, state, expr)
		end
	end

	def compile_c_decl(exe, cp, src, state, var)
		if var.type.kind_of? CParser::Array and
				var.type.length.kind_of? CParser::CExpression
			compile_c_cexpr_inner(cp, src, state, var.type.length)
			src << '; sub esp, eax - dynarray allocation'
			# update state[:off] ?
		end
	end

	def compile_c_ifgoto(exe, cp, src, state, expr, dst)
		# if (a) => Variable or CExpression ?
		case expr.op
		when :<, :>, :<=, :>=, :==, :'!='
			compile_c_cexpr_inner(cp, src, state, stmt.lexpr)
			src << "push eax"
			compile_c_cexpr_inner(cp, src, state, stmt.rexpr)
			src << "pop ebx"
			state[:dirty] |= ['ebx']
			src << "cmp ebx, eax"	# XXX eax/ax/al
			jop = { :== => 'jz', :'!=' => 'jnz' }
			if expr.lexpr.type.kind_of? CParser::BaseType and expr.lexpr.type.specifier == :unsigned
				jop.update :< => 'jg', :> => 'jl', :<= => 'jge', :>= => 'jle'
			else
				jop.update :< => 'jb', :> => 'ja', :<= => 'jbe', :>= => 'jae'
			end
			src << "#{jop[expr.op]} dst"
		when :'!'
			compile_c_cexpr_inner(cp, src, state, stmt.test)
			src << "test eax, eax"
			src << "jz #{dst}"
		when :'&&'
			src << "; test &&"
		when :'||'
			compile_c_ifgoto(exe, cp, src, state, expr.lexpr, dst)
			compile_c_ifgoto(exe, cp, src, state, expr.rexpr, dst)
		else
			compile_c_cexpr_inner(cp, src, state, stmt.test)
			src << "test eax, eax"
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
		compile_c_cexpr_inner(cp, src, state, expr)
	end

	def compile_c_prolog(exe, cp, src, func, state)
		localspc = state[:off].values.grep(::Integer).max
		if localspc
			src << "push ebp"
			src << "mov ebp, esp"
			src << "sub esp, #{localspc}"
		else
			state[:no_saved_ebp] = true
		end
		state[:dirty].each { |reg|
			src << "push #{reg}"
		}
	end

	def compile_c_epilog(exe, cp, src, func, state)
		src << "; restore esp from dynarrays"
		state[:dirty].reverse_each { |reg|
			src << "pop #{reg}"
		}
		if not state[:no_saved_ebp]
			src << "mov esp, ebp"
			src << "pop ebp"
		end
		if func.attributes.to_a.include? 'stdcall' and
			# XXX void foo(char toto[42]) {}
			retargs = func.args.map { |a| cp.sizeof(a) }.inject(0) { |a, b|
				a + (b + 3)/4 * 4
			} > 0
			src << "ret #{retargs}"
		else
			src << 'ret'
		end
	end
end
end
