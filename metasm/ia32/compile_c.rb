#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ia32/parse'
require 'metasm/compile_c'

module Metasm
class Ia32
class CCompiler < C::Compiler
	# holds compiler state information for a function
	class State
		# variable => offset from ebp (::Integer or CExpression)
		# TODO dynamicarray/nestedfunc/arg/varargs
		attr_accessor :offset
		# the current function
		attr_accessor :func
		# the current register values (reg symbol => CExpression, reg size from expr.type)
		attr_accessor :regs
		# array of registers used (to save/restore at prolog/epilog)
		attr_accessor :dirty
		# the register currently in use by our caller
		attr_accessor :used
		# variable => register for current scope (variable never on the stack)
		attr_accessor :bound

		# bool
		attr_accessor :saved_ebp

		def initialize(func)
			@func = func
			@offset = {}
			@regs = {}
			@dirty = []
			@used = []
			@bound = {}
		end
	end

	BASIC_OPS = { :+ => 'add', :- => 'sub', :^ => 'xor', :| => 'or', :& => 'and', :<< => 'shl', :>> => 'shr' }
	BASIC_OPS_LVALUE = { :'=' => 'mov', :'+=' => 'add', :'-=' => 'sub', :'^=' => 'xor',
		:'|=' => 'or', :'&=' => 'and', :'<<=' => 'shl', :'>>=' => 'shr' }

	# returns a new State
	def c_init_state(func)
		@state = State.new(func)
		c_reserve_stack(func.initializer)
		# TODO add args to state.offset
	end

	# returns a new register, put it in state.used
	def findreg
		reg = [:eax, :ebx, :ecx, :edx, :edi, :esi].find { |r| not @state.used.include? r }
		if not reg
			raise 'need more registers! (or a better compiler?)'
		end

		@state.used << reg
		@state.regs.delete reg
		@state.dirty |= [reg] if not [:eax].include? reg	# XXX ABI
		reg
	end

	# returns the address of a variable in reg
	def findvaraddr(var, reg=nil)
		return @state.bound[var] if @state.bound[var]

		case e = @state.offset[var]
		when C::CExpression
			# automatic, dynamic address
			# TODO
			raise "find dynamic addr of #{var.name} in #{reg}"
		when ::Integer
			# automatic
			"ebp-#{e}"
		when nil
			# static
			# TODO choice for position-independant code
			if true
				reg ||= findreg
				@source << 'push eax' if reg != :eax and @state.used.include? :eax
				@source << "call metasm_intern_geteip"
				@source << "mov #{reg}, eax" if reg != :eax
				@source << 'pop eax' if reg != 'eax' and @state.used.include? :eax
				@source << "add #{reg}, #{var.name} - metasm_intern_geteip"
				reg
			else
				var.name
			end
		end
	end
	
	# adds the metasm_intern_geteip function, which returns its own adress in eax (used for PIC adressing)
	def c_program_epilog
		@source <<
			'metasm_intern_geteip:' <<
			'call 123123f' <<
			'123123: pop eax' <<
			'add eax, metasm_intern_geteip-123123b' <<
			'ret'
	end

	# compiles a c expression, updates state
	# returns the register containing the value
	# TODO XXX floating point (or anything other than int)
	def c_cexpr_inner(expr, want=nil)
		case expr
		when C::Variable
			if not reg = @state.regs.keys.find { |reg| @state.regs[reg] == expr }
				e = findvaraddr(expr)
				case expr.type
				when C::Array
					if e != reg
						use_lea = e.to_s[1..-1].count('+-*') > 0
						@source << (use_lea ? "lea #{reg}, [#{e}]" : "mov #{reg}, #{e}")
					end
					@source << "push #{reg}" if want == :push
				else
					if want == :push
						@source << "push [#{e}]"
					else
						@source << "mov #{reg}, [#{e}]"
					end
				end
			end
			return reg
		when ::Integer
			@source << "push #{expr}" if want == :push
			return expr
		end
		if not expr.lexpr
			case expr.op
			when nil
				# TODO movzx etc
				reg = c_cexpr_inner(expr.rexpr)
			when :+
				reg = c_cexpr_inner(expr.rexpr)
			when :-
				reg = c_cexpr_inner(expr.rexpr)
				@source << "neg #{reg}"
			when :*
				case expr.rexpr
				when C::CExpression
					case expr.op
					when :'+', :'*'
						@source << '; TODO optimize dereference'
					end
				end
				reg = c_cexpr_inner(expr.rexpr)
				@source << "mov #{reg}, [#{reg}]"
			when :&
				reg = findreg
				e = findvaraddr(expr.rexpr, reg)
				@source << (@state.offset[expr.rexpr] ? "lea #{reg}, [#{e}]" : "mov #{reg}, #{e}") if e != reg
			else
				@source << "; wtf? #{expr.inspect}"
			end
			return reg
		elsif not expr.rexpr
			case expr.op
			when :'++', :'--'
				op = expr.op == :'++' ? 'inc' : 'dec'
				case expr.lexpr
				when C::Variable
					reg = c_cexpr_inner(expr.lexpr)
					@source << "#{op} #{reg}"
					@state.pending[reg] = expr.lexpr
				when C::CExpression
					if expr.lexpr.op == :'*' and not expr.lexpr.lexpr
						reg = c_cexpr_inner(expr.lexpr.rexpr)
						@source << "#{op} [#{reg}]"
						@state.used.delete reg
						reg = nil
					else
						@source << "; bad lvalue? #{expr.inspect}"
					end
				end
			else
				@source << "; wtf? #{expr.inspect}"
			end
			return reg
		end
		case expr.op
		when :funcall
			expr.rexpr.reverse_each { |arg|
				reg = c_cexpr_inner(arg)
				@source << "push #{reg}"
				@state.used.delete reg
			}
			if expr.lexpr.kind_of? C::Variable
				@source << "call #{expr.lexpr.name}"
				if not expr.lexpr.attributes.to_a.include? 'stdcall'
					retargs = expr.rexpr.length * 4	# booh	(varargs)
					@source << "add esp, #{retargs}" if retargs > 0
				end
			else
				# declspec ?
				reg = c_cexpr_inner(expr.lexpr)
				@source << "call #{reg}"
				@state.used.delete reg
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
			rl = c_cexpr_inner(expr.lexpr)
			rr = c_cexpr_inner(expr.rexpr)
			@source << "#{BASIC_OPS[expr.op]} #{rl}, #{rr}"
			@state.used.delete rr
			rl
		when *BASIC_OPS_LVALUE.keys
			rl = c_cexpr_inner(expr.lexpr)
			rr = c_cexpr_inner(expr.rexpr)
			@state.used.delete rr
			case expr.lexpr
			when C::Variable
				@source << "#{BASIC_OPS_LVALUE[expr.op]} #{rl}, #{rr}"
				@state.pending[rl] = expr.lexpr
			when C::CExpression
				if expr.lexpr.op == :'*' and not expr.lexpr.lexpr
					@source << "#{BASIC_OPS_LVALUE[expr.op]} [#{rl}], #{rr}"
					@state.used.delete rl
					rl = nil
				else
					@source << "; bad lvalue? #{expr.inspect}"
				end
			end
			rl
		else
			@source << "; wtf? #{expr.inspect}"
		end
	end

	def c_cexpr(expr)
		@source << "; #{expr.dump(C::Block.new(nil))[0].join}"
		c_cexpr_inner(expr)
	end

	def c_decl(var)
		if var.type.kind_of? C::Array and
				var.type.length.kind_of? C::CExpression
			reg = c_cexpr_inner(var.type.length)
			@source << "sub esp, #{reg}"
			# TODO
		end
	end

	def c_ifgoto(expr, target)
		case expr.op
		when :<, :>, :<=, :>=, :==, :'!='
			rl = c_cexpr_inner(expr.lexpr)
			rr = c_cexpr_inner(expr.rexpr)
			@state.used.delete rl
			@state.used.delete rr
			@source << "cmp #{rl}, #{rr}"	# XXX eax/ax/al

			jop = { :== => 'jz', :'!=' => 'jnz' }
			if expr.lexpr.type.kind_of? C::BaseType and expr.lexpr.type.specifier == :unsigned
				jop.update :< => 'jg', :> => 'jl', :<= => 'jge', :>= => 'jle'
			else
				jop.update :< => 'jb', :> => 'ja', :<= => 'jbe', :>= => 'jae'
			end
			@source << "#{jop[expr.op]} #{target}"
		when :'!'
			reg = c_cexpr_inner(expr.rexpr)
			@state.used.delete reg
			@source << "test #{reg}, #{reg}"
			@source << "jz #{target}"
		else
			reg = c_cexpr_inner(expr)
			@state.used.delete reg
			@source << "test #{reg}, #{reg}"
			@source << "jnz #{target}"
		end
	end

	def c_goto(target)
		@source << "jmp #{target}"
	end

	def c_return(expr)
		if expr
			reg = c_cexpr_inner(expr)
			@state.used.delete reg
			@source << "mov eax, #{reg}" if reg != :eax
		end
	end

	def c_prolog
		localspc = @state.offset.values.grep(::Integer).max
		if localspc
			a = typesize[:ptr]
			localspc = (localspc + a - 1) / a * a
			@source << 'push ebp'
			@source << 'mov ebp, esp'
			@source << "sub esp, #{localspc}"
			@state.saved_ebp = true
			@state.used << :ebp
		end
		@state.dirty.each { |reg|
			@source << "push #{reg}"
		}
	end

	def c_epilog
		#src << "; restore esp from dynarrays"
		@state.dirty.reverse_each { |reg|
			@source << "pop #{reg}"
		}
		if @state.saved_ebp
			@source << 'mov esp, ebp'
			@source << 'pop ebp'
		end
		if @state.func.attributes.to_a.include? 'stdcall' and
				(retargs = @state.func.type.args.length * 4) > 0	# booh
			@source << "ret #{retargs}"
		else
			@source << 'ret'
		end
	end
end

	def compile_c(parser, exe=ExeFormat.new)
		cmp = CCompiler.new(parser, exe)
		cmp.compile
	end
end
end
