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
	# registers are saved as register number (see Ia32::Reg)
	# TODO cache eflags ? or just z ? (may be defered to asm_optimize)
	class State
		# variable => offset from ebp (::Integer or CExpression)
		attr_accessor :offset
		# the current function
		attr_accessor :func
		# register => CExpression
		attr_accessor :cache
		# array of register values used in the function (to save/restore at prolog/epilog)
		attr_accessor :dirty
		# the register values currently in use by our caller
		attr_accessor :used
		# variable => register for current scope (variable never on the stack)
		# bound registers are also in +used+
		attr_accessor :bound

		# +used+ includes ebp if true
		# nil if ebp is not reserved for stack variable adressing
		# Reg if used
		attr_accessor :saved_ebp

		def initialize(func)
			@func = func
			@offset = {}
			@cache = {}
			@dirty = []
			@used = [4]	# esp is always in use
			@bound = {}
		end
	end

	# tracks 2 registers storing a value bigger than each
	class Composite
		attr_accessor :low, :high
		def initialize(low, high)
			       @low, @high = low, high
		end
	end

	attr_accessor :generate_PIC
	def initialize(*a)
		super
		@generate_PIC = true
		@cpusz = @exeformat.cpu.size
		@regnummax = (@cpusz == 64 ? 15 : 7)
	end

	# returns a new State
	def c_init_state(func)
		@state = State.new(func)
		argoff = 0
		al = typesize[:ptr]
		func.type.args.each { |a|
			@state.offsets[a] = -argoff
			argoff = (argoff + sizeof(a) + al - 1) / al * al
		}
		c_reserve_stack(func.initializer)
	end

	# shortcut
	def instr(name, *args)
		# XXX parse_postfix ?
		@source << Instruction.new(@exeformat.cpu, name, args)
	end

	# returns a new register number, put it in state.used
	# XXX beware of sz == 8 ! (aliasing)
	def findreg(sz = @cpusz)
		caching = @state.cache.keys.grep(Reg).map { |r| r.val }
		if not regval = ([*0..@regnummax] - @state.used - caching).first ||
		                ([*0..@regnummax] - @state.used).first
			raise 'need more registers! (or a better compiler?)'
		end

		@state.used << regval
		@state.cache.delete_if { |e, val|
			case e
			when Reg: e.val == regval
			when ModRM: e.b && (e.b.val == regval) or e.i && (e.i.val == regval)
			when Composite: e.low.val == regval or e.high.val == regval
			end
		}
		@state.dirty |= [regval]
		Reg.new(regval, sz)
	end

	# makes an argument disposable (removes from state.used)
	# works with reg/modrm
	def unuse(*val)
		val.each { |val|
			case val
			when Reg: @state.used.delete val.val if not @state.bound.index(val)
			when ModRM: unuse val.b, val.i
			when Composite: unuse val.low, val.high
			end
		}
	end

	# returns a variable storage (ModRM for stack/global, Reg for register-bound)
	def findvar(var)
		return @state.bound[var] if @state.bound[var]

		if ret = @state.cache.index(var)
			puts "ia32cc: cache hit  #{ret} -> #{var}" if $DEBUG
			return ret
		end

		case off = @state.offset[var]
		when C::CExpression
			# stack, dynamic address
			# TODO
			# no need to update state.cache here, never recursive
			raise "find dynamic addr of #{var.name}"
		when ::Integer
			# stack
			# TODO -fomit-frame-pointer ( => state.cache dependant on stack_offset... )
			ModRM.new(@state.saved_ebp.sz, sizeof(var), nil, nil, @state.saved_ebp, -off)
		when nil
			# global
			if @generate_PIC
				if not reg = @state.cache.index('metasm_intern_geteip')
					@need_geteip_stub = true
					reg = findreg

					eax = Reg.new(0, @cpusz)
					instr 'xchg', eax, reg if reg.val != 0 and @state.used.include? 0
					instr 'call', Expression['metasm_intern_geteip']
					instr 'xchg', eax, reg if reg.val != 0 and @state.used.include? 0

					@state.cache[reg] = 'metasm_intern_geteip'
				end
				ModRM.new(@cpusz, sizeof(var), nil, nil, reg, Expression[var.name, :-, 'metasm_intern_geteip'])
			else
				ModRM.new(@cpusz, sizeof(var), nil, nil, nil, Expression[var.name])
			end
		end
	end

	# converts a Reg/ModRM/Expression to Reg
	# XXX fullsize ?
	def make_reg(e)
		case e
		when ModRM
			unuse e
			reg = findreg
			instr 'mov', reg, e
		else
			reg = e
		end
		reg
	end

	# loads the immediate integral expression expr in ST(0)
	def load_fp_imm(expr)
		esp = Reg.new(4, @cpusz)
		instr 'push.i32', Expression[expr, :>>, 32]
		instr 'push.i32', Expression[expr, :>>, 32]
		instr 'fild', ModRM.new(@cpusz, 64, nil, nil, esp, nil)
		instr 'add', esp, 8
		FpReg.new
	end
	
	# compiles a c expression, returns an Ia32 instruction argument
	def c_cexpr_inner(expr)
		ret = case expr
		when ::Integer: Expression[expr]
		when C::Variable: findvar(expr)
		when C::CExpression
			if not expr.lexpr
				c_cexpr_inner_nol(expr)
			else
				c_cexpr_inner_l(expr)
			end
		end
		
		# update cache
		case ret
		when Reg, ModRM, Composite
			@state.cache[ret] = expr if expr.lexpr or not [:'--', :'++', :'+'].include? expr.op
		end

		ret
	end

	# compile a CExpression with no lexpr
	def c_cexpr_inner_nol(expr)
		case expr.op
		when nil
			# cast
			r = c_cexpr_inner(expr.rexpr)
			if expr.rexpr.kind_of? C::CExpression and expr.type.kind_of? C::BaseType and expr.rexpr.type.kind_of? C::BaseType
				esp = Reg.new(4, @cpusz)
				if expr.type.float? and expr.rexpr.type.float
					if expr.type.name != expr.rexpr.type.name and r.kind_of? ModRM
						instr 'fld', r
						r = FpReg.new
					end
				elsif expr.type.float? and expr.rexpr.type.integral?
					# XXX investigate push sizes (push al, push ax, push eax, push rax)
					unuse r
					case r
					when ModRM
						# XXX signedness ?
						if expr.rexpr.type.name == :__int8
							instr 'push', r
							r = ModRM.new(@cpusz, @cpusz, nil, nil, esp, nil)
							addesp = @cpusz
						end
					when Composite
						instr 'push', r.high
						instr 'push', r.low
						r = ModRM.new(@cpusz, 64, nil, nil, esp, nil)
						addesp = 64
					when Reg
						instr 'push', r
						psz = r.sz
						psz = @cpusz if psz == 8
						r = ModRM.new(@cpusz, psz, nil, nil, esp, nil)
						addesp = psz
					when Expression
						if expr.rexpr.type == :__int64 and @cpusz != 64
							instr 'push.i32', Expression[r, :>>, 32]
							instr 'push.i32', Expression[r, :&, 0xffff_ffff]
							r = ModRM.new(@cpusz, 64, nil, nil, esp, nil)
							addesp = 64
						else
							instr 'push', r
							r = ModRM.new(@cpusz, @cpusz, nil, nil, esp, nil)
							addesp = @cpusz
						end
					end
					instr 'fild', r
					# XXX barrier ?
					instr 'add', esp, Expression[addesp/8] if addesp
				elsif expr.type.integral? and expr.rexpr.type.float?
					case r
					when Expression
						# assume the Expression is integral
						# XXX why bother ?
						return r
						#instr 'push.i32', Expression[r, :>>, 32]
						#instr 'push.i32', Expression[r, :&, 0xffff_ffff]
						#r = ModRM.new(@cpusz, 64, nil, nil, esp, nil)
						#instr 'fild', r
						#instr 'add', esp, Expression[8]
					when ModRM
						unuse r
						instr 'fild', r
					end

					case expr.type.name
					when :__int64
						instr 'sub', esp, Expression[8]
						instr 'fistp', ModRM.new(@cpusz, 64, nil, nil, esp, nil)
						if @cpusz != 64
							r = Composite.new(findreg(32), findreg(32))
							instr 'pop', r.low
							instr 'pop', r.high
						else
							r = findreg
							instr 'pop', r
						end
					else
						instr 'sub', esp, Expression[4]
						instr 'fistp', ModRM.new(@cpusz, 32, nil, nil, esp, nil)
						r = findreg(32)
						instr 'pop', r
						r = Reg.new(r.val,  8) if expr.type.name == :__int8
						r = Reg.new(r.val, 16) if expr.type.name == :__int16
					end
				elsif expr.type.integral? and expr.rexpr.type.integral?
					tto   = typesize[expr.type.name]*8
					tfrom = typesize[expr.rexpr.type.name]*8
					if tfrom > tto and not r.kind_of? Expression
						if tfrom == 64 and r.kind_of? Composite
							unuse r.high
							r = r.low
						end
						case r
						when ModRM
							r = r.dup
							r.sz = tto
						when Reg
							r = Reg.new(r.val, tto)
						end
					elsif tto > tfrom and not r.kind_of? Expression
						if tto == 64 and @cpusz != 64
							if not r.kind_of? Reg or r.sz == 32
								unuse r
								low = findreg(32)
								if r.sz == 32
									instr 'mov', low, r
								elsif expr.type.qualifier == :unsigned
									instr 'movzx', low, r
								else
									instr 'movsx', low, r
								end
							else
								low = r
							end
							high = findreg(32)
							if expr.type.qualifier == :unsigned
								instr 'xor', high, high
							else
								instr 'mov', high, low
								instr 'sar', high, Expression[31]
							end
							r = Composite.new(high, low)
						else
							reg = findreg(tto)
							if expr.type.qualifier == :unsigned
								instr 'movzx', reg, r
							else
								instr 'movsx', reg, r
							end
							r = reg
						end
					end
				end
			end
			r
		when :+
			c_cexpr_inner(expr.rexpr)
		when :-
			r = c_cexpr_inner(expr.rexpr)
			if expr.type.integral?
				if expr.type.name == :__int64 and @cpusz != 64
					if r.kind_of? ModRM
						unuse r
						reg = Composite.new(findreg(32), findreg(32))
						ml = r.dup
						ml.sz = 32
						mh = ml.dup
						mh.imm = Expression[mh.imm, :+, 4]
						instr 'mov', reg.low, ml
						instr 'mov', reg.high, mh
						r = reg
					end
					instr 'neg', r.low
					instr 'adc', r.high, Expression[0]
					instr 'neg', r.high
				else
					if r.kind_of? ModRM or @state.bound.index(r)	# XXX used ?
						unuse r if r.kind_of? ModRM
						reg = findreg
						reg.sz = r.sz
						instr 'mov', reg, r
						r = reg
					end
					instr 'neg', r
				end
			elsif expr.type.float?
				if r.kind_of? ModRM
					unuse r
					instr 'fld', r
					r = FpReg.new
				end
				instr 'fchs'
			else raise
			end
			r
		when :'++', :'--'
			# 'i++ + i;'  =>  'a = i; b = i+1; i+=1 ; a+b;'
			r = c_cexpr_inner(expr.rexpr)
			inc = true if op == :'++'
			if expr.type.integral?
				if expr.type.name == :__int64 and @cpusz != 64
					if r.kind_of? ModRM
						ml = r.dup
						ml.sz = 32
						mh = ml.dup
						mh.imm = Expression[mh.imm, :+, 4]
					else
						ml = r.low
						mh = r.high
					end
					instr 'add', ml, Expression[inc ? 1 : -1]
					instr 'adc', mh, Expression[inc ? 0 : -1]
				else
					op = (inc ? 'inc' : 'dec')
					instr op, r
				end
			elsif expr.type.float?
				instr 'fld1'
				op = (inc ? 'faddp' : 'fsubp')
				instr op, FpReg.new(1)
			end
			r
		when :&
			r = findvar(expr.rexpr)
			raise 'cannot take addr of ' + expr.to_s + r.inspect if not expr.rexpr.kind_of? C::Variable or not r.kind_of? ModRM
			if r.b or r.i
				# r.seg is ignored by lea
				unuse r
				reg = findreg
				instr 'lea', reg, r
				reg
			else
				r.imm
			end
		when :*
			e = expr.rexpr
			m = ModRM.new(@cpusz, sizeof(e), nil, nil, nil, nil)
			if e.kind_of? C::CExpression and e.op == :+ and e.lexpr	# TODO or e.op == :-
				# *(a+b), *(a+(b*c)), TODO *(a+(b*c)+d) (seen in ary[off].bla)
				case b = c_cexpr_inner(e.lexpr)
				when Expression: m.imm = b
				when ModRM, Reg: m.b = make_reg(b)
				end

				ee = e.rexpr
				if ee.kind_of? C::CExpression and ee.op == :* and ee.lexpr and
					ee.rexpr.kind_of? C::CExpression and not ee.rexpr.op and [1,2,4,8].include? ee.rexpr.rexpr
					i = c_cexpr_inner(ee.lexpr)
					i = make_reg(i)
					if ee.rexpr.rexpr == 1 and not m.b
						m.b = i
					else
						m.i = i
						m.s = ee.rexpr.rexpr
					end
				else
					case off = c_cexpr_inner(ee.lexpr)
					when Expression
						m.imm = off
					when ModRM, Reg
						off = make_reg(off)
						if not m.b
							m.b = off
						else
							m.i = off
							m.s = 1
						end
					end
				end
			else
				case p = c_cexpr_inner(e)
				when Expression: m.imm = p
				when ModRM, Reg: m.b = make_reg(p)
				end
			end
			m
		else raise 'mmh ? ' + expr.inspect
		end
	end

	# compiles a CExpression having a lexpr
	def c_cexpr_inner_l(expr)
		case expr.op
		when :funcall
			# TODO __fastcall
			expr.rexpr.reverse_each { |arg|
				a = c_cexpr_inner(arg)
				unuse a
				case arg.type
				when BaseType
					case t = arg.type.name
					when :__int8
						instr 'push', a
					when :__int16
						if @cpusz != 16 and a.kind_of? Reg
							instr 'push', Reg.new(a.val, @cpusz)
						else
							instr 'push', a
						end
					when :__int32
						# XXX 64bits && Reg ?
						instr 'push', a
					when :__int64
						case a
						when Composite
							instr 'push', a.high
							instr 'push', a.low
						when Reg
							instr 'push', a
						when ModRM
							if @cpusz == 64
								instr 'push', a
							else
								ml = a.dup
								ml.sz = 32
								mh = ml.dup
								mh.imm = Expression[mh.imm, :+, 4]
								instr 'push', mh
								instr 'push', ml
							end
						when Expression
							instr 'push.i32', Expression[a, :>>, 32]
							instr 'push.i32', Expression[a, :&, 0xffff_ffff]
						end
					when :float, :double, :longdouble
						esp = Reg.new(4, @cpusz)
						case a
						when Expression
							# assume expr is integral
							a = load_fp_imm(a)
						when ModRM
							instr 'fld', a
						end
						instr 'sub', esp, typesize[t]
						instr 'fstp', ModRM.new(@cpusz, (t == :longdouble ? 80 : (t == :double ? 64 : 32)), nil, nil, esp, nil)
					end
				when Union
					raise 'want a modrm ! ' + a.inspect if not a.kind_of? ModRM
					reg = findreg
					unuse reg
					al = typesize[:ptr]
					argsz = (sizeof(arg) + al - 1) / al * al
					while argsz > 0
						argsz -= reg.sz
						m = a.dup
						m.imm = Expression[m.imm, :+, argsz]
						instr 'push', m
					end
				end
			}
			if expr.lexpr.kind_of? C::Variable
				instr 'call', Expression[expr.lexpr.name]
				if not expr.lexpr.attributes.to_a.include? 'stdcall'
					al = typesize[:ptr]
					argsz = expr.rexpr.inject(0) { |sum, a| sum + (sizeof(a) + al - 1) / al * al }
					instr 'add', Reg.new(4, @cpusz), Expression[argsz] if argsz > 0
				end
			else
				# TODO declspec
				ptr = c_cexpr_inner(expr.lexpr)
				unuse ptr
				instr 'call', ptr
			end
			expr.lexpr.type.float? ? FpReg.new : Reg.new(0, @cpusz)

		# for arithmetic operations, both sides are cast to the same type by the precompilator
		when :+, :-, :'+=', :'-='
			op =	case expr.op
				when :+, :'+=': 'add'
				when :-, :'-=': 'sub'
				end

			l = c_expr_inner(expr.lexpr)
			instr 'fld', al if expr.type.float? and l.kind_of? ModRM		# must push in order on fpstack
			r = c_expr_inner(expr.rexpr)

			case expr.op
			when :'+=', :'-='
				raise 'bad lvalue ' + l.inspect if not l.kind_of? ModRM and not @state.bound.index(l)
			when :+, :-
				# l = make_volatile l
				if expr.type.name == :__int64 and @cpusz != 64
					l2 = Composite.new(findreg(32), findreg(32))
					case l
					when ModRM
						ll = l.dup
						ll.sz = 32
						lh = ll.dup
						lh.imm = Expression[lh, :+, 4]
					when Composite
						ll = l.low
						lh = l.high
					else raise
					end
					instr 'mov', l2.low, ll
					instr 'mov', l2.high, lh
				else
					# XXX set l2.sz, beware __int8 -> !ah
					l2 = findreg
					instr 'mov', l2, l
				end
				unuse l if l.kind_of? ModRM
				l = l2
			end if expr.type.integral? and (l.kind_of? ModRM or @state.bound.index(l))

			raise 'bad lvalue' if not l.kind_of? ModRM and not @state.bound.index(l) and (expr.op == :'+=' or expr.op == :'-=')

			if expr.type.integral?
				unuse r
				if expr.type.name == :__int64 and @cpusz != 64
					case l
					when ModRM
						ll = l.dup
						ll.sz = 32
						lh = ll.dup
						lh.imm = Expression[lh, :+, 4]
					when Expression
						return Expression.new[l, expr.op, r] if r.kind_of? Expression
						ll = Expression[l, :&, 0xffff_ffff]
						lh = Expression[l, :>>, 32]
						l = Composite.new(findreg(32), findreg(32))
						instr 'mov', l.low, ll
						instr 'mov', l.high, lh
						ll = l.low
						lh = l.high
					when Composite
						ll = l.low
						lh = l.high
					else raise
					end

					case r
					when ModRM
						rl = r.dup
						rl.sz = 32
						rh = rl.dup
						rh.imm = Expression[rh.imm, :+, 4]
						if l.kind_of? ModRM
							# add [x], [y]
							r2h = findreg(32)
							# undo unuse(r)
							@state.used[r.b] = true if r.b
							@state.used[r.i] = true if r.i
							r2l = findreg(32)
							unuse r, r2h, r2l
							instr 'mov', r2l, rl
							instr 'mov', r2h, rh
							rl = r2l
							rh = r2h
						end
					when Expression
						rl = Expression[r, :&, 0xffff_ffff]
						rh = Expression[r, :>>, 32]
					when Composite
						rl = r.low
						rh = r.high
					end
					instr op, ll, rl
					op = {'add' => 'adc', 'sub' => 'sbb'}[op]
					instr op, lh, rh
				else
					if l.kind_of? ModRM and r.kind_of? ModRM
						# TODO r = make_volatile r
						r2 = findreg
						instr 'mov', r, r2
						r = r2
						unuse r
					end
					instr op, l, r
				end

			elsif expr.type.float?
				case r
				when FpReg
					instr "f#{op}p", FpReg.new(1)
				when ModRM
					instr "f#{op}", r	# XXX pop ?
				else raise
				end
				case expr.op
				when :'+=', :'-='
					raise 'bad lvalue' if not l.kind_of? ModRM
					instr 'fstp', l
				end
			end
			l

		when :'='
			l = c_expr_inner(expr.lexpr)
			r = c_expr_inner(expr.rexpr)
			unuse r
			raise 'bad lvalue ' + l.inspect if not l.kind_of? ModRM and not @state.bound.index(l)
			if expr.type.integral?
				if expr.type.name == :__int64 and @cpusz != 64
					if r.kind_of? ModRM
						rh = findreg(32)
						@state.used[r.b] = true if r.b # need to reuse r
						@state.used[r.i] = true if r.i
						rl = findreg(32)
						unuse r.b if r.b and rh.val != r.b.val
						unuse r.i if r.i and rh.val != r.i.val
						r = r.dup
						r.sz = 32
						instr 'mov', rl, r
						r = r.dup
						r.imm = Expression[r.imm, :+, 4]
						instr 'mov', rh, r
						r = Composite.new(rl, rh)
					end
					case r
					when Composite
						rl = r.low
						rh = r.high
					when Expression
						rl = Expression[r, :&, 0xffff_ffff]
						rh = Expression[r, :>>, 32]
					end
					# Composite are never bound
					ll = l.dup
					ll.sz = 32
					lh = ll.dup
					lh.imm = Expression[lh, :+, 4]
					instr 'mov', ll, rl
					instr 'mov', lh, rh
				else
					if r.kind_of? ModRM
						rr = findreg
						# TODO movzx
						instr 'mov', r, rr
						r = rr
					end
					instr 'mov', l, r
				end
			elsif expr.type.float?
				# XXX ?
				instr 'fld', r
				instr 'fstp', l
			end
# TODO
		#when :>>, :<<
		#when :'<<=', :'>>='
		#when :'/'
		#when :'/='
		#when :'%'
		#when :'%='
		#when :'*'
		#when :'*='
		else
			raise 'unhandled cexpr ' + expr.to_s
		end
	end

	def c_cexpr(expr)
		case expr.op
		when :+, :-, :*, :/, :&, :|, :^, :%, :[], nil, :'.', :'->',
			:>, :<, :<=, :>=, :==, :'!=', :'!'
			# skip no-ops
			c_cexpr(expr.lexpr) if expr.lexpr.kind_of? C::CExpression
			c_cexpr(expr.rexpr) if expr.rexpr.kind_of? C::CExpression
		else c_cexpr_inner(expr)
		end
	end

	def c_decl(var)
		if var.type.kind_of? C::Array and
				var.type.length.kind_of? C::CExpression
			reg = c_cexpr_inner(var.type.length)
			unuse reg
			instr 'sub', Reg.new(4, @cpusz), reg
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
		instr 'jmp', Expression[target]
	end

	def c_label(name)
		state.cache.clear
		@source << Label.new(name)
	end

	def c_return(expr)
		if expr
			ret = c_cexpr_inner(expr)
			unuse ret
			if not ret.kind_of? Reg or ret.val != 0
				eax = Reg.new(0, @cpusz)
				if (ret.kind_of? Reg or ret.kind_of? ModRM) and ret.sz != eax.sz
					rettype = @state.func.type.type
					if rettype.kind_of? C::BaseType and rettype.specifier != :unsigned
						op = 'movsx'
					else
						op = 'movzx'
					end
				else
					op = 'mov'
				end
				instr op, eax, ret
			end
		end
	end

	def c_asm(stmt)
		super
	end

	def c_prolog
		localspc = @state.offset.values.grep(::Integer).max
		if localspc
			al = typesize[:ptr]
			localspc = (localspc + al - 1) / al * al
			@state.saved_ebp = ebp = Reg.new(5, @cpusz)
			@state.used << 5
			esp = Reg.new(4, ebp.sz)
			instr 'push', ebp
			instr 'mov', ebp, esp
			instr 'sub', esp, Expression[localspc]
		end
		@state.dirty -= [0]	# XXX ABI
		@state.dirty.each { |reg|
			instr 'push', Reg.new(reg, @cpusz)
		}
	end

	def c_epilog
		# TODO revert dynamic array alloc
		@state.dirty.reverse_each { |reg|
			instr 'pop', Reg.new(reg, @cpusz)
		}
		if ebp = @state.saved_ebp
			instr 'mov', Reg.new(4, ebp.sz), ebp
			instr 'pop', ebp
		end
		f = @state.func
		al = typesize[:ptr]
		argsz = f.args.inject(0) { |sum, a| sum += (sizeof(a) + al - 1) / al * al }
		if f.attributes.to_a.include? 'stdcall' and argsz > 0
			instr 'ret', Expression[argsz]
		else
			instr 'ret'
		end
	end

	# adds the metasm_intern_geteip function, which returns its own adress in eax (used for PIC adressing)
	def c_program_epilog
		if defined? @need_geteip_stub and @need_geteip_stub
			eax = Reg.new(0, @cpusz)
			label = new_label('geteip')

			@source << Label.new('metasm_intern_geteip')
			instr 'call', Expression[label]
			@source << Label.new(label)
			instr 'pop', eax
			instr 'add', eax, Expression['metasm_intern_geteip', :-, label]
			instr 'ret'
		end
	end
end

	def compile_c(parser, exe=ExeFormat.new)
		exe.cpu ||= self
		cmp = CCompiler.new(parser, exe)
		cmp.compile
	end
end
end
