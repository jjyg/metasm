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
		def sz; 64 end
	end

	def initialize(*a)
		super
		@generate_PIC = @exeformat.cpu.generate_PIC
		@cpusz = @exeformat.cpu.size
		@regnummax = (@cpusz == 64 ? 15 : 7)
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

		v =
		case off = @state.offset[var]
		when C::CExpression
			# stack, dynamic address
			# TODO
			# no need to update state.cache here, never recursive
			raise "find dynamic addr of #{var.name}"
		when ::Integer
			# stack
			# TODO -fomit-frame-pointer ( => state.cache dependant on stack_offset... )
			ModRM.new(@state.saved_ebp.sz, 8*sizeof(var), nil, nil, @state.saved_ebp, -off)
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
				ModRM.new(@cpusz, 8*sizeof(var), nil, nil, reg, Expression[var.name, :-, 'metasm_intern_geteip'])
			else
				ModRM.new(@cpusz, 8*sizeof(var), nil, nil, nil, Expression[var.name])
			end
		end

		case var.type
		when C::Array
			v.sz = 8*typesize[:ptr]
			if not v.b and not v.i: v.imm
			elsif (not v.b and v.s == 1) or not v.i: v.b || v.i
			else
				unuse v
				r = findreg
				instr 'lea', r, v
				r
			end
		else v
		end
	end

	# copies the arg e to a volatile location (register/composite) if it is not already
	# unuses the old storage if ModRM
	# may return a register bigger than the type size (eg __int8 are stored in full reg size)
	def make_volatile(e, type, rsz=@cpusz)
		if e.kind_of? ModRM or @state.bound.index(e)
			if type.integral?
				oldval = @state.cache[e]
				if type.name == :__int64 and @cpusz != 64
					e2l = findreg(32)
					unuse e
					e2h = findreg(32)
					case e
					when ModRM
						el = e.dup
						el.sz = 32
						eh = el.dup
						eh.imm = Expression[eh, :+, 4]
					when Composite
						el = e.low
						eh = e.high
					else raise
					end
					instr 'mov', e2l, el
					instr 'mov', e2h, eh
					e2 = Composite.new(e2l, e2h)
				else
					unuse e
					if (sz = typesize[type.name]*8) < @cpusz or sz < rsz
						e2 = findreg(rsz)
						op = ((type.specifier == :unsigned) ? 'movzx' : 'movsx')
					else
						e2 = findreg(sz)
						op = 'mov'
					end
					instr op, e2, e
				end
				@state.cache[e2] = oldval if oldval and e.kind_of? ModRM
				e2
			elsif type.float?
				raise 'bad float static' + e.inspect if not e.kind_of? ModRM
				unuse e
				instr 'fld', e
				FpReg.new nil
			end
		elsif e.kind_of? Expression
			if type.integral?
				if type.name == :__int64 and @cpusz != 64
					e2 = Composite.new(findreg(32), findreg(32))
					instr 'mov', e2.low, Expression[e, :&, 0xffff_ffff]
					instr 'mov', e2.high, Expression[e, :>>, 32]
				else
					e2 = findreg
					instr 'mov', e2, e
				end
				e2
			elsif type.float?
				case e.reduce
				when 0: instr 'fldz'
				when 1: instr 'fld1'
				else
					esp = Reg.new(4, @cpusz)
					instr 'push.i32', Expression[expr, :>>, 32]
					instr 'push.i32', Expression[expr, :&, 0xffff_ffff]
					instr 'fild', ModRM.new(@cpusz, 64, nil, nil, esp, nil)
					instr 'add', esp, 8
				end
				FpReg.new nil
			end
		else
			e
		end
	end
	
	# returns two args corresponding to the low and high 32bits of the 64bits composite arg
	def get_composite_parts(e)
		case e
		when ModRM
			el = e.dup
			el.sz = 32
			eh = el.dup
			eh.imm = Expression[eh.imm, :+, 4]
		when Expression
			el = Expression[e, :&, 0xffff_ffff]
			eh = Expression[e, :>>, 32]
		when Composite
			el = e.low
			eh = e.high
		else raise
		end
		[el, eh]
	end

	def getcc(op, type)
		case op
		when :'==': 'z'
		when :'!=': 'nz'
		when :'<' : 'b'
		when :'>' : 'a'
		when :'<=': 'be'
		when :'>=': 'ae'
		else raise "bad comparison op #{op}"
		end.tr((type.specifier == :unsigned ? '' : 'ab'), 'gl')
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
			@state.cache[ret] = expr if expr.kind_of? C::Variable #CExpression and (expr.lexpr or not [:'--', :'++', :'+'].include? expr.op)
		end

		ret
	end

	# compile a CExpression with no lexpr
	def c_cexpr_inner_nol(expr)
		case expr.op
		when nil
			r = c_cexpr_inner(expr.rexpr)
			if expr.rexpr.kind_of? C::CExpression and expr.type.kind_of? C::BaseType and expr.rexpr.type.kind_of? C::BaseType
				r = c_cexpr_inner_cast(expr, r)
			elsif r.kind_of? ModRM
				r = r.dup
				r.sz = sizeof(expr)*8
			end
			r
		when :+
			c_cexpr_inner(expr.rexpr)
		when :-
			r = c_cexpr_inner(expr.rexpr)
			r = make_volatile(r, expr.type)
			if expr.type.integral?
				if r.kind_of? Composite
					instr 'neg', r.low
					instr 'adc', r.high, Expression[0]
					instr 'neg', r.high
				else
					instr 'neg', r
				end
			elsif expr.type.float?
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
				raise 'bad lvalue' if not r.kind_of? ModRM
				instr 'fld1'
				op = (inc ? 'faddp' : 'fsubp')
				instr op, r
				instr 'fstp', r
			end
			r
		when :&
			r = c_cexpr_inner(expr.rexpr)
			raise 'bad lvalue' if not r.kind_of? ModRM
			if r.b or r.i
				# r.seg is ignored by lea
				if not r.imm and ((not r.b and r.s == 1) or not r.i)
					return r.b || r.i
				end
				unuse r
				reg = findreg
				r = r.dup
				r.sz = reg.sz
				instr 'lea', reg, r
				reg
			elsif r.imm
				r.imm
			else
				raise 'bad modrm'
			end
		when :*
			# optimized modrm
			e = expr.rexpr
			m = ModRM.new(@cpusz, 8*sizeof(expr), nil, nil, nil, nil)
			if e.kind_of? C::CExpression and e.op == :+ and e.lexpr	# TODO or e.op == :-
				# *(a+b), *(a+(b*c)), TODO *(a+(b*c)+d) (seen in ary[off].bla)
				case b = c_cexpr_inner(e.lexpr)
				when Expression: m.imm = b
				when ModRM: m.b = make_volatile(b, e.lexpr.type)
				when Reg: m.b = b
				end

				ee = e.rexpr
				if ee.kind_of? C::CExpression and ee.op == :* and ee.lexpr and
					ee.rexpr.kind_of? C::CExpression and not ee.rexpr.op and [1,2,4,8].include? ee.rexpr.rexpr
					i = c_cexpr_inner(ee.lexpr)
					i = make_volatile(i, ee.lexpr.type) if not i.kind_of? Reg
					if ee.rexpr.rexpr == 1 and not m.b
						m.b = i
					else
						m.i = i
						m.s = ee.rexpr.rexpr
					end
				else
					case off = c_cexpr_inner(ee)
					when Expression
						m.imm = off
					when ModRM, Reg
						off = make_volatile(off, ee.lexpr.type) if not off.kind_of? Reg
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
				when ModRM: m.b = make_volatile(p, e.type)
				when Reg: m.b = p
				end
			end
			m
		when :'!'
			r = c_cexpr_inner(expr.rexpr)
			r = make_volatile(r, expr.rexpr.type)
			if expr.rexpr.type.integral?
				if expr.rexpr.type.name == :__int64 and @cpusz != 64
					raise # TODO
				end
				instr 'test', r, Expression[-1]
			elsif expr.lexpr.type.float?
				if @exeformat.cpu.opcode_list_byname['fucomip']
					instr 'fldz'
					instr 'fucomip'
				else
					raise # TODO
				end
				r = findreg
			else raise 'bad comparison ' + expr.to_s
			end
			opcc = getcc(expr.op, expr.type)
			if @exeformat.cpu.opcode_list_byname['set'+opcc]
				instr 'set'+opcc, r
			else
				instr 'mov', r, Expression[1]
				label = new_label('setcc')
				instr 'j'+opcc, Expression[label]
				instr 'mov', r, Expression[0]
				@source << Label.new(label)
			end
		else raise 'mmh ? ' + expr.to_s
		end
	end

	# compile a cast (BaseType to BaseType)
	def c_cexpr_inner_cast(expr, r)
		esp = Reg.new(4, @cpusz)
		if expr.type.float? and expr.rexpr.type.float?
			if expr.type.name != expr.rexpr.type.name and r.kind_of? ModRM
				instr 'fld', r
				r = FpReg.new nil
			end
		elsif expr.type.float? and expr.rexpr.type.integral?
			return make_volatile(r, expr.type) if r.kind_of? Expression
			unuse r
			case r
			when ModRM
				case expr.rexpr.type.name
				when :__int8, :__int16
					r = make_volatile(r, expr.rexpr.type, 32)
					instr 'push', r
				else
					if expr.rexpr.type.specifier != :unsigned
						instr 'fild', r
						return FpReg.new(nil)
					end
					instr 'push', r
				end
			when Composite
				instr 'push', r.high
				instr 'push', r.low
			when Reg
				instr 'push', r
			end
			m = ModRM.new(@cpusz, r.sz, nil, nil, esp, nil)
			instr 'fild', m
			if expr.rexpr.type.specifier == :unsigned
				t = findreg(32)
				unuse t
				raise
				if m.sz == 64
					mm = m.dup
					mm.sz = 32
					mm.imm = Expression[mm.imm, :+, 4]
					instr 'mov', t, mm
					fcst = @prolog_add_variables['floatunsigned64'] ||= C::Variable.new	# TODO
				else
					instr 'mov', t, m
					fcst = @prolog_add_variables['floatunsigned32'] ||= C::Variable.new
					fcst.initializer = (1<<31).to_f	# 0xffff_ffff + fcst => 0x0000_0000_ffff_ffff
				end
				instr 'test', t, t
				label = new_label('unsignedfloat')
				instr 'jns', label
				fcst = c_cexpr_inner(fcst)
				instr 'fadd', fcst
				@source << Label.new(label)
			end
			instr 'add', esp, Expression[r.sz/8]
			r = FpReg.new nil
		elsif expr.type.integral? and expr.rexpr.type.float?
			r = make_volatile(r, expr.rexpr.type)

			if expr.type.name == :__int64
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
				tto = typesize[expr.type.name]*8
				instr 'and', r, Expression[(1<<tto)-1] if r.sz > tto
			end
		elsif expr.type.integral? and expr.rexpr.type.integral?
			tto   = typesize[expr.type.name]*8
			tfrom = typesize[expr.rexpr.type.name]*8
			if r.kind_of? Expression
				r = make_volatile r, expr.type
			elsif tfrom > tto
				if tfrom == 64 and r.kind_of? Composite
					unuse r.high
					r = r.low
				end
				case r
				when ModRM
					r = r.dup
					r.sz = tto
				when Reg
					instr 'and', r, Expression[(1<<tto)-1] if r.sz > tto
				end
			elsif tto > tfrom
				if tto == 64 and @cpusz != 64
					if not r.kind_of? Reg or r.sz != 32
						unuse r
						low = findreg(32)
						op = (r.sz == 32 ? 'mov' : (expr.type.specifier == :unsigned ? 'movzx' : 'movsx'))
						instr op, low, r
						r = low
					end
					r = Composite.new(r, findreg(32))
					if expr.type.specifier == :unsigned
						instr 'xor', r.high, r.high
					else
						instr 'mov', r.high, r.low
						instr 'sar', r.high, Expression[31]
					end
				else
					reg = findreg
					op = (r.sz == reg.sz ? 'mov' : (expr.type.specifier == :unsigned ? 'movzx' : 'movsx'))
					instr op, reg, r
					r = reg
				end
			end
		end
		r
	end

	# compiles a CExpression, not arithmetic (assignment, comparison etc)
	def c_cexpr_inner_l(expr)
		case expr.op
		when :funcall
			c_cexpr_inner_funcall(expr)
		when :'+=', :'-=', :'*=', :'/=', :'%=', :'^=', :'&=', :'|=', :'<<=', :'>>='
			l = c_cexpr_inner(expr.lexpr)
			raise 'bad lvalue' if not l.kind_of? ModRM and not @state.bound.index(l)
			instr 'fld', l if expr.type.float?
			r = c_cexpr_inner(expr.rexpr)
			op = expr.op.to_s.chop.to_sym
			c_cexpr_inner_arith(l, op, expr.rexpr, expr.type)
			instr 'fstp', l if expr.type.float?
			l
		when :'+', :'-', :'*', :'/', :'%', :'^', :'&', :'|', :'<<', :'>>'
			# both sides are already cast to the same type by the precompiler
			l = c_cexpr_inner(expr.lexpr)
			l = make_volatile(l, expr.type)
			r = c_cexpr_inner(expr.rexpr)
			c_cexpr_inner_arith(l, expr.op, r, expr.type)
			l
		when :'='
			l = c_cexpr_inner(expr.lexpr)
			r = c_cexpr_inner(expr.rexpr)
			raise 'bad lvalue ' + l.inspect if not l.kind_of? ModRM and not @state.bound.index(l)
			r = make_volatile(r, expr.type) if l.kind_of? ModRM and r.kind_of? ModRM
			unuse r
			if expr.type.integral?
				if expr.type.name == :__int64 and @cpusz != 64
					ll, lh = get_composite_parts l
					rl, rh = get_composite_parts r
					instr 'mov', ll, rl
					instr 'mov', lh, rh
				else
					instr 'mov', l, r
				end
			elsif expr.type.float?
				instr 'fstp', l
			end
		when :>, :<, :>=, :<=, :==, :'!='
			l = c_cexpr_inner(expr.lexpr)
			l = make_volatile(l, expr.type)
			r = c_cexpr_inner(expr.rexpr)
			unuse r
			if expr.lexpr.type.integral?
				if expr.lexpr.type.name == :__int64 and @cpusz != 64
					raise # TODO
				end
				instr 'cmp', l, r
			elsif expr.lexpr.type.float?
				raise # TODO
				instr 'fucompp', l, r
				l = findreg
			else raise 'bad comparison ' + expr.to_s
			end
			opcc = getcc(expr.op, expr.type)
			if @exeformat.cpu.opcode_list_byname['set'+opcc]
				instr 'set'+opcc, l
			else
				instr 'mov', l, Expression[1]
				label = new_label('setcc')
				instr 'j'+opcc, Expression[label]
				instr 'mov', l, Expression[0]
				@source << Label.new(label)
			end
		else
			raise 'unhandled cexpr ' + expr.to_s
		end
	end

	# compiles a subroutine call
	def c_cexpr_inner_funcall(expr)
		# TODO __fastcall
		expr.rexpr.reverse_each { |arg|
			a = c_cexpr_inner(arg)
			unuse a
			case arg.type
			when C::BaseType
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
		@state.cache.clear
		expr.lexpr.type.float? ? FpReg.new(nil) : Reg.new(0, @cpusz)
	end

	# compiles/optimizes arithmetic operations
	def c_cexpr_inner_arith(l, op, r, type)
		# optimize *2 -> <<1
		if r.kind_of? Expression and (rr = r.reduce).kind_of? ::Integer
			if type.integral?
				log2 = proc { |v|
					# TODO lol
					i = 0
					i += 1 while (1 << i) < v
					i if (1 << i) == v
				}
				if (lr = log2[rr]).kind_of? ::Integer
					case op
					when :*: return c_cexpr_inner_arith(l, :<<, Expression[lr], type)
					when :/: return c_cexpr_inner_arith(l, :>>, Expression[lr], type)
					when :%: return c_cexpr_inner_arith(l, :&, Expression[rr-1], type)
					end
				else
					# TODO :/ => *(r^(-1)), *3..
				end
			elsif type.float?
				case op
				when :<<: return c_cexpr_inner_arith(l, :*, Expression[1<<rr], type)
				when :>>: return c_cexpr_inner_arith(l, :/, Expression[1<<rr], type)
				end
			end
		end

		if type.float?
			c_cexpr_inner_arith_float(l, op, r, type)
		elsif type.integral? and type.name == :__int64 and @cpusz != 64
			c_cexpr_inner_arith_int64compose(l, op, r, type)
		else
			c_cexpr_inner_arith_int(l, op, r, type)
		end
	end

	# compiles a float arithmetic expression
	def c_cexpr_inner_arith_float(l, op, r, type)
		op = case op
		when :+: 'fadd'
		when :-: 'fsub'
		when :*: 'fmul'
		when :/: 'fdiv'
		else raise "unsupported FPU operation #{l} #{op} #{r}"
		end

		case r
		when FpReg: instr op+'p', FpReg.new(1)
		when ModRM: instr op, r
		end
	end

	# compile an integral arithmetic expression, reg-sized
	def c_cexpr_inner_arith_int(l, op, r, type)
		op = case op
		when :+: 'add'
		when :-: 'sub'
		when :&: 'and'
		when :|: 'or'
		when :^: 'xor'
		when :>>: type.specifier == :unsigned ? 'shr' : 'sar'
		when :<<: 'shl'
		# pseudo ops
		when :*: 'mul'
		when :/: 'div'
		when :%: 'mod'
		end

		case op
		when 'add', 'sub', 'and', 'or', 'xor'
			instr op, l, r
		when 'shr', 'sar', 'shl'
			if r.kind_of? Expression
				instr op, l, r
			else
				raise # TODO cl
			end
		when 'mul'
			raise # TODO
		when 'div'
			raise # TODO
		when 'mod'
			raise # TODO
		end
	end

	# compile an integral arithmetic 64-bits expression on a non-64 cpu
	def c_cexpr_inner_arith_int64compose(l, op, r)
		op = case op
		when :+: 'add'
		when :-: 'sub'
		when :&: 'and'
		when :|: 'or'
		when :^: 'xor'
		when :>>: type.specifier == :unsigned ? 'shr' : 'sar'
		when :<<: 'shl'
		# pseudo ops
		when :*: 'mul'
		when :/: 'div'
		when :%: 'mod'
		end

		ll, lh = get_composite_parts l
		rl, rh = get_composite_parts r

		case op
		when 'add', 'sub', 'and', 'or', 'xor'
			instr op, ll, rl
			op = {'add' => 'adc', 'sub' => 'sbb'}[op] || op
			instr op, lh, rh
		when 'shr', 'sar'
			raise # TODO
			instr 'shrd'
		when 'shl'
			raise # TODO
			instr 'shld'
		when 'mul'
			# high = (low1*high2) + (high1*low2) + (low1*low2).high
			t1 = findreg(32)
			t2 = findreg(32)
			unuse t1, t2
			instr 'mov',  t1, ll
			instr 'mov',  t2, rl
			instr 'imul', t1, rh
			instr 'imul', t2, lh
			instr 'add',  t1, t2

			raise # TODO push eax/edx, mul, pop
			instr 'mov',  eax, ll
			if rl.kind_of? Expression
				instr 'mov', t2, rl
				instr 'mul', t2
			else
				instr 'mul',  rl
			end
			instr 'add', t1, edx
			instr 'mov', lh, t1
			instr 'mov', ll, eax

		when 'div'
			raise # TODO
		when 'mod'
			raise # TODO
		end
	end

	def c_cexpr(expr)
		case expr.op
		when :+, :-, :*, :/, :&, :|, :^, :%, :[], nil, :'.', :'->',
			:>, :<, :<=, :>=, :==, :'!=', :'!'
			# skip no-ops
			c_cexpr(expr.lexpr) if expr.lexpr.kind_of? C::CExpression
			c_cexpr(expr.rexpr) if expr.rexpr.kind_of? C::CExpression
		when :funcall
			ret = c_cexpr_inner(expr)
			unuse ret
			ret
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
			l = c_cexpr_inner(expr.lexpr)
			r = c_cexpr_inner(expr.rexpr)
			r = make_volatile(r, expr.type) if r.kind_of? ModRM and l.kind_of? ModRM
			unuse l, r
			if expr.lexpr.type.integral?
				if expr.lexpr.type.name == :__int64 and @cpusz != 64
					raise # TODO
				end
				instr 'cmp', l, r
			elsif expr.lexpr.type.float?
				raise # TODO
				instr 'fcmpp', l, r
			else raise 'bad comparison ' + expr.to_s
			end
			op = 'j' + getcc(expr.op, expr.lexpr.type)
			instr op, Expression[target]
		else
			r = c_cexpr_inner(expr.rexpr)
			unuse r
			instr 'test', r, Expression[-1]
			jop = ((expr.op == :'!') ? 'jz' : 'jnz')
			instr jop, Expression[target]
		end
	end

	def c_goto(target)
		instr 'jmp', Expression[target]
	end

	def c_label(name)
		@state.cache.clear
		@source << Label.new(name)
	end

	def c_return(expr)
		return if not expr
		r = c_cexpr_inner(expr)
		r = make_volatile(r, expr.type)
		unuse r
		instr 'mov', Reg.new(0, r.sz), r if r.val != 0
	end

	def c_asm(stmt)
		raise # TODO parse, handle %%0 -> clobber etc
	end

	def c_init_state(func)
		@state = State.new(func)
		argoff = 0
		al = typesize[:ptr]
		func.type.args.each { |a|
			@state.offsets[a] = -argoff
			argoff = (argoff + sizeof(a) + al - 1) / al * al
		}
		c_reserve_stack(func.initializer)
		if not @state.offset.values.grep(::Integer).empty?
			@state.saved_ebp = Reg.new(5, @cpusz)
		end
	end

	def c_prolog
		localspc = @state.offset.values.grep(::Integer).max
		if localspc
			al = typesize[:ptr]
			localspc = (localspc + al - 1) / al * al
			ebp = @state.saved_ebp
			@state.used << 5
			esp = Reg.new(4, ebp.sz)
			instr 'push', ebp
			instr 'mov', ebp, esp
			instr 'sub', esp, Expression[localspc] if localspc > 0
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
		argsz = f.type.args.inject(0) { |sum, a| sum += (sizeof(a) + al - 1) / al * al }
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

	def new_ccompiler(parser, exe=ExeFormat.new)
		exe.cpu ||= self
		CCompiler.new(parser, exe)
	end
end
end
