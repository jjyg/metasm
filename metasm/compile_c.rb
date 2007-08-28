#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'
require 'metasm/parse_c'

module Metasm
class CParser
	attr_accessor :exeformat
	attr_accessor :auto_label_list
	def new_label(base='')
		lbl = @exeformat.new_label base
		(@auto_label_list ||= {})[lbl] = true
		lbl
	end

	# simplifies self.toplevel (destructively)
	# remove typedefs
	# remove structs/arrays from expressions (kept only in declarations)
	# types are turned into __int8/__int16/__int32/__int64 (signed or unsigned)
	# simplifies While/For/Break into If/goto
	# If: else are removed, then are turned in goto
	# label statements are removed
	# returns are kept, but are followed by a jump to the end of the function
	# uses an ExeFormat to build unique label names
	# only toplevel symbols are initialized (static symbols are turned into anonymised toplevel one)
	# after that, we are no longer valid C (typewise, + moved blocks outside of their enclosing scope)
	def precompile(exe = ExeFormat.new)
		@exeformat = exe
		@toplevel.precompile(self)
		self
	end

	class Statement
		# all Statements/Declaration must define a precompile(parser, scope) method
		# it must append itself to scope.statements

		# turns a statement into a new block
		def precompile_make_block(scope)
			b = Block.new scope
			b.statements << self
			b
		end
	end
	
	class Block
		# precompile all statements, then simplifies symbols/structs types
		def precompile(parser, scope=nil)
			stmts = @statements.dup
			@statements.clear
			stmts.each { |st| st.precompile(parser, self) }

			# cleanup declarations
			@symbol.delete_if { |n, s| not s.kind_of? Variable }
			@struct.delete_if { |n, s| not s.kind_of? Union }
			@symbol.each_value { |var|
				CExpression.precompile_type(parser, self, var, true)
			}
			@struct.each_value { |var|
				next if not var.members
				var.members.each { |m|
					CExpression.precompile_type(parser, self, m, true)
				}
			}
			scope.statements << self if scope

			# TODO precompile return struct
		end

		# removes unused labels, and in-place goto (goto toto; toto:)
		def precompile_optimize
			precompile_optimize_inner(precompile_optimize_inner([], 1), 2)
		end

		# step 1: list used labels
		# step 2: remove unused labels
		def precompile_optimize_inner(list, step)
			# XXX goto 3; goto 2; goto 1; 1: 3: 2: x;
			lastgoto = nil
			@statements.dup.each { |s|
				lastgoto = nil if not s.kind_of? Label
				case s
				when Block: s.precompile_optimize(list, step)
				when Switch: s.statement.precompile_optimise(list, step)
				when Case
				when CExpression:	# gcc's unary && support
				when Label
					case step
					when 1: list.delete s.name if lastgoto == s.name
					when 2: @statements.delete s if not list.include? s.name
					end
				when Goto
					case step
					when 1: list << s.target ; lastgoto = s.target
					when 2: @statements.delete s if not list.include? s.target
					end
				end
			}
			list
		end

		# noop
		def precompile_make_block(scope) self end

		def continue_label ; defined?(@continue_label) ? @continue_label : @outer.continue_label end
		def continue_label=(l) @continue_label = l end
		def break_label ; defined?(@break_label) ? @break_label : @outer.break_label end
		def break_label=(l) @break_label = l end
		def return_label ; defined?(@return_label) ? @return_label : @outer.return_label end
		def return_label=(l) @return_label = l end
		def nonauto_label=(l) @nonauto_label = l end
		def nonauto_label ; defined?(@nonauto_label) ? @nonauto_label : @outer.nonauto_label end
	end

	class Declaration
		def precompile(parser, scope)
			if (@var.type.kind_of? Function and @var.initializer and scope != parser.toplevel) or @var.storage == :static
				scope.symbol.delete @var.name
				@var.name = parser.new_label @var.name
				parser.toplevel.symbol[@var.name] = @var
				parser.toplevel.statements << self
			else
				scope.statements << self
			end

			if i = @var.initializer
				if @var.type.kind_of? Function
					i.return_label = parser.new_label('epilog')
					i.nonauto_label = {}
					i.precompile(parser)
					i.statements << Label.new(i.return_label)
					i.precompile_optimize

				elsif scope != parser.toplevel
					precompile_dyn_initializer(parser, scope, @var, @var.type, i)
					@var.initializer = nil
				end

			end
		end

		def precompile_dyn_initializer(parser, scope, var, type, init)
			case type = type.untypedef
			when Array
				# XXX TODO type.length may be dynamic !!
				case init
				when CExpression
					# char toto[] = "42"
					if not init.kind_of? CExpression or init.op or init.lexpr or not init.rexpr.kind_of? ::String
						raise "unknown initializer #{init.inspect} for #{var.inspect}"
					end
					init = init.rexpr.unpack('C*') + [0]
					init.map! { |chr| CExpression.new(nil, nil, chr, type.type) }
					precompile_dyn_initializer(parser, scope, var, type, init)

				when ::Array
					type.length ||= init.length
					# len is an Integer
					init.each_with_index { |it, idx|
						next if not it
						break if idx >= type.length
						idx = CExpression.new(nil, nil, idx, BaseType.new(:long, :unsigned))
						v = CExpression.new(var, :'[]', idx, type.type)
						precompile_dyn_initializer(parser, scope, v, type.type, it)
					}
				else raise "unknown initializer #{init.inspect} for #{var.inspect}"
				end
			when Union
				case init
				when CExpression, Variable
					if init.type.untypedef.kind_of? BaseType
						# works for struct foo bar[] = {0}; ...
						type.members.each { |m|
							v = CExpression.new(var, :'.', m.name, m.type)
							precompile_dyn_initializer(parser, scope, v, v.type, init)
						}
					elsif init.type.untypedef.kind_of? type.class
						CExpression.new(var, :'=', init, type).precompile(parser, scope)
					else
						raise "bad initializer #{init.inspect} for #{var.inspect}"
					end
				when ::Array
					init.each_with_index{ |it, idx|
						next if not it
					}
				else raise "unknown initializer #{init.inspect} for #{var.inspect}"
				end
			else
				case init
				when CExpression
					CExpression.new(var, :'=', init, type).precompile(parser, scope)
				else raise "unknown initializer #{init.inspect} for #{var.inspect}"
				end
			end
		end
	end

	class If
		def precompile(parser, scope)
			if belse or not @bthen.kind_of? Goto
				if @test.kind_of? CExpression and not @test.lexpr and @test.op == :'!' and @test.rexpr.kind_of? CExpression
					@test = @test.rexpr
				else
					@test = CExpression.new(nil, :'!', @test, BaseType.new(:int))
				end
				inverted = true
			end
			@test = CExpression.precompile_inner(parser, scope, @test)

			if @test.kind_of? CExpression and not @test.lexpr and not @test.op and @test.rexpr.kind_of? Numeric
				if (inverted and @test.rexpr == 0) or (not inverted and @test.rexpr != 0)
					@bthen.precompile(parser, scope)
					return
				else
					@belse.precompile(parser, scope) if belse
					return
				end
			end

			scope.statements << self	# @test might have a coma, we must precompile it before appending ourself

			if belse
				ifelse = parser.new_label('if_else')
				ifend = parser.new_label('if_end')
				@bthen.precompile(parser, scope)
				@bthen = Goto.new(ifelse)
				scope.statements << Goto.new(ifend)
				scope.statements << Label.new(ifelse)
				@belse.precompile(parser, scope)
				@belse = nil
				scope.statements << Label.new(ifend)
			else
				ifend = parser.new_label('if_end')
				@bthen.precompile(parser, scope)
				@bthen = Goto.new(ifend)
				scope.statements << Label.new(ifend)
			end
		end
	end

	class For
		def precompile(parser, scope)
			if init
				if @init.kind_of? Block
					@init.precompile(parser)
					scope.statements << @init
					scope = @init
				else
					@init.precompile(parser, scope)
				end
			end

			@body = @body.precompile_make_block scope
			@body.continue_label = parser.new_label 'for_continue'
			@body.break_label = parser.new_label 'for_break'

			scope.statements << Label.new(@body.continue_label)

			if test
				nottest = CExpression.new(nil, :'!', @test, BaseType.new(:int))
				If.new(nottest, Goto.new(@body.break_label)).precompile(parser, scope)
			end

			@body.precompile(parser, scope)

			if iter
				@iter.precompile(parser, scope)
			end

			scope.statements << Goto.new(@body.continue_label)
			scope.statements << Label.new(@body.break_label)
		end
	end

	class While
		def precompile(parser, scope)
			@body = @body.precompile_make_block scope
			@body.continue_label = parser.new_label('while_continue')
			@body.break_label = parser.new_label('while_break')

			scope.statements << Label.new(@body.continue_label)

			nottest = CExpression.new(nil, :'!', @test, BaseType.new(:int))
			If.new(nottest, Goto.new(@body.break_label)).precompile(parser, scope)

			@body.precompile(parser, scope)

			scope.statements << Goto.new(@body.continue_label)
			scope.statements << Label.new(@body.break_label)
		end
	end

	class DoWhile
		def precompile(parser, scope)
			@body = @body.precompile_make_block scope
			@body.continue_label = parser.new_label('dowhile_continue')
			@body.break_label = parser.new_label('dowhile_break')
			loop_start = parser.new_label('dowhile_start')

			scope.statements << Label.new(loop_start)

			@body.precompile(parser, scope)

			scope.statements << Label.new(@body.continue_label)

			If.new(@test, Goto.new(loop_start)).precompile(parser, scope)

			scope.statements << Label.new(@body.break_label)
		end
	end

	class Switch
		def precompile(parser, scope)
			@test = CExpression.precompile_inner(parser, scope, @test)

			scope.statements << self

			@body = @body.precompile_make_block scope
			@body.break_label = parser.new_label('switch_break')
			@body.precompile(parser)

			scope.statements << Label.new(@body.break_label)
		end
	end

	class Continue
		def precompile(parser, scope)
			scope.statements << Goto.new(scope.continue_label)
		end
	end

	class Break
		def precompile(parser, scope)
			scope.statements << Goto.new(scope.break_label)
		end
	end

	class Return
		def precompile(parser, scope)
			@value = CExpression.precompile_inner(parser, scope, @value)
			scope.statements << self
			scope.statements << Goto.new(scope.return_label)
		end
	end

	class Label
		def precompile(parser, scope)
			if not parser.auto_label_list or not parser.auto_label_list[@name]
				@name = scope.nonauto_label[@name] ||= parser.new_label(@name)
			end
			scope.statements << self
			if statement 
				@statement.precompile(parser, scope)
				@statement = nil
			end
		end
	end

	class Case
		def precompile(parser, scope)
			@expr = CExpression.precompile_inner(parser, scope, @expr)
			@exprup = CExpression.precompile_inner(parser, scope, @exprup) if exprup
			super
		end
	end

	class Goto
		def precompile(parser, scope)
			if not parser.auto_label_list or not parser.auto_label_list[@target]
				@target = scope.nonauto_label[@target] ||= parser.new_label(@target)
			end
			scope.statements << self
		end
	end

	class Asm
		def precompile(parser, scope)
			scope.statements << self
			# TODO CExpr.precompile_type(clobbers)
		end
	end

	class CExpression
		def self.precompile_inner(parser, scope, expr)
			case expr
			when CExpression: expr.precompile_inner(parser, scope)
			else expr
			end
		end

		def precompile(parser, scope)
			scope.statements << precompile_inner(parser, scope)
		end

		# changes obj.type to a precompiled type
		# keeps struct/union, change everything else to __int* 
		# except Arrays if keep_arrays is true (need to know variable allocation sizes etc)
		# returns the type
		def self.precompile_type(parser, scope, obj, declaration = false)
			case t = obj.type.untypedef
			when BaseType
				case t.name
				when :void
				when :float, :double, :longdouble
				else t = BaseType.new("__int#{parser.typesize[t.name]*8}".to_sym, t.specifier)
				end
			when Array
				if declaration: precompile_type(parser, scope, t, declaration)
				else   t = BaseType.new("__int#{parser.typesize[:ptr]*8}".to_sym, :unsigned)
				end
			when Pointer:  t = BaseType.new("__int#{parser.typesize[:ptr]*8}".to_sym, :unsigned)
			when Enum:     t = BaseType.new("__int#{parser.typesize[:int]*8}".to_sym)
			when Function
				precompile_type(parser, scope, t)
				t.args.each { |a| precompile_type(parser, scope, a) }
			when Union
				if declaration and t.members and not t.name	# anonymous struct
					t.members.each { |a| precompile_type(parser, scope, a, true) }
				end
			else raise 'bad type ' + t.inspect
			end
			loop do
				(t.qualifier ||= []).concat obj.type.qualifier if obj.type.qualifier and t != obj.type
				if obj.type.kind_of? TypeDef: obj.type = obj.type.type
				else break
				end
			end
			obj.type = t
		end

		# returns a new CExpression with simplified self.type, computes structure offsets
		# turns char[]/float immediates to reference to anonymised const
		# TODO anonymise legit Goto/Label
		def precompile_inner(parser, scope)
			case @op
			when :'.'
				lexpr = CExpression.precompile_inner(parser, scope, @lexpr)
				if lexpr.kind_of? CExpression and lexpr.op == :'*' and not lexpr.lexpr
					@lexpr = lexpr.rexpr
					@lexpr.type = Pointer.new(lexpr.type)
				else
					@lexpr = CExpression.new(nil, :'&', lexpr, Pointer.new(lexpr.type))
				end
				@op = :'->'
				precompile_inner(parser, scope)
			when :'->'
				struct = @lexpr.type.untypedef.type.untypedef
				lexpr = CExpression.precompile_inner(parser, scope, @lexpr)
				if struct.kind_of? Struct and (off = struct.offsetof(parser, @rexpr)) != 0
					@rexpr = CExpression.new(lexpr, :'+', off, lexpr.type)
				else
					@rexpr = lexpr
					if @rexpr.kind_of? CExpression and @rexpr.op == :'&' and not @rexpr.lexpr
						if @rexpr.rexpr.kind_of? CExpression: (e = @rexpr.rexpr).type = @type
						else e = CExpression.new(nil, nil, @rexpr.rexpr, @type)
						end
						return e.precompile_inner(parser, scope)
					end
				end
				@op = :'*'
				@lexpr = nil
				precompile_inner(parser, scope)
			when :'[]'
				@rexpr = CExpression.new(@lexpr, :'+', @rexpr, @lexpr.type)
				@op = :'*'
				@lexpr = nil
				precompile_inner(parser, scope)
			when :'?:'
				# cannot precompile in place, a conditionnal expression may have a coma: must turn into If
				raise 'conditional in toplevel' if scope == parser.toplevel	# just in case
				var = Variable.new
				var.name = parser.new_label('ternary')
				var.type = @rexpr[0].type
				CExpression.precompile_type(parser, scope, var)
				Declaration.new(var).precompile(parser, scope)
				If.new(@lexpr, CExpression.new(var, :'=', @rexpr[0], var.type), CExpression.new(var, :'=', @rexpr[1], var.type)).precompile(parser, scope)
				
				@lexpr = nil
				@op = nil
				@rexpr = var
				precompile_inner(parser, scope)
			when :funcall
				@lexpr = CExpression.precompile_inner(parser, scope, @lexpr)
				@rexpr.map! { |e| CExpression.precompile_inner(parser, scope, e) }
				CExpression.precompile_type(parser, scope, self)
				self
			when :','
				lexpr = @lexpr.kind_of?(CExpression) ? @lexpr : CExpression.new(nil, nil, @lexpr, @lexpr.type)
				rexpr = @rexpr.kind_of?(CExpression) ? @rexpr : CExpression.new(nil, nil, @rexpr, @rexpr.type)
				scope.statements << lexpr.precompile_inner(parser, scope)
				rexpr.precompile_inner(parser, scope)
			when :'='
				# handle structure assignment/array assignment
				case @lexpr.type.untypedef
				when Union
					@lexpr.type.untypedef.members.zip(@rexpr.type.untypedef.members) { |m1, m2|
						# assume m1 and m2 are compatible
						v1 = CExpression.new(@lexpr, :'.', m1.name, m1.type)
						v2 = CExpression.new(@rexpr, :'.', m2.name, m1.type)
						scope.statements << CExpression.new(v1, :'=', v2, v1.type).precompile_inner(parser, scope)
					}
					# struct may have no members...
					@op = nil
					@lexpr = nil
					@rexpr = CExpression.new(nil, nil, 0, BaseType.new(:int))
					@type = BaseType.new(:void)
					precompile_inner(parser, scope)
				when Array
					if not len = @lexpr.type.untypedef.length
						@rexpr = CExpression.precompile_inner(parser, scope, @rexpr)
						# char toto[] = "bla"
						if @rexpr.kind_of? CExpression and not @rexpr.lexpr and not @rexpr.op and
								@rexpr.rexpr.kind_of? Variable and @rexpr.rexpr.type.kind_of? Array
							len = @rexpr.rexpr.type.length
						end
					end
					raise 'array initializer with no length !' if not len
					# TODO optimize...
					len.times { |i|
						i = CExpression.new(nil, nil, i, BaseType.new(:long, :unsigned))
						v1 = CExpression.new(@lexpr, :'[]', i, @lexpr.type.untypedef.type)
						v2 = CExpression.new(@rexpr, :'[]', i, v1.type)
						scope.statements << CExpression.new(v1, :'=', v2, v1.type).precompile_inner(parser, scope)
					}
					@op = nil
					@lexpr = nil
					@rexpr = CExpression.new(nil, nil, 0, BaseType.new(:int))
					@type = BaseType.new(:void)
					precompile_inner(parser, scope)
				else
					@lexpr = CExpression.precompile_inner(parser, scope, @lexpr)
					@rexpr = CExpression.precompile_inner(parser, scope, @rexpr)
					CExpression.precompile_type(parser, scope, self)
					self
				end
			else
				# handle compound statements
				if not @lexpr and not @op and @rexpr.kind_of? Block
					raise 'compound statement in toplevel' if scope == parser.toplevel	# just in case
					var = Variable.new
					var.name = parser.new_label('compoundstatement')
					var.type = @type
					CExpression.precompile_type(parser, scope, var)
					Declaration.new(var).precompile(parser, scope)
					if @rexpr.statements.last.kind_of? CExpression
						@rexpr.statements[-1] = CExpression.new(var, :'=', @rexpr.statements[-1], var.type)
						@rexpr.precompile(parser, scope)
					end
					@rexpr = var
				end

				# handle pointer + 2 == ((char *)pointer) + 2*sizeof(*pointer)
				if		@lexpr and (@lexpr.kind_of? CExpression or @lexpr.kind_of? Variable) and
						@rexpr and (@rexpr.kind_of? CExpression or @rexpr.kind_of? Variable) and
						[:'+', :'+=', :'-', :'-='].include? @op and
						@lexpr.type.pointer? and @rexpr.type.integral?
					#sz = parser.sizeof(CExpression.new(nil, :'*', @lexpr, @lexpr.type.untypedef.type.untypedef))
					sz = parser.sizeof(nil, @lexpr.type.untypedef.type.untypedef)
					@rexpr = CExpression.new(@rexpr, :'*', sz, @rexpr.type) if sz != 1
				end

				@lexpr = CExpression.precompile_inner(parser, scope, @lexpr)
				@rexpr = CExpression.precompile_inner(parser, scope, @rexpr)

				if @op == :'&' and not @lexpr and @rexpr.kind_of? CExpression and @rexpr.op == :'*' and not @rexpr.lexpr
					if @rexpr.rexpr.kind_of? CExpression: (e = @rexpr.rexpr).type = @type
					else e = CExpression.new(nil, nil, @rexpr.rexpr, @type)
					end
					return e.precompile_inner(parser, scope)
				end

				# handle char[] immediates and float
				if not @lexpr and not @op and scope != parser.toplevel
					case @rexpr
					when ::String
						v = Variable.new
						v.name = parser.new_label('string')
						v.type = Array.new(@type.type)
						v.type.length = @rexpr.length + 1
						v.type.type.qualifier = [:const]
						v.initializer = CExpression.new(nil, nil, @rexpr, @type)
						parser.toplevel.symbol[v.name] = v
						parser.toplevel.statements << Declaration.new(v)
						@rexpr = v
					when ::Float
						v = Variable.new
						v.name = parser.new_label(@type.untypedef.name.to_s)
						v.type = @type
						v.type.qualifier = [:const]
						v.initializer = CExpression.new(nil, nil, @rexpr, @type)
						parser.toplevel.symbol[v.name] = v
						parser.toplevel.statements << Declaration.new(v)
						@rexpr = v
					end
				end

				CExpression.precompile_type(parser, scope, self)

				# calc numeric
				if @rexpr.kind_of? CExpression and not @rexpr.lexpr and not @rexpr.op and @rexpr.rexpr.kind_of? Numeric and
					(not @lexpr or (@lexpr.kind_of? CExpression and not @lexpr.lexpr and not @lexpr.op and @lexpr.rexpr.kind_of? Numeric))
					if (val = reduce(parser)).kind_of? Numeric
						@lexpr = nil
						@op = nil
						@rexpr = val
					end
				end

				self
			end
		end
	end
	class BaseType ;def wantalign(cp) [cp.typesize[@name], 8].min end end
	class Array    ;def wantalign(cp) @type.wantalign(cp) end end
	class Struct   ;def wantalign(cp) @align end end
	class Union    ;def wantalign(cp) @members.map { |m| m.type.wantalign(cp) }.max end end
end

class CPU
	# turns a precompiled CParser into an assembler source string
	def compile_c(exe, cp)
		src = []

		# reorder statements (arrays of Variables)
		funcs, rwdata, rodata, udata = [], [], [], []
		cp.toplevel.statements.each { |st|
			v = st.var
			if v.type.kind_of? CParser::Function: funcs << v if v.initializer	# no initializer == storage :extern
			elsif v.storage == :extern
			elsif v.initializer and not v.type.qualifier.to_a.include?(:const):  rwdata << v
			elsif v.initializer: rodata << v
			else udata << v
			end
		}

		exe.compile_setsection src, '.text' if not funcs.empty?
		funcs.each { |func| compile_c_function(exe, cp, src, func) }

		align = 1
		exe.compile_setsection src, '.data' if not rwdata.empty?
		rwdata.each { |data| align = compile_c_idata(exe, cp, src, data, align) }

		exe.compile_setsection src, '.rodata' if not rodata.empty?
		rodata.each { |data| align = compile_c_idata(exe, cp, src, data, align) }

		exe.compile_setsection src, '.bss' if not udata.empty?
		udata.each  { |data| align = compile_c_udata(exe, cp, src, data, align) }

		src.join("\n")
	end

	# compiles a C function +func+ to asm source into the array of strings +str+
	def compile_c_function(exe, cp, src, func)
		src << ''
		src << "#{func.name}:"

		# must wait the Declaration to run the CExpr for dynamic auto offsets,
		# and must run those statements once only
		# XXX alloc a stack variable to maintain the auto offset of every dynarray ?
		auto_offsets = compile_c_reservestack(cp, func.initializer)

		# state caches register values, includes auto_offsets
		tmpsrc = []
		state = compile_c_pre_prolog(exe, cp, tmpsrc, func, auto_offsets)

		func.initializer.statements.each { |stmt|
			case stmt
			when CParser::CExpression
				compile_c_cexpr(exe, cp, tmpsrc, state, stmt)
			when CParser::Declaration
				compile_c_decl(exe, cp, tmpsrc, state, stmt.var)
			when CParser::If
				compile_c_ifgoto(exe, cp, tmpsrc, state, stmt.test, stmt.bthen.target)
			when CParser::Switch
				# removes Cases
				compile_c_switch(exe, cp, tmpsrc, state, stmt)
			when CParser::Goto
				compile_c_goto(exe, cp, tmpsrc, state, stmt.target)
			when CParser::Label
				tmpsrc << "#{stmt.name}:"
			when CParser::Return
				compile_c_return(exe, cp, tmpsrc, state, stmt.value) if stmt.value
			when CParser::Asm
				compile_c_asm(exe, cp, tmpsrc, state, stmt)
			end
		}

		compile_c_prolog(exe, cp, src, func, state)
		src.concat tmpsrc
		compile_c_epilog(exe, cp, src, func, state)
	end

	# creates a hash automatic variable => stack offset for a precompiled block (recursive)
	# offset is an ::Integer or a CParser::CExpression (dynamic array), offset from a ptr-size-aligned value.
	# TODO nested function
	def compile_c_reservestack(cp, block, off = 0)
		block.statements.inject({}) { |res, stmt|
			case stmt
			when CParser::Declaration
				off = compile_c_reservestack_var(cp, stmt.var, off)
				res[stmt.var] = off
				next res
			when CParser::Block
			when CParser::Switch: stmt = stmt.statement
			else next res
			end
			res.update compile_c_reservestack(cp, stmt, off)
			# do not update off, not nested subblocks can overlap
		}
	end

	# computes the new stack offset for var
	# off is either an offset from stack start (:ptr-size-aligned) or
	# a CExpression [[[expr, +, 7], &, -7], +, off]
	def compile_c_reservestack_var(cp, var, off)
		e = CParser::CExpression
		if (arr_type = var.type.untypedef).kind_of? CParser::Array and (arr_sz = arr_type.length).kind_of? e
			# dynamic array !
			arr_sz = e.new(arr_sz, :*, cp.sizeof(nil, arr_type.type),
				       BaseType.new(:long, :unsigned)).precompile_inner(cp, nil)
			off = e.new(arr_sz, :+, off, arr_sz.type)
			off = e.new(off, :+,  7, off.type)
			off = e.new(off, :&, -7, off.type)
			e.new(off, :+,  0, off.type)
		else
			al = var.type.wantalign(cp)
			sz = cp.sizeof(var)
			case off
			when e: e.new(off.lexpr, :+, ((off.rexpr + sz + al - 1) / al * al), off.type)
			else (off + sz + al - 1) / al * al
			end
		end
	end

	# compiles a C static data definition into an asm string
	# returns the new alignment value
	def compile_c_idata(exe, cp, src, data, align)
		w = data.type.wantalign(cp)
		src << ".align #{align = w}" if w > align

		src << data.name.dup
		len = compile_c_idata_inner(exe, cp, src, data.type, data.initializer)
		len %= w
		len == 0 ? w : len
	end

	# dumps an anonymous variable definition, appending to the last line of src
	# src.last is a label name or is empty before calling here
	# return the length of the data written
	def compile_c_idata_inner(exe, cp, src, type, value)
		value ||= 0
		case type
		when CParser::BaseType
			if type.name == :void
				src.last << ':' if not src.last.empty?
				return 0
			end

			src.last <<
			case type.name
			when :__int8:  ' db '
			when :__int16: ' dw '
			when :__int32: ' dd '
			when :__int64: ' dq '
			when :float:   ' df '	# TODO
			when :double:  ' dfd '
			when :longdouble: ' dfld '
			else raise "unknown idata type #{type.inspect} #{value.inspect}"
			end

			src.last <<
			case value
			when CParser::CExpression: value.rexpr.kind_of?(::Numeric) ? value.rexpr.to_s : value.inspect
			when ::Integer: (value >= 4096) ? ('0x%X' % value) : value.to_s
			when ::Numeric: value.to_s
			else value.inspect
			end

			cp.typesize[type.name]

		when CParser::Struct
			src.last << ':' if not src.last.empty?
			value = [0] * type.members.length if value == 0
			raise "unknown struct initializer #{value.inspect}" if not value.kind_of? ::Array
			sz = 0
			type.members.zip(value).each { |m, v|
				src << ''
				flen = compile_c_idata_inner(exe, cp, src, m.type, v)
				sz += flen
				src << ".align #{type.align}" if flen % type.align != 0
			}

			sz

		when CParser::Union
			src.last << ':' if not src.last.empty?
			len = cp.sizeof(nil, type)
			value = [0] if value == 0
			raise "unknown union initializer #{value.inspect}" if not value.kind_of? ::Array
			idx = value.rindex(value.compact.last)
			raise "empty union initializer" if not idx
			wlen = compile_c_idata_inner(exe, cp, src, type.members[idx].type, value[idx])
			src << "db #{'0' * (len - wlen) * ', '}" if wlen < len

			len

		when CParser::Array
			if value.kind_of? CParser::CExpression and not value.op and value.rexpr.kind_of? ::String
				elen = cp.sizeof(nil, value.type.type)
				src.last << 
				case elen
				when 1: ' db '
				when 2: ' dw '
				else raise 'bad char* type ' + value.inspect
				end << value.rexpr.inspect

				len = type.length || (value.rexpr.length+1)
				if len > value.rexpr.length
					src.last << (', 0' * (len - value.rexpr.length))
				end

				elen * len

			elsif value.kind_of? ::Array
				src.last << ':' if not src.last.empty?
				len = type.length || value.length
				value.each { |v|
					src << ''
					compile_c_idata_inner(exe, cp, src, type.type, v)
				}
				len -= value.length
				if len > 0
					src << " db #{len * cp.sizeof(nil, type.type)} dup(0)"
				end

				cp.sizeof(nil, type.type) * len

			else raise "unknown static array initializer #{value.inspect}"
			end
		end
	end

	def compile_c_udata(exe, cp, src, data, align)
		src << "#{data.name} "
		src.last <<
		case data.type
		when CParser::BaseType
			len = cp.typesize[data.type.name]
			case type.name
			when :__int8:  'db ?'
			when :__int16: 'dw ?'
			when :__int32: 'dd ?'
			when :__int64: 'dq ?'
			else "db #{len} dup(?)"
			end
		else
			len = cp.sizeof(data)
			"db #{len} dup(?)"
		end
		len %= align
		len == 0 ? align : len
	end
end

class ExeFormat
	# add directives to encode different sections (.text .data .rodata .bss)
	def compile_setsection(src, section)
		src << section
	end

	def self.compile_c_to_asm(cpu, source)
		exe = new(cpu)
		cp = CParser.parse(source)
		cp.precompile
		exe.cpu.compile_c(exe, cp)
	end
end
end
