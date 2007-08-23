#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/parse_c'

module Metasm
class CParser
	attr_accessor :exeformat
	def new_label(base='')
		@exeformat.new_label base
	end

	# simplifies self.toplevel (destructively)
	# remove typedefs
	# remove structs/arrays from expressions (kept only in declarations)
	# types are turned into __int8/__int16/__int32/__int64 (signed or unsigned)
	# simplifies While/For/Break into If/goto
	# If: else are removed, then are turned in goto
	# label statements are removed
	# returns are kept
	# uses an ExeFormat to build unique label names
	# only toplevel symbols are initialized (static symbols are turned into anonymised toplevel one)
	# after that, we are no longer valid C (typewise, + moved blocks outside of their enclosing scope)
	def precompile(exe = ExeFormat.new)
		@exeformat = exe
		@toplevel.precompile(self)
		self
	end

	class Statement
		# all Statements/Declaration must define this method
		# it must append itself to scope.statements
		def precompile(parser, scope) raise end

		def precompile_make_block(scope)
			b = Block.new scope
			b.statements << self
			b
		end
	end
	
	class Block
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
		end

		def precompile_make_block(scope)
			self
		end

		def continue_label ; defined?(@continue_label) ? @continue_label : @outer.continue_label end
		def continue_label=(l) @continue_label = l end
		def break_label ; defined?(@break_label) ? @break_label : @outer.break_label end
		def break_label=(l) @break_label = l end
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

			if @var.type.kind_of? Function and @var.initializer
				@var.initializer.precompile(parser)
			elsif @var.initializer.kind_of? CExpression and scope != parser.toplevel
				CExpression.new(@var, :'=', @var.initializer, @var.type).precompile(parser, scope)
				@var.initializer = nil
			end
		end
	end

	class If
		def precompile(parser, scope)
			if not @belse and @bthen.kind_of? Goto
				scope.statements << self
				return
			end

			if @test.kind_of? CExpression and not @test.lexpr and @test.op == :'!' and @test.rexpr.kind_of? CExpression
				@test = @test.rexpr
			else
				@test = CExpression.new(nil, :'!', @test, BaseType.new(:int))
			end
			@test = CExpression.precompile_inner(parser, scope, @test)

			if @test.kind_of? CExpression and not @test.lexpr and not @test.op and @test.rexpr.kind_of? Numeric
				if @test.rexpr == 0
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
		end
	end

	class Label
		def precompile(parser, scope)
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
			obj.type = \
			case t = obj.type.untypedef
			when BaseType: t.name == :void ? t : BaseType.new("__int#{parser.typesize[t.name]*8}".to_sym, t.specifier)
			when Array
				if declaration: precompile_type(parser, scope, t, declaration) ; t
				else   BaseType.new("__int#{parser.typesize[:ptr]*8}".to_sym, :unsigned)
				end
			when Pointer:  BaseType.new("__int#{parser.typesize[:ptr]*8}".to_sym, :unsigned)
			when Enum:     BaseType.new("__int#{parser.typesize[:int]*8}".to_sym)
			when Function
				precompile_type(parser, scope, t)
				t.args.each { |a| precompile_type(parser, scope, a) }
				t
			when Union
				if declaration and t.members and not t.name	# anonymous struct
					t.members.each { |a| precompile_type(parser, scope, a, true) }
				end
				t
			else raise 'bad type ' + t.inspect
			end
		end

		# returns a new CExpression with simplified self.type, computes structure offsets
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
			when :'?:', :funcall
				@lexpr = CExpression.precompile_inner(parser, scope, @lexpr)
				if @op == :'?:' and @lexpr.kind_of? CExpression and not @lexpr.lexpr and not @lexpr.op and @lexpr.rexpr.kind_of? Numeric
					if @lexpr.rexpr != 0
						CExpression.precompile_inner(parser, scope, @rexpr[0])
					else
						CExpression.precompile_inner(parser, scope, @rexpr[1])
					end
				else
					@rexpr.map! { |e| CExpression.precompile_inner(parser, scope, e) }
					CExpression.precompile_type(parser, scope, self)
					self
				end
			when :','
				lexpr = @lexpr.kind_of?(CExpression) ? @lexpr : CExpression.new(nil, nil, @lexpr, @lexpr.type)
				rexpr = @rexpr.kind_of?(CExpression) ? @rexpr : CExpression.new(nil, nil, @rexpr, @rexpr.type)
				scope.statements << lexpr.precompile_inner(parser, scope)
				rexpr.precompile_inner(parser, scope)
			else
				if @op == :'&' and not @lexpr and @rexpr.kind_of? CExpression and @rexpr.op == :'*' and not @rexpr.lexpr
					if @rexpr.rexpr.kind_of? CExpression: (e = @rexpr.rexpr).type = @type
					else e = CExpression.new(nil, nil, @rexpr.rexpr, @type)
					end
					return e.precompile_inner(parser, scope)
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
end
end
