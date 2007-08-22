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
			scope.statements << self
			return if not @belse and @bthen.kind_of? Goto

			if @test.kind_of? CExpression and not @test.lexpr and @test.op == :'!' and @test.rexpr.kind_of? CExpression
				@test = @test.rexpr
			else
				@test = CExpression.new(nil, :'!', @test, BaseType.new(:int))
			end
			@test = @test.precompile_inner(parser, scope)

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
			@test = @test.precompile_inner(parser, scope)

			@body = @body.precompile_make_block scope
			@body.break_label = parser.new_label('switch_break')
			@body.precompile(parser)

			scope.statements << self
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
			@value = @value.precompile_inner(parser, scope) if value
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
		# same as Label
	end

	class Goto
		def precompile(parser, scope)
			scope.statements << self
		end
	end

	class Asm
		def precompile(parser, scope)
			scope.statements << self
			# TODO simplify clobber types
		end
	end

	class CExpression
		def precompile(parser, scope)
			scope.statements << precompile_inner(parser, scope)
		end

		# returns a new CExpression with simplified self.type, computes structure offsets
		def precompile_inner(parser, scope)
			case @op
			when :'.'
				# TODO ensure we get an lvalue
				@lexpr = CExpression.new(nil, :'&', @lexpr, Pointer.new(@lexpr.type))
				@op = :'->'
				precompile_inner(parser, scope)
			when :'->'
				case s = @lexpr.type.untypedef.type.untypedef
				when Struct
					@op = :'*'
					@lexpr = @lexpr.precompile_inner(parser, scope)	if @lexpr.kind_of? CExpression	# turn pointer to integer
					@rexpr = CExpression.new(@lexpr, :'+', s.offsetof(parser, @rexpr), BaseType.new(:int)).precompile_inner(parser, scope)
					@lexpr = nil
					self
				when Union
					@op = :'*'
					@rexpr = @lexpr
					@lexpr = nil
					precompile_inner(parser, scope)
				else raise self.dump(scope)
				end
			when :'[]'
				@op = :'*'
				@rexpr = CExpression.new(@lexpr, :'+', @rexpr, Pointer.new(@type))
				@lexpr = nil
				precompile_inner(parser, scope)
			when :'?:'
				raise
			when :funcall
				@lexpr = @lexpr.precompile_inner(parser, scope) if @lexpr.kind_of? CExpression
				@rexpr.map! { |a| a.kind_of?(CExpression) ? a.precompile_inner(parser, scope) : a }
				self
			else
				# handle pointer + 2 == ((char *)pointer) + 2*sizeof(*pointer)
				if (@op == :'+' or @op == :'+=') and @lexpr.type.pointer?
					pt = CExpression.new(nil, :*, @lexpr, @lexpr.type.untypedef.type)
					@rexpr = CExpression.new(@rexpr, :*, parser.sizeof(pt), BaseType.new(:int))
				end

				# TODO precompile Variable#type ?
				@lexpr = @lexpr.precompile_inner(parser, scope) if @lexpr.kind_of? CExpression
				@rexpr = @rexpr.precompile_inner(parser, scope) if @rexpr.kind_of? CExpression
				case t = @type.untypedef
				when BaseType
					@type = BaseType.new("__int#{parser.typesize[t.name]*8}".to_sym, t.specifier)
				when Pointer
					@type = BaseType.new("__int#{parser.typesize[:ptr]*8}".to_sym, :unsigned)
				else raise "bad type for reduce #{dump(scope)} #{@type.inspect}"
				end
				self
			end
		end
	end
end
end
