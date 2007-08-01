#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'
require 'metasm/preprocessor'

module Metasm
# c parser
# inspired from http://www.math.grin.edu/~stone/courses/languages/C-syntax.xhtml
class CParser
	class Statement
	end

	class Block < Statement
		attr_accessor :symbol	# hash name => Type/Variable/enum value
		attr_accessor :struct	# hash name => Struct/Union/Enum
		attr_accessor :outer	# parent block
		attr_accessor :statements	# array of statements

		def initialize(outer)
			@symbol, @struct = {}, {}
			@statements = []
			@outer = outer
		end

		def struct_ancestors
			(outer ? outer.struct_ancestors : {}).merge @struct
		end

		def symbol_ancestors
			(outer ? outer.symbol_ancestors : {}).merge @symbol
		end
	end

	module Attributes
		attr_accessor :attributes

		# parses a sequence of __attribute__((anything)) into self.attributes (array of string)
		def parse_attributes(parser)
			while tok = parser.skipspaces and tok.type == :string and tok.raw == '__attribute__'
				raise tok || parser if not tok = parser.skipspaces or tok.type != :punct or tok.type != '('
				raise tok || parser if not tok = parser.skipspaces or tok.type != :punct or tok.type != '('
				nest = 0
				attrib = ''
				loop do
					raise parser if not tok = parser.skipspaces
					if tok.type == :punct and tok.raw == ')'
						if nest == 0
							raise tok || parser if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'
							break
						else
							nest -= 1
						end
					elsif tok.type == :punct and tok.raw == '('
						nest += 1
					end
					attrib << tok.raw
				end
				(@attributes ||= []) << attrib
			end
			parser.unreadtok tok
		end
	end

	class Type
		include Attributes
		attr_accessor :qualifier	# const volatile

		def pointer? ; false ; end
		def arithmetic? ; false ; end

		def parse_initializer(parser, scope)
			raise parser, 'expr expected' if not ret = CExpression.parse(parser, scope, false)
			parser.check_compatible_type(parser, ret.type, self)
			ret
		end
	end
	class BaseType < Type
		attr_accessor :name		# :int :long :longlong :short :double :longdouble :float :char :void
		attr_accessor :specifier	# sign specifier only

		def arithmetic? ; true ; end

		def initialize(name, *specs)
			@name = name
			specs.each { |s|
				case s
				when :const, :volatile: (@qualifier ||= []) << s
				when :signed, :unsigned: @specifier = s
				else raise "internal error, got #{name.inspect} #{specs.inspect}"
				end
			}
		end
	end
	class TypeDef < Type
		attr_accessor :name
		attr_accessor :type
		attr_accessor :backtrace

		def initialize(name, type, backtrace)
			@name, @type, @backtrace = name, type, backtrace
		end

		def pointer? ; @type.pointer? ; end
		def arithmetic? ; @type.arithmetic? ; end
	end
	class Function < Type
		attr_accessor :type		# return type
		attr_accessor :args		# [name, Variable]
		attr_accessor :varargs		# true/false

		def initialize(type=nil)
			@type = type
		end
	end
	class Union < Type
		attr_accessor :members		# [Variable]
		attr_accessor :bits		# name => len
		attr_accessor :name
		attr_accessor :backtrace

		def parse_members(parser, scope)
			@members = []
			# parse struct/union members in definition
			loop do
				raise parser if not tok = parser.skipspaces
				break if tok.type == :punct and tok.raw == '}'
				parser.unreadtok tok
	
				raise parser if not basetype = Variable.parse_type(parser, scope)
				loop do
					member = basetype.dup
					member.parse_declarator(parser, scope)
					# raise parser if not member.name	# can be useful while hacking: struct foo {int; int*; int iwant;};
					raise member.backtrace, 'member redefinition' if member.name and @members.find { |m| m.name == member.name }
					@members << member
	
					raise tok || parser if not tok = parser.skipspaces or tok.type != :punct
	
					if tok.raw == ':'	# bits
						raise tok, 'bad bit count' if not bits = CExpression.parse(parser, scope, false) or not bits.constant? or not bits = bits.reduce
						raise tok, 'bitfield must have a name' if not member.name
						(@bits ||= {})[member.name] = bits
						raise tok || parser, '"," or ";" expected' if not tok = parser.skipspaces or tok.type != :punct
					end
	
					case tok.raw
					when ';': break
					when ','
					else raise tok, '"," or ";" expected'
					end
				end
			end
			parse_attributes(parser)
		end
	end
	class Struct < Union
		attr_accessor :align

		def offsetof(parser, name)
			raise parser, 'undefined structure' if not @members
			raise parser, 'unknown structure member' if not @members.find { |m| m.name == name }
			off = 0
			@members.each { |m|
				break if m.name == name
				raise parser, 'offsetof unhandled with bit members' if @bits and @bits[m.name]	# TODO
				off += parser.sizeof(m)
				off = (off + @align - 1) / @align * @align
			}
			off
		end

		def parse_initializer(parser, scope)
			if tok = parser.skipspaces and tok.type == :punct and tok.raw == '{'
				# struct x toto = { 1, .4, .member = 12 };
				raise tok, 'undefined struct' if not @members
				ret = []
				if tok = parser.skipspaces and (tok.type != :punct or tok.raw != '}')
					parser.unreadtok tok
					idx = -1
					loop do
						nt = nnt = nnnt = nil
						if nt = parser.skipspaces and   nt.type == :punct  and   nt.raw == '.' and
						  nnt = parser.skipspaces and  nnt.type == :string and
						 nnnt = parser.skipspaces and nnnt.type == :punct  and nnnt.raw == '='
							raise nnt, 'invalid member' if not idx = @members.index(@members.find { |m| m.name == nnt.raw })
						else
							parser.unreadtok nnnt
							parser.unreadtok  nnt
							parser.unreadtok   nt
							idx += 1
						end

						ret[idx] = @members[idx].type.parse_initializer(parser, scope)
						raise tok || parser, '"," or "}" expected' if not tok = parser.skipspaces or tok.type != :punct or (tok.raw != '}' and tok.raw != ',')
						break if tok.raw == '}'
					end
				end
				ret
			else
				parser.unreadtok tok
				super
			end
		end

		def parse_members(parser, scope)
			super
			if @attributes and @attributes.include? 'packed'
				@type.align = 1
			end
		end
	end
	class Enum < Type
		# name => value
		attr_accessor :members

		def parse_members(parser, scope)
			val = -1
			@members = {}
			loop do
				raise parser if not tok = parser.skipspaces
				break if tok.type == :punct and tok.raw == '}'
	
				name = tok.raw
				raise tok, 'bad enum name' if tok.type != :string or Reserved[name] or (?0..?9).include?(name[0])
				raise tok, 'enum value redefinition' if scope.symbol[name]
	
				raise parser if not tok = parser.skipspaces
				if tok.type == :punct and tok.raw == '='
					raise tok || parser if not val = CExpression.parse(parser, scope, false) or not val = val.reduce or not tok = parser.skipspaces
				else
					val += 1
				end
				@members[name] = val
				scope.symbol[name] = val
	
				if tok.type == :punct and tok.raw == '}'
					break
				elsif tok.type == :punct and tok.raw == ','
				else raise tok, '"," or "}" expected'
				end
			end
			@type.parse_attributes(parser)
		end

	end
	class Pointer < Type
		attr_accessor :type

		def initialize(type=nil)
			@type = type
		end

		def pointer? ; true ; end
		def arithmetic? ; true ; end
	end
	class Array < Pointer
		attr_accessor :length

		def parse_initializer(parser, scope)
			if tok = parser.skipspaces and tok.type == :punct and tok.raw == '{'
				# int foo[] = { 1, 2, 3 };
				ret = []
				if tok = parser.skipspaces and (tok.type != :punct or tok.raw != '}')
					parser.unreadtok tok
					loop do
						ret << @type.parse_initializer(parser, scope)
						raise tok || parser if not tok = parser.skipspaces or tok.type != :punct or (tok.raw != '}' and tok.raw != ',')
						break if tok.raw == '}'
					end
				end
				raise parser, 'initializer too long' if type.length.kind_of? Integer and type.length < ret.length
				ret
			else
				parser.unreadtok tok
				super
			end
		end
	end

	class Variable
		include Attributes
		attr_accessor :type
		attr_accessor :initializer	# CExpr	/ Block (for Functions)
		attr_accessor :name
		attr_accessor :storage		# auto register static extern typedef
		attr_accessor :backtrace	# definition backtrace info (the name token)
	end

	class If < Statement
		attr_accessor :test		# expression
		attr_accessor :bthen, :belse	# statements
		def initialize(test, bthen, belse=nil)
			@test = test
			@bthen = bthen
			@belse = belse if belse
		end

		def self.parse(parser, scope, nest)
			tok = nil
			raise tok || self, '"(" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '('
			raise tok, 'expr expected' if not expr = CExpression.parse(parser, scope)
			raise tok || self, '")" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'
			bthen = parser.parse_statement scope, nest
			if tok = parser.skipspaces and tok.type == :string and tok.raw == 'else'
				belse = parser.parse_statement scope, nest
			else
				parser.unreadtok tok
			end

			new expr, bthen, belse
		end
	end
	class For < Statement
		attr_accessor :init, :test, :iter	# CExpressions, init may be Block
		attr_accessor :body
		def initialize(init, test, iter, body)
			@init, @test, @iter, @body = init, test, iter, body
		end

		def self.parse(parser, scope, nest)
			tok = nil
			raise tok || parser, '"(" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '('
			init = forscope = Block.new
			if not parse_definition(forscope)
				forscope = scope
				raise tok, 'expr expected' if not init = CExpression.parse(parser, forscope)
				raise tok || parser, '";" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ';'
			end
			raise tok, 'expr expected' if not test = CExpression.parse(parser, forscope)
			raise tok || parser, '";" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ';'
			raise tok, 'expr expected' if not iter = CExpression.parse(parser, forscope)
			raise tok || parser, '")" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'

			new init, test, iter, parser.parse_statement(forscope, nest + [:loop])
		end
	end
	class While < Statement
		attr_accessor :test
		attr_accessor :body

		def initialize(test, body)
			@test = test
			@body = body
		end

		def self.parse(parser, scope, nest)
			tok = nil
			raise tok || parser, '"(" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '('
			raise tok, 'expr expected' if not expr = CExpression.parse(parser, scope)
			raise tok || parser, '")" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'

			new expr, parser.parse_statement(scope, nest + [:loop])
		end
	end
	class DoWhile < While
		def self.parse(parser, scope, nest)
			body = parser.parse_statement(scope, nest + [:loop])
			tok = nil
			raise tok || parser, '"while" expected' if not tok = parser.skipspaces or tok.type != :string or tok.raw != 'while'
			raise tok || parser, '"(" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '('
			raise tok, 'expr expected' if not expr = CExpression.parse(parser, scope)
			raise tok || parser, '")" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'
			raise tok || parser, '";" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ';'

			new expr, body
		end
	end
	class Switch < Statement
		attr_accessor :test, :body

		def initialize(test, body)
			@test = test
			@body = body
		end

		def self.parse(parser, scope, nest)
			raise tok || parser, '"(" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '('
			raise tok, 'expr expected' if not expr = CExpression.parse(parser, scope)
			raise tok || parser, '")" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'

			new expr, parser.parse_statement(scope, nest + [:switch])
		end
	end

	class Continue < Statement
	end
	class Break < Statement
	end
	class Goto < Statement
		attr_accessor :target
		def initialize(target)
			@target = target
		end
	end
	class Return < Statement
		attr_accessor :value
		def initialize(value)
			@value = value
		end
	end
	class Label < Statement
		attr_accessor :name
		attr_accessor :statement
		def initialize(name, statement)
			@name, @statement = name, statement
		end
	end
	class Case < Label
		attr_accessor :expr, :exprup	# exprup if range, expr may be 'default'
		def initialize(expr, exprup, statement)
			@expr, @statement = expr, statement
			@exprup = exprup if exprup
		end

		def self.parse(parser, scope, nest)
			raise parser if not expr = CExpression.parse(parser, scope)
			raise tok || parser, '":" or "..." expected' if not tok = parser.skipspaces or tok.type != :punct or (tok.raw != ':' and tok.raw != '.')
			if tok.raw == '.'
				raise tok || parser, '".." expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '.'
				raise tok || parser,  '"." expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '.'
				raise tok if not exprup = CExpression.parse(parser, scope)
				raise tok || parser, '":" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ':'
			end
			body = parser.parse_statement scope, nest
			new expr, exprup, body
		end
	end

	# inline asm statement
	class Asm < Statement
		attr_accessor :body		# asm source (::String)
		attr_accessor :output, :input, :clobber	# I/O, gcc-style (::Array)
		attr_accessor :backtrace	# body Token
		attr_accessor :volatile

		def initialize(body, backtrace, output, input, clobber, volatile)
			@body, @backtrace, @output, @input, @clobber, @volatile = body, backtrace, output, input, clobber, volatile
		end
		
		def self.parse(parser, scope)
			if tok = parser.skipspaces and tok.type == :string and (tok.raw == 'volatile' or tok.raw == '__volatile__')
				volatile = true
				tok = parser.skipspaces
			end
			raise tok || parser, '"(" expected' if not tok or tok.type != :punct or tok.raw != '('
			raise tok || parser, 'qstring expected' if not tok = parser.skipspaces or tok.type != :quoted
			body = tok
			tok = parser.skipspaces
			raise tok || parser, '":" or ")" expected' if not tok or tok.type != :punct or (tok.raw != ':' and tok.raw != ')')

			if tok.raw == ':'
				output = []
				raise parser if not tok = parser.skipspaces
				while tok.type == :quoted
					type = tok.value
					raise tok, 'expr expected' if not var = CExpression.parse_value(parser, scope)
					output << [type, var]
					raise tok || parser, '":" or "," or ")" expected' if not tok = parser.skipspaces or tok.type != :punct or (tok.raw != ',' and tok.raw != ')' and tok.raw != ':')
					break if tok.raw == ':' or tok.raw == ')'
					raise tok || parser, 'qstring expected' if not tok = parser.skipspaces or tok.type != :quoted
				end
			end
			if tok.raw == ':'
				input = []
				raise parser if not tok = parser.skipspaces
				while tok.type == :quoted
					type = tok.value
					raise tok, 'expr expected' if not var = CExpression.parse_value(parser, scope)
					input << [type, var]
					raise tok || parser, '":" or "," or ")" expected' if not tok = parser.skipspaces or tok.type != :punct or (tok.raw != ',' and tok.raw != ')' and tok.raw != ':')
					break if tok.raw == ':' or tok.raw == ')'
					raise tok || parser, 'qstring expected' if not tok = parser.skipspaces or tok.type != :quoted
				end
			end
			if tok.raw == ':'
				clobber = []
				raise parser if not tok = parser.skipspaces
				while tok.type == :quoted
					clobber << tok.value
					raise tok || parser, '"," or ")" expected' if not tok = parser.skipspaces or tok.type != :punct or (tok.raw != ',' and tok.raw != ')')
					break if tok.raw == ')'
					raise tok || parser, 'qstring expected' if not tok = parser.skipspaces or tok.type != :quoted
				end
			end
			raise tok || parser, '")" expected' if not tok or tok.type != :punct or tok.raw != ')'
			raise tok || parser, '";" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ';'

			new body.value, body, output, input, clobber, volatile
		end
	end

	class CExpression < Statement
		# may be :,, :., :->, :funcall (function, [arglist]), :[] (array indexing), nil (cast)
		attr_accessor :op
		# nil/CExpr/Variable/Label/::String( = :quoted/struct member name)/::Integer/::Float
		attr_accessor :lexpr, :rexpr
		# a Type
		attr_accessor :type
		def initialize(l, o, r, t)
			@lexpr, @op, @rexpr, @type = l, o, r, t
		end
	end

	# creates a new CParser, parses all top-level statements
	def self.parse(text, file='unknown', lineno=1)
		c = new
		c.lexer.feed text, file, lineno
		nil while not c.lexer.eos? and c.parse_definition(c.toplevel)
		raise c.lexer.readtok || c, 'EOF expected' if not c.lexer.eos?
		c.sanity_checks
		c
	end

	attr_accessor :lexer, :toplevel, :typesize
	def initialize(lexer = nil, model=:ilp32)
		@lexer = lexer || Preprocessor.new
		@lexer.feed <<EOS, 'metasm_intern_init'
#ifndef inline
# define inline __attribute__((inline))
#endif
#ifndef __declspec
# define __declspec(a) __attribute__((a))
# define __cdecl    __declspec(cdecl)
# define __stdcall  __declspec(stdcall)
# define __fastcall __declspec(fastcall)
#endif
EOS
		@lexer.readtok until @lexer.eos?
		@toplevel = Block.new(nil)
		@unreadtoks = []
		send model
	end

	def lp32
		@typesize = { :char => 1, :short => 2, :ptr => 4,
			:int => 2, :long => 4, :longlong => 8,
			:float => 4, :double => 8, :longdouble => 12 }
	end
	def ilp32
		@typesize = { :char => 1, :short => 2, :ptr => 4,
			:int => 4, :long => 4, :longlong => 8,
			:float => 4, :double => 8, :longdouble => 12 }
	end
	def llp64
		# longlong should only exist here
		@typesize = { :char => 1, :short => 2, :ptr => 8,
			:int => 4, :long => 4, :longlong => 8,
			:float => 4, :double => 8, :longdouble => 12 }
	end
	def ilp64
		@typesize = { :char => 1, :short => 2, :ptr => 8,
			:int => 8, :long => 8, :longlong => 8,
			:float => 4, :double => 8, :longdouble => 12 }
	end
	def lp64
		@typesize = { :char => 1, :short => 2, :ptr => 8,
			:int => 4, :long => 8, :longlong => 8,
			:float => 4, :double => 8, :longdouble => 12 }
	end

	# C sanity checks
	def sanity_checks
		return if not $VERBOSE
		#  TODO
	end

	# checks that the types are compatible (variable predeclaration, function argument..)
	# strict = false for func call/assignment (eg char compatible with int -- but int is incompatible with char)
	def check_compatible_type(tok, oldtype, newtype, strict = false)
		puts tok.exception('type qualifier mismatch').message if oldtype.qualifier != newtype.qualifier

		oldtype = oldtype.type while oldtype.kind_of? TypeDef
		newtype = newtype.type while newtype.kind_of? TypeDef
		oldtype = BaseType(:int) if oldtype.kind_of? Enum
		newtype = BaseType(:int) if newtype.kind_of? Enum

		case newtype
		when Function
			raise tok, 'incompatible type' if not oldtype.kind_of? Function
			check_compatible_type tok, oldtype.type, newtype.type, strict
			if oldtype.args and newtype.args
				if oldtype.args.length != newtype.args.length or
						oldtype.varargs != newtype.varargs
					raise tok, 'incompatible type'
				end
				oldtype.args.zip(newtype.args) { |oa, na|
					# begin ; rescue ParseError: raise $!.message + "in parameter #{oa.name}" end
					check_compatible_type tok, oa.type, na.type, strict
				}
			end
		when Pointer
			raise tok, 'incompatible type' if not oldtype.kind_of? Pointer
			# allow any pointer to void*
			check_compatible_type tok, oldtype.type, newtype.type, strict if strict or newtype.type != :void
		when Union
			raise tok, 'incompatible type' if not oldtype.class == newtype.class
			if oldtype.members and newtype.members
				if oldtype.members.length != newtype.members.length
					raise tok, 'incompatible type'
				end
				oldtype.members.zip(newtype.members) { |om, nm|
					# raise tok if om.name and nm.name and om.name != nm.name # don't care
					check_compatible_type tok, om.type, nm.type, strict
				}
			end
		when BaseType
			if strict
				if oldtype.name != newtype.name or
				oldtype.qualifier != newtype.qualifier or
				oldtype.specifier != newtype.specifier
					raise tok, 'incompatible type'
				end
			else
				# void type not allowed
				raise tok, 'incompatible type' if oldtype.name == :void or newtype.name == :void
				# check int/float mix	# TODO float -> int allowed ?
				raise tok, 'incompatible type' if oldtype.name != newtype.name and ([:char, :int, :short, :long, :longlong] & [oldtype.name, newtype.name]).length == 1
				# check int size/sign
				raise tok, 'incompatible type' if @typesize[oldtype.name] > @typesize[newtype.name]
				puts tok.exception('sign mismatch').message if $VERBOSE and oldtype.specifier != newtype.specifier and @typesize[newtype.name] == @typesize[oldtype.name]
			end
		end
	end

	Reserved = %w[struct union enum  if else for while do switch goto
			register extern auto static typedef  const volatile
			void int float double char  signed unsigned long short
			case continue break return default  __attribute__
			asm __asm__ sizeof __builtin_offsetof typeof
	].inject({}) { |h, w| h.update w => true }

	# allows 'raise self'
	def exception(msg='EOF unexpected')
		raise @lexer, msg
	end

	# reads a token, convert 'L"foo"' to a :quoted
	def readtok_longstr
		if t = @lexer.readtok and t.type == :string and t.raw == 'L' and
		nt = @lexer.readtok and nt.type == :quoted and nt.raw[0] == ?"
			nt.raw[0, 0] = 'L'
			nt
		else
			@lexer.unreadtok nt
			t
		end
	end
	private :readtok_longstr

	# reads a token from self.lexer
	# concatenates strings, merges spaces/eol to ' ', handles wchar strings
	def readtok
		if not t = @unreadtoks.pop
			return if not t = readtok_longstr
			case t.type
			when :space, :eol
				# merge consecutive :space/:eol
				t = t.dup
				t.type = :space
				t.raw = ' '
				nil while nt = @lexer.readtok and (nt.type == :eol or nt.type == :space)
				@lexer.unreadtok nt

			when :quoted
				# merge consecutive :quoted
				t = t.dup
				while nt = readtok_longstr and nt.type == :quoted
					if t.raw[0] == ?" and nt.raw[0, 1] == 'L"'
						# ensure wide prefix is set
						t.raw[0, 0] = 'L'
					end
					t.raw << ' ' << nt.raw
					t.value << nt.value
				end
				@lexer.unreadtok nt
			end
		end
		t
	end

	def unreadtok(tok)
		@unreadtoks << tok if tok
	end

	# returns the next non-space/non-eol token
	def skipspaces
		nil while t = readtok and t.type == :space
		t
	end

	# returns the size of a type in bytes
	def sizeof(var, type=var.type)
		# XXX double-check class apparition order ('when' checks inheritance)
		case type
		when Array
			case type.length
			when nil
				raise self, 'unknown array size' if not var.kind_of? Variable or not var.initializer
				raise self, 'TODO sizeof(array[] initializer)'	# TODO
			when Integer: type.length * sizeof(type)
			else raise self, 'unknown array size'
			end
		when Pointer
			@typesize[:ptr]
		when Function
			# raise # gcc responds 1
			1
		when BaseType
			@typesize[type.name]
		when Enum
			@typesize[:int]
		when Struct
			raise self, 'unknown structure size' if not type.members
			type.members.map { |m| (sizeof(m) + type.align - 1) / type.align * type.align }.inject(0) { |a, b| a+b }
		when Union
			raise self, 'unknown structure size' if not type.members
			type.members.map { |m| sizeof(m) }.max || 0
		when TypeDef
			sizeof(var, type.type)
		end
	end

	# parses variable/function definition/declaration/initialization
	# populates scope.symbols and scope.struct
	# raises on redefinitions
	# returns false if no definition found
	def parse_definition(scope)
		return false if not basetype = Variable.parse_type(self, scope, true)

		# check struct predeclaration
		tok = skipspaces
		if tok and tok.type == :punct and tok.raw == ';' and basetype.type and
				(basetype.type.kind_of? Union or basetype.type.kind_of? Enum)
			return true
		else unreadtok tok
		end

		nofunc = false
		loop do
			var = basetype.dup
			var.parse_declarator(self, scope)

			raise self if not var.name	# barrel roll

			if prev = scope.symbol[var.name] and (
					not scope.symbol[var.name].kind_of?(Variable) or
					scope.symbol[var.name].initializer)
				raise var.backtrace, 'redefinition'
			elsif var.storage == :typedef
				var = TypeDef.new var.name, var.type, var.backtrace
			elsif prev
				check_compatible_type prev.backtrace, prev.type, var.type, true
				# XXX forward attributes ?
			end
			scope.symbol[var.name] = var

			raise tok || self, 'punctuation expected' if not tok = skipspaces or tok.type != :punct

			case tok.raw
			when '{'
				# function body
				raise tok if nofunc or not var.kind_of? Variable or not var.type.kind_of? Function
				body = var.initializer = Block.new(scope)
				var.type.args.each { |v|
					# put func parameters in func body scope
					# arg redefinition is checked in parse_declarator
					if not v.name
						puts "unnamed argument in definition" if $VERBOSE
						next	# should raise
					end
					body.variable[v.name] = v	# XXX will need special check in stack allocator
				}

				loop do
					raise tok || self, '"}" expected' if not tok = skipspaces
					break if tok.type == :punct and tok.raw == '}'
					unreadtok tok
					if not parse_definition(body)
						body.statements << parse_statement(body, [])
					end
				end
				break
			when '='
				# variable initialization
				raise tok, '"{" or ";" expected' if var.type.kind_of? Function
				raise tok, 'cannot initialize extern variable' if var.storage == :extern
				var.initializer = var.type.parse_initializer(self, scope)
				if var.initializer.kind_of?(CExpression) and (scope == @toplevel or var.storage == :static)
					raise tok, 'initializer is not constant' if not var.initializer.constant?
					var.initializer = var.initializer.reduce(self)
					var.initializer = var.initializer.initializer if var.initializer.kind_of? Variable
				end
				raise tok || self, '"," or ";" expected' if not tok = skipspaces or tok.type != :punct
			end

			case tok.raw
			when ',': nofunc = true
			when ';': break
			else raise tok, '";" or "," expected'
			end
		end
		true
	end

	# returns a statement or raise
	def parse_statement(scope, nest)
		raise self, 'statement expected' if not tok = skipspaces

		if tok.type == :punct and tok.raw == '{'
			body = Block.new scope
			loop do
				raise tok || self, '"}" expected' if not tok = skipspaces
				break if tok.type == :punct and tok.raw == '}'
				unskipspaces tok
				if not parse_definition(body)
					body.statements << parse_statement(body, nest)
				end
			end
			return body
		elsif tok.type != :string
			unskipspaces tok
			raise tok, 'expr expected' if not expr = CExpression.parse(self, scope)
			raise tok || self, '";" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ';'

			if $VERBOSE and (expr.op or not expr.type.kind_of? BaseType or expr.type.name != :void) and CExpression.constant?(expr)
				puts tok.exception('statement with no effect')
			end
			return expr
		end

		case tok.raw
		when 'if'
			If.parse      self, scope, nest
		when 'while'
			While.parse   self, scope, nest
		when 'do'
			DoWhile.parse self, scope, nest
		when 'for'
			For.parse     self, scope, nest
		when 'switch'
			Switch.parse  self, scope, nest
		when 'goto'
			raise tok || self, 'label expected' if not tok = skipspaces or tok.type != :string
			name = tok.raw
			raise tok || self, '";" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ';'
			Goto.new name
		when 'return'
			expr = CExpression.parse(self, scope)	# nil allowed
			raise tok || self, '";" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ';'
			Return.new expr
		when 'case'
			raise tok, 'case out of switch' if not nest.include? :switch
			Case.parse    self, scope, nest
		when 'default'
			raise tok || self, '":" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ':'
			raise tok, 'case out of switch' if not nest.include? :switch
			Case.new 'default', nil, parse_statement(scope, nest)
		when 'continue'
			raise tok || self, '";" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ';'
			raise tok, 'continue out of loop' if not nest.include? :loop
			Continue.new
		when 'break'
			raise tok || self, '";" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ';'
			raise tok, 'break out of loop' if not nest.include? :loop and not nest.include? :switch
			Break.new
		when 'asm', '__asm__'
			Asm.parse self, scope
		else
			if ntok = skipspaces and ntok.type == :punct and ntok.raw == ':'
				Label.new tok.raw, parse_statement(scope, nest)
			else
				unreadtok ntok
				unreadtok tok
				raise tok, 'expr expected' if not expr = CExpression.parse(self, scope)
				raise tok || self, '";" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ';'

				if $VERBOSE and (expr.op or not expr.type.kind_of? BaseType or expr.type.name != :void) and CExpression.constant?(expr)
					puts tok.exception('statement with no effect')
				end
				expr
			end
		end
	end

	class Variable
		# parses a variable basetype/qualifier/(storage if allow_value), returns a new variable of this type
		# populates scope.struct
		def self.parse_type(parser, scope, allow_value = false)
			var = new
			qualifier = []
			loop do
				break if not tok = parser.skipspaces
				if tok.type != :string
					parser.unreadtok tok
					break
				end
	
				case tok.raw
				when 'const', 'volatile'
					qualifier << tok.raw.to_sym
					next
				when 'register', 'auto', 'static', 'typedef', 'extern'
					raise tok, 'storage specifier not allowed here' if not allow_value
					raise tok, 'multiple storage class' if var.storage
					var.storage = tok.raw.to_sym
					next
				when 'struct'
					var.type = Struct.new
					var.type.align = parser.lexer.pragma_pack
					var.parse_type_struct(parser, scope)
				when 'union'
					var.type = Union.new
					var.parse_type_struct(parser, scope)
				when 'enum'
					var.type = Enum.new
					var.parse_type_struct(parser, scope)
				when 'typeof'
					if ntok = parser.skipspaces and ntok.type == :punct and ntok.raw == '('
						# check type
						if v = parse_type(parser, scope)
							v.parse_declarator(parser, scope)
							raise tok if v.name != false
							raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'
						else
							raise tok, 'expr expected' if not v = CExpression.parse(parser, scope)
							raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'
						end
					else
						parser.unreadtok ntok
						raise tok, 'expr expected' if not v = CExpression.parse_value(parser, scope)
					end
					var.type = TypeDef.new('typeof', v.type, tok)
				when 'long', 'short', 'signed', 'unsigned', 'int', 'char', 'float', 'double', 'void'
					parser.unreadtok tok
					var.parse_type_base(parser, scope)
				else
					if type = scope.symbol_ancestors[tok.raw] and type.kind_of? TypeDef
						var.type = type.dup
					else
						parser.unreadtok tok
					end
				end
	
				break
			end
	
			if not var.type
				raise parser, 'bad type name' if not qualifier.empty? or var.storage
				nil
			else
				(var.type.qualifier ||= []).concat qualifier if not qualifier.empty?
				var.type.parse_attributes(parser)
				var
			end
		end
	
		# parses a structure/union/enum declaration
		def parse_type_struct(parser, scope)
			if tok = parser.skipspaces and tok.type == :punct and tok.raw == '{'
				# anonymous struct, ok
				@type.backtrace = tok
			elsif tok and tok.type == :string
				name = tok.raw
				raise tok, 'bad struct name' if Reserved[name] or (?0..?9).include?(name[0])
				@type.parse_attributes(parser)
				raise parser if not ntok = parser.skipspaces
				if ntok.type != :punct or ntok.raw != '{'
					# variable declaration
					parser.unreadtok ntok
					if ntok.type == :punct and ntok.raw == ';'
						# struct predeclaration
						# allow redefinition
						scope.struct[name] ||= @type
					else
						# check that the structure exists
						# do not check it is declared (may be a pointer)
						struct = scope.struct_ancestors[name]
						raise tok, 'unknown struct' if not struct or not struct.kind_of?(@type.class)
						(struct.attributes ||= []).concat @type.attributes if @type.attributes
						(struct.qualifier ||= []).concat @type.qualifier if @type.qualifier
						@type = struct
					end
					return
				end
				raise tok, 'struct redefinition' if scope.struct[name] and scope.struct[name].members
				scope.struct[name] = @type
				@type.backtrace = tok
			else
				raise tok || parser, 'struct name or "{" expected'
			end
	
			@type.parse_members(parser, scope)
		end
	
		# parses int/long int/long long/double etc
		def parse_type_base(parser, scope)
			specifier = []
			qualifier = []
			name = :int
			tok = nil
			loop do
				raise parser if not tok = parser.skipspaces
				if tok.type != :string
					parser.unreadtok tok
					break
				end
				case tok.raw
				when 'const', 'volatile'
					qualifier << tok.raw.to_sym
				when 'long', 'short', 'signed', 'unsigned'
					specifier << tok.raw.to_sym
				when 'int', 'char', 'void', 'float', 'double'
					name = tok.raw.to_sym
					break
				else
					parser.unreadtok tok
					break
				end
			end
	
			case name
			when :double	# long double
				if specifier == [:long]
					name = :longdouble
					specifier.clear
				elsif not specifier.empty?
					raise tok || parser, 'invalid specifier list'
				end
			when :int	# short, long, long long X signed, unsigned
				specifier = specifier - [:long] + [:longlong] if (specifier & [:long]).length == 2
				if (specifier & [:signed, :unsigned]).length > 1 or (specifier & [:short, :long, :longlong]).length > 1
					raise tok || parser, 'invalid specifier list'
				else
					name = (specifier & [:longlong, :long, :short])[0] || :int
					specifier -= [:longlong, :long, :short]
				end
				specifier.delete :signed	# default
			when :char	# signed, unsigned
				# signed char != char and unsigned char != char
				if (specifier & [:signed, :unsigned]).length > 1 or (specifier & [:short, :long]).length > 0
					raise tok || parser, 'invalid specifier list'
				end
			else		# none
				raise tok || parser, 'invalid type' if not specifier.empty?
			end
	
			@type = BaseType.new(name, *specifier)
			@type.qualifier = qualifier if not qualifier.empty?
		end

		# updates @type and @name, parses pointer/arrays/function declarations
		# parses anonymous declarators (@name will be false)
		# the caller is responsible for detecting redefinitions
		# scope used only in CExpression.parse for array sizes and function prototype argument types
		# rec for internal use only
		def parse_declarator(parser, scope, rec = false)
			raise parser if not tok = parser.skipspaces
			# read upto name
			if tok.type == :punct and tok.raw == '*'
				ptr = Pointer.new
				ptr.parse_attributes(parser)
				parse_declarator(parser, scope, true)
				t = self
				t = t.type while t.type and (t.type.kind_of?(Pointer) or t.type.kind_of?(Function))
				ptr.type = t.type
				t.type = ptr
				return
			elsif tok.type == :punct and tok.raw == '('
				parse_declarator(parser, scope, true)
				raise tok || parser, '")" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'
			elsif tok.type == :string
				if tok.raw == 'const' or tok.raw == 'volatile'
					(@type.qualifier ||= []) << tok.raw.to_sym
					return parse_declarator(parser, scope, rec)
				end
				raise tok if @name or @name == false
				raise tok, 'bad var name' if Reserved[tok.raw] or (?0..?9).include?(tok.raw[0])
				@name = tok.raw
				@backtrace = tok
				parse_attributes(parser)
			else
				# unnamed
				raise tok if @name or @name == false
				@name = false
				@backtrace = tok
				parser.unreadtok tok
				parse_attributes(parser)
			end
			parse_declarator_postfix(parser, scope)
			if not rec
				raise @backtrace, 'void type is invalid' if @name and @type.kind_of? BaseType and @type.name == :void
				raise @backtrace, 'uninitialized structure' if (@type.kind_of? Union or @type.kind_of? Enum) and not @type.members
			end
		end
	
		# parses array/function type
		def parse_declarator_postfix(parser, scope)
			if tok = parser.skipspaces and tok.type == :punct and tok.raw == '['
				# array indexing
				idx = CExpression.parse(parser, scope)	# may be nil
				if idx and (scope == parser.toplevel or @storage == :static)
					raise tok, 'array size is not constant' if not idx.constant?
				end
				t = self
				t = t.type while t.type and (t.type.kind_of?(Pointer) or t.type.kind_of?(Function))
				t.type = Array.new t.type
				t.type.length = idx
				raise tok || parser, '"]" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ']'
				parse_attributes(parser)	# should be type.attrs, but this is should be more compiler-compatible
			elsif tok and tok.type == :punct and tok.raw == '('
				# function prototype
				t = self
				t = t.type while t.type and (t.type.kind_of?(Pointer) or t.type.kind_of?(Function))
				t.type = Function.new t.type
				if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'
					parser.unreadtok tok
					t.type.args = []
					loop do
						raise parser if not tok = parser.skipspaces
						if tok.type == :punct and tok.raw == '.'	# variadic function
							raise parser, '".." expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '.'
							raise parser,  '"." expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '.'
							raise parser,  '")" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'
							t.type.varargs = true
							break
						elsif tok.type == :string and tok.raw == 'register'
							storage = :register
						else
							parser.unreadtok tok
						end
	
						raise tok if not v = Variable.parse_type(parser, scope)
						v.storage = storage if storage
						v.parse_declarator(parser, scope)
	
						args << v if not v.type.kind_of? BaseType or v.type.name != :void
						if tok = parser.skipspaces and tok.type == :punct and tok.raw == ','
							raise tok, '")" expected' if args.last != v		# last arg of type :void
						elsif tok and tok.type == :punct and tok.raw == ')'
							break
						else raise tok || parser, '"," or ")" expected'
						end
					end
				end
				parse_attributes(parser)	# should be type.attrs, but this should be more existing-compiler-compatible
			else
				parser.unreadtok tok
				return
			end
			parse_declarator_postfix(parser, scope)
		end
	end

	class CExpression
		def self.lvalue?(e)
			e.kind_of?(self) ? e.lvalue? : (e.kind_of? Variable and e.name)
		end
		def lvalue?
			case @op
			when :*: true if not @lexpr
			when :'[]': true
			when nil	# cast
				CExpression.lvalue?(@rexpr)
			else false
			end
		end

		def self.constant?(e)
			e.kind_of?(self) ? e.constant? : true
		end
		def constant?
			# gcc considers '1, 2' not constant
			if [:',', :funcall, :'--', :'++', :'+=', :'-=', :'*=', :'/=', :'>>=', :'<<=', :'&=', :'|=', :'^=', :'%=', :'->', :'[]'].include?(@op)
				false
			elsif @op == :'*' and not @lexpr: false
			else
				out = true
				walk { |e| break out = false if not CExpression.constant?(e) }
				out
			end
		end

		def self.reduce(parser, e)
			e.kind_of?(self) ? e.reduce(parser) : e
		end
		def reduce(parser)
			# parser used for arithmetic overflows (need basic type sizes)
			case @op
			when :'&&'
				case l = CExpression.reduce(parser, @lexpr)
				when 0: 0
				when ::Integer
					case r = CExpression.reduce(parser, @rexpr)
					when 0: 0
					when ::Integer: 1
					else CExpression.new(l, @op, r, @type)
					end
				else CExpression.new(l, @op, @rexpr, @type)
				end
			when :'||'
				case l = CExpression.reduce(parser, @lexpr)
				when 0
					case r = CExpression.reduce(parser, @rexpr)
					when 0: 0
					when ::Integer: 1
					else CExpression.new(l, @op, r, @type)
					end
				when ::Integer: 1
				else CExpression.new(l, @op, @rexpr, @type)
				end
			when :'!'
				case r = CExpression.reduce(parser, @rexpr)
				when 0: 1
				when ::Integer: 0
				else CExpression.new(nil, @op, r, @type)
				end
			when :'!=', :'==', :'<', :'>', :'>=', :'<='
				l = CExpression.reduce(parser, @lexpr)
				r = CExpression.reduce(parser, @rexpr)
				if l.kind_of?(::Integer) and r.kind_of?(::Integer)
					if @op == :'!=': l != r ? 1 : 0
					else l.send(@op, r) ? 1 : 0
					end
				else CExpression.new(l, @op, r, @type)
				end
			when :'.'
				le = CExpression.reduce(parser, @lexpr)
				if le.kind_of? Variable and le.initializer.kind_of? ::Array
					midx = le.type.members.index(le.type.members.find { |m| m.name == @rexpr })
					CExpression.reduce(parser, le.initializer[midx] || 0)
				else CExpression.new(le, @op, @rexpr, @type)
				end
			when :'?:'
				case c = CExpression.reduce(parser, @lexpr)
				when 0:         CExpression.reduce(parser, @rexpr[0])
				when ::Integer: CExpression.reduce(parser, @rexpr[1])
				else CExpression.new(c, @op, @rexpr, @type)
				end
			when :'+', :'-', :'*', :'/', :'^', :'%', :'&', :'|', :'>>', :'<<', :'~', nil
				t = @type
				t = t.type while t.kind_of? TypeDef
				case t
				when BaseType
				when Pointer: return self #raise parser, 'address unknown for now'
				else raise parser, 'not arithmetic type'
				end

				# compute value
				r = CExpression.reduce(parser, @rexpr)
				ret = \
				if not @lexpr
					# unary
					case @op
					when :'+', nil, :'-', :'~'
						return CExpression.new(nil, @op, r, @type) if not r.kind_of? ::Numeric
						case @op
						when :'-': -r
						when :'~': ~r
						else r
						end
					else return CExpression.new(nil, @op, r, @type)
					end
				else
					l = CExpression.reduce(parser, @lexpr)
					return CExpression.new(l, @op, r, @type) if not l.kind_of?(::Numeric) or not r.kind_of?(::Numeric)
					l.send(@op, r)
				end
				
				# overflow
				case t.name
				when :char, :short, :int, :long, :longlong
					max = 1 << (8*parser.typesize(t.name))
					ret = ret.to_i & (max-1)
					if t.specifier == :signed and (ret & (max >> 1)) > 0	# char == unsigned char
						ret - max
					else
						ret
					end
				when :float, :double, :longdouble
					ret.to_f	# TODO
				end
			when :funcall
				l = CExpression.reduce(parser, @lexpr)
				r = @rexpr.map { |rr| CExpression.reduce(parser, rr) }
				CExpression.new(l, @op, r, @type)
			else
				l = CExpression.reduce(parser, @lexpr) if @lexpr
				r = CExpression.reduce(parser, @rexpr) if @rexpr
				CExpression.new(l, @op, r, @type)
			end
		end

		def walk
			case @op
			when :funcall
				yield @lexpr
				@rexpr.each { |arg| yield arg }
			when :'->', :'.'
				yield @lexpr
			when :'?:'
				yield @lexpr
				yield @rexpr[0]
				yield @rexpr[1]
			else
				yield @lexpr if @lexpr
				yield @rexpr if @rexpr
			end
		end

	class << self
		RIGHTASSOC = [:'=', :'+=', :'-=', :'*=', :'/=', :'%=', :'&=',
			:'|=', :'^=', :'<<=', :'>>='
		].inject({}) { |h, op| h.update op => true }

		# key = operator, value = hash regrouping operators of lower precedence
		# funcall/array index/member dereference/sizeof are handled in parse_value
		OP_PRIO = [[:','], [:'?:'], [:'=', :'+=', :'-=', :'*=', :'/=',
			:'%=', :'&=', :'|=', :'^=', :'<<=', :'>>='], [:'||'],
			[:'&&'], [:|], [:^], [:&], [:'==', :'!='],
			[:'<', :'>', :'<=', :'>='], [:<<, :>>], [:+, :-],
			[:*, :/, :%], ].inject({}) { |h, oplist|
				lessprio = h.keys.inject({}) { |hh, op| hh.update op => true }
				oplist.each { |op| lessprio.update op => true } if RIGHTASSOC[oplist.first]
				oplist.each { |op| h[op] = lessprio }
				h }

		# reads a binary operator from the parser, returns the corresponding symbol or nil
		def readop(parser)
			if not tok = parser.readtok or tok.type != :punct
				parser.unreadtok tok
				return
			end

			op = tok
			case op.raw
			when '>', '<', '|', '&' # << >> || &&
				if ntok = parser.readtok and ntok.type == :punct and ntok.raw == op.raw
					op.raw << parser.readtok.raw
				else
					parser.unreadtok ntok
				end
			when '!' # != (mandatory)
				if not ntok = parser.nexttok or ntok.type != :punct and ntok.raw != '='
					parser.unreadtok tok
					return
				end
				op.raw << parser.readtok.raw
			when '+', '-', '*', '/', '%', '^', '=', '&', '|', ',', '?', ':', '>>', '<<', '||', '&&',
			     '+=','-=','*=','/=','%=','^=','==','&=','|=','!=' # ok
			else # bad
				parser.unreadtok tok
				return
			end

			# may be followed by '='
			case tok.raw
			when '+', '-', '*', '/', '%', '^', '&', '|', '>>', '<<', '<', '>', '='
				if ntok = parser.readtok and ntok.type == :punct and ntok.raw == '='
					op.raw << ntok.raw
				else
					parser.unreadtok ntok
				end
			end

			op.value = op.raw.to_sym
			op
		end

		# parse sizeof offsetof float immediate etc into tok.value
		def parse_intfloat(parser, scope, tok)
			if tok.type == :string and not tok.value
				case tok.raw
				when 'sizeof'
					if ntok = parser.skipspaces and ntok.type == :punct and ntok.raw == '('
						# check type
						if v = Variable.parse_type(parser, scope)
							v.parse_declarator(parser, scope)
							raise tok if v.name != false
							raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'
						else
							raise tok, 'expr expected' if not v = parse(parser, scope)
							raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'
						end
					else
						parser.unreadtok ntok
						raise tok, 'expr expected' if not v = parse_value(parser, scope)
					end
					tok.value = parser.sizeof(v)
					return
				when '__builtin_offsetof'
					raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != '('
					raise tok if not ntok = parser.skipspaces or ntok.type != :string or ntok.raw != 'struct'
					raise tok if not ntok = parser.skipspaces or ntok.type != :string
					raise tok, 'unknown structure' if not struct = scope.struct_ancestors[ntok.raw] or not struct.kind_of? Union or not struct.members
					raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ','
					raise tok if not ntok = parser.skipspaces or ntok.type != :string
					tok.value = struct.offsetof(parser, ntok.raw)
					raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'
					return
				end
			end

			Expression.parse_num_value(parser, tok)
		end

		# returns the next value from parser (parenthesised expression, immediate, variable, unary operators)
		def parse_value(parser, scope)
			return if not tok = parser.skipspaces
			case tok.type
			when :string
				parse_intfloat(parser, scope, tok)
				val = tok.value || tok.raw
				if val.kind_of? ::String
					raise tok, 'undefined variable' if not val = scope.symbol_ancestors[val]
				end
				case val
				when Type
					raise tok, 'invalid variable'
				when Variable
					val = parse_value_postfix(parser, scope, val)
				when ::Float
					# parse suffix
					type = :double
					if (?0..?9).include?(tok.raw[0])
						case tok.raw.downcase[-1]
						when ?l: type = :longdouble
						when ?f: type = :float
						end
					end
					val = CExpression.new(nil, nil, val, BaseType.new(type))

				when ::Integer
					# parse suffix
					# XXX 010h ?
					type = :int
					specifier = []
					if (?0..?9).include?(tok.raw[0])
						suffix = tok.raw.downcase[-3, 3] || tok.raw.downcase[-2, 2] || tok.raw.downcase[-1, 1]	# short string
						specifier << :unsigned if suffix.include?('u') # XXX or tok.raw.downcase[1] == ?x
						type = :longlong if suffix.count('l') == 2
						type = :long if suffix.count('l') == 1
					end
					val = CExpression.new(nil, nil, val, BaseType.new(type, *specifier))
				else raise parser, "internal error #{val.inspect}"
				end

			when :quoted
				if tok.raw[0] == ?'
					raise tok, 'invalid character constant' if tok.value.length > 1
					val = CExpression.new(nil, nil, tok.value[0], BaseType.new(:int))
				else
					val = CExpression.new(nil, nil, tok.value, Pointer.new(BaseType.new(tok.raw[0, 1] == 'L"' ? :short : :char)))
					val = parse_value_postfix(parser, scope, val)
				end

			when :punct
				case tok.raw
				when '('
					# check type casting
					if v = Variable.parse_type(parser, scope)
						v.parse_declarator(parser, scope)
						raise tok, 'bad cast' if v.name != false
						raise ntok || tok, 'no ")" found' if not ntok = parser.readtok or ntok.type != :punct or ntok.raw != ')'
						raise ntok, 'expr expected' if not val = parse_value(parser, scope)	# parses postfix too
						val = CExpression.new(nil, nil, val, v.type)
					else
						if not val = parse(parser, scope)
							parser.unreadtok tok
							return
						end
						raise ntok || tok, 'no ")" found' if not ntok = parser.readtok or ntok.type != :punct or ntok.raw != ')'
						val = parse_value_postfix(parser, scope, val)
					end
				when '.'	# float
					parse_intfloat(parser, scope, tok)
					if not tok.value
						parser.unreadtok tok
						return
					end
					type = \
					case tok.raw.downcase[-1]
					when ?l: :longdouble
					when ?f: :float
					else :double
					end
					val = CExpression.new(nil, nil, val, BaseType.new(type))

				when '+', '-', '&', '!', '~', '*', '--', '++', '&&'
					# unary prefix
					# may have been read ahead
					
					raise parser if not ntok = parser.readtok
					# check for -- ++ &&
					if ntok.type == :punct and ntok.raw == tok.raw and %w[+ - &].include?(tok.raw)
						tok.raw << ntok.raw
					else
						parser.unreadtok ntok
					end

					case tok.raw
					when '&'
						val = parse_expr(parser, scope)
						raise parser, "invalid lvalue #{val.inspect}" if not CExpression.lvalue?(val)
						raise val.backtrace, 'cannot take addr of register' if val.kind_of? Variable and val.storage == :register
						val = CExpression.new(nil, tok.raw.to_sym, val, Pointer.new(val.type))
					when '++', '--'
						val = parse_expr(parser, scope)
						raise parser, "invalid lvalue #{val.inspect}" if not CExpression.lvalue?(val)
						val = CExpression.new(nil, tok.raw.to_sym, val, val.type)
					when '&&'
						raise tok, 'label name expected' if not val = lexer.skipspaces or val.type != :string
						val = CExpression.new(nil, nil, Label.new(val.raw, nil), Pointer.new(BaseType.new(:void)))
					when '*'
						raise tok, 'expr expected' if not val = parse_value(parser, scope)
						raise tok, 'not a pointer' if not val.type.pointer?
						val = CExpression.new(nil, tok.raw.to_sym, val, val.type.type)
					when '~', '!', '+', '-'
						raise tok, 'expr expected' if not val = parse_value(parser, scope)
						raise tok, 'type not arithmetic' if not val.type.arithmetic?
						val = CExpression.new(nil, tok.raw.to_sym, val, val.type)
					else raise tok, 'internal error'
					end
				else
					parser.unreadtok tok
					return
				end
			else
				parser.unreadtok tok
				return
			end
			val
		end
		
		# parse postfix forms (postincrement, array index, struct member dereference)
		def parse_value_postfix(parser, scope, val)
			tok = parser.skipspaces
			nval = \
			if tok and tok.type == :punct
				case tok.raw
				when '-', '--', '->'
					ntok = parser.skipspaces
					if tok.raw == '-' and ntok and ntok.type == :punct and (ntok.raw == '-' or ntok.raw == '>')
						tok.raw << ntok.raw
					else
						parser.unreadtok ntok
					end

					case tok.raw
					when '-'
						parser.unreadtok tok
						nil
					when '->'
						raise tok, 'not a pointer' if not val.type.pointer?
						raise tok, 'invalid member' if not tok = parser.skipspaces or tok.type != :string
						type = val.type
						type = type.type while type.kind_of? TypeDef
						type = type.type
						type = type.type while type.kind_of? TypeDef
						raise tok, 'invalid member' if not type.kind_of? Union or not type.members or not m = type.members.find { |m| m.name == tok.raw }
						CExpression.new(val, :'->', tok.raw, m.type)
					when '--'
						raise parser, "invalid lvalue #{val.inspect}" if not CExpression.lvalue?(val)
						CExpression.new(val, :'--', nil, val.type)
					end
				when '+', '++'
					ntok = parser.skipspaces
					if tok.raw == '+' and ntok and ntok.type == :punct and ntok.raw == '+'
						tok.raw << ntok.raw
					else
						parser.unreadtok ntok
					end
					case tok.raw
					when '+'
						parser.unreadtok tok
						nil
					when '++'
						raise parser, "invalid lvalue #{val.inspect}" if not CExpression.lvalue?(val)
						CExpression.new(val, :'++', nil, val.type)
					end
				when '.'
					raise tok, 'invalid member' if not tok = parser.skipspaces or tok.type != :string
					type = val.type
					type = type.type while type.kind_of? TypeDef
					raise tok, 'invalid member' if not type.kind_of? Union or not type.members or not m = type.members.find { |m| m.name == tok.raw }
					CExpression.new(val, :'.', tok.raw, m.type)
				when '['
					raise tok, 'not a pointer' if not val.type.pointer?
					raise tok, 'bad index' if not idx = parse(parser, scope)
					raise tok, 'get perpendicular ! (elsewhere)' if idx.kind_of?(CExpression) and idx.op == :','
					raise tok || parser, '"]" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ']'
					type = val.type
					type = type.type while type.kind_of? TypeDef
					type = type.type
					# TODO boundscheck (and become king of the universe)
					CExpression.new(val, :'[]', idx, type)
				when '('
					type = val.type
					type = type.type while type.kind_of? TypeDef
					type = type.type if type.kind_of? Pointer
					type = type.type while type.kind_of? TypeDef
					raise tok, 'not a function' if not type.kind_of? Function

					list = parse(parser, scope)
					raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'

					args = []
					if list
						# XXX func((omg, owned))
						while list.kind_of? CExpression and list.op == :','
							args << list.lexpr
							list = list.rexpr
						end
						args << list
					end

					raise tok, "bad argument count: #{args.length} for #{type.args.length}" if (type.varargs ? (args.length < type.args.length) : (args.length != type.args.length))
					type.args.zip(args) { |ta, a| parser.check_compatible_type(tok, a, ta) }
					CExpression.new(val, :funcall, args, type.type)
				end
			end

			if nval
				parse_value_postfix(parser, scope, nval)
			else
				parser.unreadtok tok
				val
			end
		end

		def parse(parser, scope, allow_coma = true)
			opstack = []
			stack = []

			popstack = proc { 
				r, l = stack.pop, stack.pop
				case op = opstack.pop
				when :'?:'
					#parser.check_compatible_type(parser, l.type, r.type)
					ll = stack.pop
					stack << CExpression.new(ll, op, [l, r], l.type)
				when :','
					stack << CExpression.new(l, op, r, r.type)
				else
					raise parser, "invalid type #{l.inspect}" if not l.type.arithmetic?
					raise parser, "invalid type #{r.inspect}" if not r.type.arithmetic?

					if l.type.pointer? and r.type.pointer?
						raise parser, 'cannot do that on pointers' if op != :'-'
						type = BaseType.new(:long)	# addr_t or sumthin ?
					elsif l.type.pointer? or r.type.pointer?
						raise parser, 'cannot do that on pointer' if op != :'+' and op != :'-'
						type = l.type.pointer? ? l.type : r.type
					else
						# integer promotion
						# TODO
						type = r.type
					end
					stack << CExpression.new(l, op, r, type)
				end
			}

			return if not e = parse_value(parser, scope)

			stack << e

			while op = readop(parser)
				case op.value
				when :'?'
					# a, b ? c, d : e, f  ==  a, (b ? (c, d) : e), f
					until opstack.empty? or opstack.last == :','
						popstack[]
					end
					stack << parse(parser, scope)
					raise op || parser, '":" expected' if not op = readop(parser) or op.value != :':'
					op = op.dup
					op.value = :'?:'
				when :':'
					parser.unreadtok op
					break
				else
					if not allow_coma and op.value == :','
						parser.unreadtok op
						break
					end
					until opstack.empty? or OP_PRIO[op.value][opstack.last]
						popstack[]
					end
				end

				raise op, 'need rhs' if not e = parse_value(parser, scope)
				stack << e
				opstack << op.value
			end

			until opstack.empty?
				popstack[]
			end

			stack.first.kind_of?(CExpression) ? stack.first : CExpression.new(nil, nil, stack.first, stack.first.type)
		end
	end
	end

	# dumper: ruby objects => source
	def to_s
		r, dep = @toplevel.dump_inner
		r.join("\n")
	end

	class Block
		# return array of c source lines and array of dependencies (objects)
		def dump
			r, dep = dump_inner
			[['{'] + r.map { |s| "\t" + s } + ['}'], dep]
		end
		def dump_inner
			mydefs = @symbol.values + @struct.values
			# XXX struct a { int outer; };  {  struct b { struct a* outer; }; struct a { int inner; }; }
			todo = mydefs.map { |t| [t, t.dump(self)] }
			r = []
			dep = []
			loop do
				# reorder
				break if todo.empty?
				prelen = todo.length
				todo.find_all { |t, (tr, tdep)|
					((tdep & mydefs) - [t]).empty?
				}.each { |t, (tr, tdep)|
					r.concat tr
					dep |= (tdep - mydefs)
					todo.delete t
					todo.each { |ttr, ttdep| ttdep.delete t }
				}
				if todo.length == prelen
					# loop: predeclare needed structs
					# TODO
					# XXX struct foo; typedef struct foo *bla; struct foo { bla toto; };
					r << 'failure!'
					break
				end
			end

			@statements.each { |s|
				tr, tdep = s.dump(self)
				dep.concat(tdep - mydefs)
				r.concat tr
				case s
				when CExpression, Goto, Return, Break, Continue, Asm
					r.last << ';'
				end
			}
			[r, dep]
		end
	end
	class Variable
		# array of lines, array of dep
		def dump(scope)
			r = ['']
			r.last << @storage.to_s << ' ' if @storage

			decl = ['']
			decl.last << @name if @name

			t = type
			loop do
				# un-declaratorize
				case t
				when Array: decl.last << '[todo]'	# TODO
				when Pointer
					decl[0] = t.qualifier.map { |q| ' ' << q.to_s }.join << ' ' << decl[0] if t.qualifier
					decl[0] = '*' << decl[0]
					if t.type.kind_of? Function or t.type.kind_of? Array or (not @name and t.type.class != Pointer)
						decl[0] = '(' << decl[0]
						decl[-1] << ')'
					end
				when Function
					decl.last << '(todo)'
				else break
				end
				t = t.type
			end

			dep = []
			tr, tdep = t.dump(scope)
			dep.concat tdep
			r.last << tr.shift
			r.concat tr
			r.last << ' ' << decl.shift
			r.concat decl

			if @initializer
				case @type
				when Function

				else
					tr, tdep = @type.dump_initializer(scope, @initializer)
					dep.concat tdep
					r.last << ' = ' << tr.shift
					r.concat tr
				end
			end
			[r, dep]
		end
	end
	class Type
		def dump_initializer(scope, init)
			init.dump(scope)
		end
	end
	class BaseType
		def dump(scope)
			r = ''
			r << @qualifier.map { |q| q.to_s << ' ' }.join if @qualifier
			r << @specifier.to_s << ' ' if @specifier
			r <<
			case @name
			when :char, :short, :int, :long, :double, :float: @name.to_s
			when :longlong: 'long long'
			when :longdouble: 'long double'
			end
			[[r], []]
		end
	end
	class TypeDef
		def dump(scope)
			[[@name], [scope.symbol_ancestors[@name]]]
		end
	end
	class Union
		def dump(scope)
			if @name
				r = ''
				r << @qualifier.map { |q| q.to_s << ' ' }.join if @qualifier
				r << self.class.name.downcase << ' ' << @name
				[[r], [scope.struct_ancestors[@name]]]
			else
				dump_def(scope)
			end
		end

		def dump_def(scope)
			r = ['']
			dep = []
			r.last << @qualifier.map { |q| q.to_s << ' ' }.join if @qualifier
			r.last << self.class.name.downcase << ' '
			r.last << @name << ' ' if @name
			r.last << '{'
			@members.each { |m|
				tr, tdep = m.dump(scope)
				dep.concat tdep
				r.concat tr.map { |s| "\t" + s }
				r.last << ';'
			}
			r << '}'
			[r, dep]
		end

		def dump_initializer(scope, init)
			if init.kind_of? ::Array
				r = ['{']
				dep = []
				showname = false
				@members.zip(init) { |m, i|
					if not i
						showname = true
						next
					end
					if showname
						showname = false
						r << "\t.#{m.name} = "
					end
					tr, tdep = m.type.dump_initializer(scope, i)
					dep.concat tdep
					r.last << tr.shift
					r.concat tr
					r.last << ','
				}
				r.last[-1, 1] = '' if r.last[-1] == ?,
				r << '}'
				[r, dep]
			else super
			end
		end
	end
	class If
		def dump(scope)
			r = ['if (']
			dep = []
			tr, tdep = cond.dump(scope)
			dep.concat tdep
			r.last << tr.shift
			r.concat tr
			# if bthen.kind_of? Block
			tr, tdep = bthen.dump(scope)
			dep.concat tdep
			r.concat tr
			# if belse
		end
	end
	class CExpression
		def dump(scope)
			[[inspect], []]
		end
	end
end
end
