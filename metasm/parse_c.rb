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
		attr_accessor :statements	# array of CExpr/If../Continue../Goto/Label/Block

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

	class Variable
		attr_accessor :type
		attr_accessor :initializer	# CExpr	/ Block (for Functions)
		attr_accessor :name
		attr_accessor :attributes
		attr_accessor :storage		# auto register static extern typedef
		attr_accessor :backtrace	# definition backtrace info (the name token)
	end

	class Type
		attr_accessor :qualifier	# const volatile
		attr_accessor :attributes

		def pointer? ; false ; end
	end
	class BaseType < Type
		attr_accessor :name		# :int :long :longlong :short :double :longdouble :float :char :void
		attr_accessor :specifier	# sign specifier only

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

		def initialize(var)
			@name, @type, @backtrace = var.name, var.type, var.backtrace
		end

		def pointer? ; @type.pointer? ; end
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
				off += parser.sizeof(m.type)
				off = (off + @align - 1) / @align * @align
			}
			off
		end
	end
	class Enum < Type
		# name => value
		attr_accessor :values
	end
	class Pointer < Type
		attr_accessor :type

		def initialize(type=nil)
			@type = type
		end

		def pointer? ; true ; end
	end
	class ArrayType < Pointer
		# class name to avoid conflict with ruby's ::Array
		attr_accessor :length
	end

	class If < Statement
		attr_accessor :test		# expression
		attr_accessor :bthen, :belse	# statements
		def initialize(test, bthen, belse=nil)
			@test = test
			@bthen = bthen
			@belse = belse if belse
		end
	end
	class For < Statement
		attr_accessor :init, :test, :iter	# expressions, init may be Block
		attr_accessor :body
		def initialize(init, test, iter, body)
			@init, @test, @iter, @body = init, test, iter, body
		end
	end
	class While < Statement
		attr_accessor :test
		attr_accessor :body

		def initialize(test, body)
			@test = test
			@body = body
		end
	end
	class DoWhile < While
	end
	class Switch < Statement
		attr_accessor :test, :body

		def initialize(test, body)
			@test = test
			@body = body
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
		attr_accessor :expr, :exprup	# exprup if range
		def initialize(expr, exprup, statement)
			@expr, @statement = expr, statement
			@exprup = exprup if exprup
		end
	end

	class Asm < Statement
		attr_accessor :body, :other	# quoted string, array of qstring
		def initialize(body, other)
			@body, @other = body, other
		end
	end

	class CExpression < Statement
		# op may be :,, :., :->, :funcall (function, [arglist]), :[] (array indexing)
		attr_accessor :op
		# may be nil/Variable/String( = :quoted)/Integer/Float
		attr_accessor :lexpr, :rexpr
		# a Type
		attr_accessor :type
		def initialize(l, o, r, t)
			@lexpr, @op, @rexpr, @type = l, o, r, type
		end
	end

	# creates a new CParser, parses all top-level statements
	def self.parse(text, file='unknown', lineno=1)
		c = new
		c.lexer.feed text, file, lineno
		nil while not c.lexer.eos? and c.parse_definition(c.toplevel)
		raise c.lexer.readtok || self, 'EOF expected' if not c.lexer.eos?
		c.sanity_checks
		c
	end

	attr_accessor :lexer, :toplevel, :typesize
	def initialize(lexer = nil, model=:ilp32)
		@lexer = lexer || Preprocessor.new
		@lexer.feed <<EOS
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
	#  toplevel initializers are constants (including struct members and bit length)
	#  array lengthes are constant at toplevel
	#  no variable is of type :void
	#  all Case are in Switch, Goto target exists, Continue/Break are placed correctly
	#  etc..
	def sanity_checks
		return if not $VERBOSE
		#  TODO
	end

	# checks that the types are compatible (variable predeclaration, function argument..)
	# strict = false => old char is compatible with new int (eg function call, assignment)
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
					# don't care
					#if om.name and nm.name and om.name != nm.name
					#	raise tok, 'incompatible type'
					#end
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
				# check int/float mix
				raise tok, 'incompatible type' if ([:char, :int, :short, :long, :longlong] & [oldtype.name, newtype.name]).length == 1
				# check int size/sign
				raise tok, 'incompatible type' if @typesize[oldtype.name] > @typesize[newtype.name]
				puts tok.exception('sign mismatch').message if $VERBOSE and oldtype.specifier != newtype.specifier and @typesize[newtype.name] == @typesize[oldtype.name]
			end
		end
	end

	Reserved = %w[struct union enum  if else for while do switch goto
			register extern auto static typedef  const volatile
			void int float double char  signed unsigned long short
			case continue break return  __attribute__
	].inject({}) { |h, w| h.update w => true }
	# TODO asm, probably others

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
			t = readtok_longstr
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
	def sizeof(type)
		case type
		when ArrayType
			raise self, 'unknown array size' if not type.length or not type.length.kind_of? Integer
			type.length * sizeof(type.type)
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
			type.members.map { |m| (sizeof(m.type) + type.align - 1) / type.align * type.align }.inject(0) { |a, b| a+b }
		when Union
			raise self, 'unknown structure size' if not type.members
			type.members.map { |m| sizeof(m.type) }.max || 0
		when TypeDef
			sizeof(type.type)
		end
	end

	# parses variable/function definition/declaration/initialization
	# populates scope.symbols and scope.struct
	# raises on redefinitions
	# returns false if no definition found
	def parse_definition(scope)
		basetype = Variable.new
		parse_type(scope, basetype, true)
		return false if not basetype.type

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
			parse_declarator(scope, var)

			raise self if not var.name	# barrel roll

			if prev = scope.symbol[var.name] and (
					not scope.symbol[var.name].kind_of?(Variable) or
					scope.symbol[var.name].initializer)
				raise var.backtrace, 'redefinition'
			elsif var.storage == :typedef
				var = TypeDef.new var
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
				body = var.initializer = Block.new scope
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
						body.statements << parse_statement(body)
					end
				end
				break
			when '='
				# variable initialization
				raise tok, '"{" or ";" expected' if var.type.kind_of? Function
				raise tok, 'cannot initialize extern variable' if var.storage == :extern
				var.initializer = parse_initializer(scope, var.type)
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

	# returns a variable initializer (including array/struct)
	def parse_initializer(scope, type)
		case type
		when ArrayType
			if tok = skipspaces and tok.type == :quoted
				unreadtok tok
				raise tok if not ret = CExpression.parse(self, scope, false)
				type.length ||= ret.rexpr if not ret.op
				check_compatible_type(tok, ret.type, type)
			elsif tok and tok.type == :punct and tok.raw == '{'
				# int foo[] = { 1, 2, 3 };
				ret = []
				if tok = skipspaces and (tok.type != :punct or tok.raw != '}')
					unreadtok tok
					loop do
						ret << parse_initializer(scope, type.type)
						raise tok || self if not tok = skipspaces or tok.type != :punct or (tok.raw != '}' and tok.raw != ',')
						break if tok.raw == '}'
					end
				end
				type.length ||= ret.length
				raise self, 'initializer too long' if type.length.kind_of? Integer and type.length < ret.length
			else
				raise tok || self, 'bad initializer'
			end
			ret
		when Union
			if tok = skipspaces and tok.type == :string
				# struct toto = preexistinginstance;
				raise tok, 'bad initializer' if not ret = scope.symbol_ancestors[tok.raw] or not ret.kind_of? Variable
				check_compatible_type(tok, ret.type, type)
			elsif tok and tok.type == :punct and tok.raw == '{'
				# struct x toto = { 1, .4, .member = 12 };
				raise tok, 'undefined struct' if not type.members
				ret = []
				if tok = skipspaces and (tok.type != :punct or tok.raw != '}')
					unreadtok tok
					idx = -1
					loop do
						nt = nnt = nnnt = nil
						if nt = skipspaces and   nt.type == :punct  and   nt.raw == '.' and
						  nnt = skipspaces and  nnt.type == :string and
						 nnnt = skipspaces and nnnt.type == :punct  and nnnt.raw == '='
							raise nnt, 'invalid member' if not idx = type.members.index(type.members.find { |m| m.name == nnt.raw })
						else
							unreadtok nnntok
							unreadtok nntok
							unreadtok ntok
							idx += 1
						end

						ret[idx] = parse_initializer(scope, members[idx].type)
						raise tok || self, '"," or "}" expected' if not tok = skipspaces or tok.type != :punct or (tok.raw != '}' and tok.raw != ',')
						break if tok.raw == '}'
					end
				end
			else
				raise tok || self, 'bad initializer'
			end
			ret
		else
			# XXX gcc accepts int i={1}; (but not int i={{1}}; or struct {int foo;} i={{1}};)
			raise self, 'initializer expected' if not ret = CExpression.parse(self, scope, false)
			check_compatible_type(tok, ret.type, type)
		end
	end

	# parses var basetype/qualifier/storage
	def parse_type(scope, var, allow_value)
		qualifier = []
		loop do
			break if not tok = skipspaces
			if tok.type != :string
				unreadtok tok
				break
			end

			case tok.raw
			when 'const', 'volatile'
				qualifier << tok.raw.to_sym
				next
			when 'register', 'auto', 'static', 'typedef', 'extern'
				raise tok, 'storage specifier not allowed here' if not allow_value
				var.storage = tok.raw.to_sym
				next
			when 'struct'
				var.type = Struct.new
				var.type.align = @lexer.pragma_pack
				parse_type_unionstruct(scope, var)
			when 'union'
				var.type = Union.new
				parse_type_unionstruct(scope, var)
			when 'enum'
				var.type = Enum.new
				parse_type_enum(scope, var)
			when 'long', 'short', 'signed', 'unsigned', 'int', 'char', 'float', 'double', 'void'
				specifier = []
				name = :int
				loop do
					case tok.raw
					when 'const', 'volatile'
						qualifier << tok.raw.to_sym
					when 'long', 'short', 'signed', 'unsigned'
						specifier << tok.raw.to_sym
					when 'int', 'char', 'void', 'float', 'double'
						name = tok.raw.to_sym
						break
					else
						unreadtok tok
						break
					end
					if not tok = skipspaces or tok.type != :string
						unreadtok tok
						break
					end
				end

				case name
				when :double	# long double
					if specifier == [:long]
						name = :longdouble
						specifier.clear
					elsif not specifier.empty?
						raise tok || self, 'invalid specifier list'
					end
				when :int	# short, long, long long X signed, unsigned
					specifier = specifier - [:long] + [:longlong] if (specifier & [:long]).length == 2
					if (specifier & [:signed, :unsigned]).length > 1 or (specifier & [:short, :long, :longlong]).length > 1
						raise tok || self, 'invalid specifier list'
					else
						name = (specifier & [:longlong, :long, :short]).first || :int
						specifier -= [:longlong, :long, :short]
					end
					specifier.delete :signed	# default specifier
				when :char	# signed, unsigned
					# signed char != char and unsigned char != char
					if (specifier & [:signed, :unsigned]).length > 1 or (specifier & [:short, :long]).length > 0
						raise tok || self, 'invalid specifier list'
					end
				else		# none
					raise tok || self, 'invalid specifier list' if not specifier.empty?
				end

				var.type = BaseType.new(name, *specifier)

			else
				if type = scope.symbol_ancestors[tok.raw] and type.kind_of? TypeDef
					var.type = type
				else
					unreadtok tok
				end
			end

			break
		end

		if not var.type
			raise self, 'bad type name' if not qualifier.empty? or var.storage
			return
		end

		var.type.qualifier = qualifier if not qualifier.empty?

		parse_attribute(var.type = var.type.dup) while if tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'
		unreadtok tok
	end

	# updates var.type and var.name, parses pointer/arrays/function declarations
	# parses anonymous declarators (var.name will be false)
	# the caller is responsible for detecting redefinitions
	# scope used only in CExpression.parse for array sizes and function prototype argument types
	def parse_declarator(scope, var)
		return if not tok = skipspaces
		# read upto name
		if tok.type == :punct and tok.raw == '*'
			ptr = Pointer.new

			parse_attribute(ptr) while tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'
			unreadtok tok

			parse_declarator(scope, var)
			t = var
			t = t.type while t.type and (t.type.kind_of?(Pointer) or t.type.kind_of?(Function))
			ptr.type = t.type
			t.type = ptr
			return
		elsif tok.type == :punct and tok.raw == '('
			parse_declarator(scope, var)
			raise self, '")" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ')'
		elsif tok.type == :string
			raise tok if var.name or var.name == false
			raise tok, 'bad var name' if Reserved[tok.raw]
			var.name = tok.raw
			var.backtrace = tok
		else
			# unnamed
			raise tok if var.name or var.name == false
			var.name = false
			var.backtrace = tok
			unreadtok tok
		end

		nil while parse_declarator_postfix(scope, var)
	end

	# parses array/function type
	def parse_declarator_postfix(scope, var)
		if tok = skipspaces and tok.type == :punct and tok.raw == '['
			# array indexing
			t = var
			t = t.type while t.type and (t.type.kind_of?(Pointer) or t.type.kind_of?(Function))
			t.type = ArrayType.new t.type
			t.type.length = CExpression.parse(self, scope)	# may be nil
			raise self, '"]" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ']'
		elsif tok and tok.type == :punct and tok.raw == '('
			# function prototype
			t = var
			t = t.type while t.type and (t.type.kind_of?(Pointer) or t.type.kind_of?(Function))
			t.type = Function.new t.type
			if not tok = skipspaces or tok.type != :punct or tok.raw != ')'
				unreadtok tok
				t.type.args = []
				loop do
					v = Variable.new
					raise self if not tok = skipspace
					if tok.type == :punct and tok.raw == '.'	# variadic function
						raise self, '"..." expected' if not tok = skipspaces or tok.type != :punct or tok.raw != '.'
						raise self, '"..." expected' if not tok = skipspaces or tok.type != :punct or tok.raw != '.'
						raise self, '")" expected'   if not tok = skipspaces or tok.type != :punct or tok.raw != ')'
						t.type.varargs = true
						break
					elsif tok.type == :string and tok.raw == 'register'
						v.storage = tok.raw.to_sym
					else
						unreadtok tok
					end

					parse_type(scope, v, false)
					raise tok if not v.type
					parse_declarator(scope, v)
					parse_attribute(v) while tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'

					args << v if not v.type.kind_of? BaseType or v.type.name != :void
					if tok and tok.type == :punct and tok.raw == ','
						raise self if args.last != v		# last arg of type :void
					elsif tok and tok.type == :punct and tok.raw == ')'
						break
					else raise tok || self, '"," or ")" expected'
					end
				end
			end
			parse_attribute(var.type) while tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'
			unreadtok tok
		else
			unreadtok tok
			return false
		end
		true
	end

	# parses __attribute__((anything)) into obj.attributes (array of strings)
	def parse_attribute(obj)
		raise self if not tok = skipspaces or tok.type != :punct or tok.type != '('
		raise self if not tok = skipspaces or tok.type != :punct or tok.type != '('
		nest = 0
		attrib = ''
		loop do
			raise self if not tok = skipspaces
			if tok.type == :punct and tok.raw == ')'
				if nest == 0
					raise tok || self if not tok = skipspaces or tok.type != :punct or tok.raw != ')'
					break
				else
					nest -= 1
				end
			elsif tok.type == :punct and tok.raw == '('
				nest += 1
			end
			attrib << tok.raw
		end
		(obj.attributes ||= []) << attrib
	end

	# parses a structure/union declaration
	def parse_type_unionstruct(scope, var)
		if tok = skipspaces and tok.type == :punct and tok.raw == '{'
			# anonymous struct, ok
			var.type.backtrace = tok
		elsif tok and tok.type == :string
			name = tok.raw
			raise tok, 'bad struct name' if Reserved[name]
			parse_attribute(var.type) while ntok = skipspaces and ntok.type == :string and ntok.raw == '__attribute__'
			raise self if not ntok
			if ntok.type != :punct or ntok.raw != '{'
				# variable declaration
				unreadtok ntok
				if ntok.type == :punct and ntok.raw == ';'
					# struct predeclaration
					# allow redefinition
					scope.struct[name] ||= var.type
				else
					# check that the structure exists
					# do not check it is declared (may be a pointer, check in declarator)
					struct = scope.struct_ancestors[name]
					raise tok, 'undeclared struct' if not struct
					(struct.attributes ||= []).concat var.type.attributes if var.type.attributes
					var.type = struct
				end
				return
			end
			raise tok, 'struct redefinition' if scope.struct[name] and scope.struct[name].members
			scope.struct[name] = var.type
			var.type.backtrace = tok
		else
			raise tok || self, 'struct name or "{" expected'
		end

		var.type.members = []
		# parse struct/union members in definition
		loop do
			raise self if not tok = skipspaces
			break if tok.type == :punct and tok.raw == '}'
			unreadtok tok

			basetype = Variable.new
			parse_type(scope, basetype, false)
			raise self if not basetype.type
			loop do
				member = basetype.dup
				parse_declarator(scope, member)
				# raise self if not member.name	# can be useful while hacking: struct foo {int; int*; int iwant;};
				parse_attribute(member) while tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'
				raise self, 'member redefinition' if member.name and var.type.members.find { |m| m.name == member.name }
				var.type.members << member

				raise self if not tok or tok.type != :punct

				if tok.raw == ':'	# bits
					raise self if not bits = CExpression.parse(self, scope) or not bits = bits.reduce
					(var.type.bits ||= {})[member.name] = bits if member.name
					raise self if not tok = skipspaces or tok.type != :punct
				end

				case tok.raw
				when ';': break
				when ','
				else raise tok, '"," or ";" expected'
				end
			end
		end
		parse_attribute(var.type) while tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'
		unreadtok tok

		if var.type.kind_of? Struct and var.type.attributes and var.type.attributes.include? 'packed'
			var.type.align = 1
		end
	end

	def parse_enum(scope, var)
		if tok = skipspaces and tok.type == :punct and tok.raw == '{'
			# ok
		elsif tok and tok.type == :string
			# enum name
			name = tok.raw
			raise tok, 'bad enum name' if Reserved[name]
			parse_attribute(var.type) while ntok = skipspaces and ntok.type == :string and ntok.raw == '__attribute__'
			raise self if not ntok
			if ntok.type != :punct or ntok.raw != '{'
				unreadtok ntok
				if ntok.type == :punct and ntok.raw == ';'
					# predeclaration
					# allow redefinition
					scope.enum[name] ||= var.type
				else
					# check that the enum exists
					enum = scope.symbol_ancestors[name]
					raise tok, 'undeclared enum' if not enum or not enum.kind_of? Enum
					(enum.attributes ||= []).concat var.type.attributes if var.type.attributes
					var.type = enum
				end
				return
			end
			raise tok, 'enum redefinition' if scope.enum[name] and scope.enum[name].values
			scope.enum[name] = var.type
			var.type.backtrace = tok
		else
			raise tok, 'enum name expected'
		end

		val = -1
		loop do
			raise self if not tok = skipspaces
			break if tok.type == :punct and tok.raw == '}'

			raise tok if tok.type != :string or Reserved[tok.raw]
			name = tok.raw
			raise tok, 'enum value redefinition' if scope.symbol[name]

			raise self if not tok = skipspaces
			if tok.type == :punct and tok.raw == '='
				raise tok || self if not val = CExpression.parse(self, scope) or not val = val.reduce or not tok = skipspaces
			else
				val += 1
			end
			(var.type.values ||= {})[name] = val
			scope.symbol[name] = val

			if tok.type == :punct and tok.raw == '}'
				break
			elsif tok.type == :punct and tok.raw == ','
			else raise tok
			end
		end
		parse_attribute(var.type) while tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'
		unreadtok tok
	end

	# returns a statement or raise
	def parse_statement(scope)
		raise self, 'statement expected' if not tok = skipspaces
		if tok.type == :punct and tok.raw == '{'
			body = Block.new scope
			loop do
				raise tok || self, '"}" expected' if not tok = skipspaces
				break if tok.type == :punct and tok.raw == '}'
				unskipspaces tok
				if not parse_definition(body)
					body.statements << parse_statement(body)
				end
			end
			return body
		elsif tok.type != :string
			unskipspaces tok
			expr = CExpression.parse(self, scope)
			raise tok || self, '";" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ';'
			return expr
		end

		case tok.raw
		when 'if'
			raise tok || self, '"(" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != '('
			raise tok, 'expr expected' if not expr = CExpression.parse(self, scope)
			raise tok || self, '")" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ')'
			bthen = parse_statement scope
			if tok = skipspaces and tok.type == :string and tok.raw == 'else'
				belse = parse_statement scope
			else
				unskipspaces tok
			end
			If.new expr, bthen, belse
		when 'switch'
			raise tok || self, '"(" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != '('
			raise tok, 'expr expected' if not expr = CExpression.parse(self, scope)
			raise tok || self, '")" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ')'
			body = parse_statement scope
			Switch.new expr, body
		when 'case'
			# case 1: case 4...6:
			raise tok if not expr = CExpression.parse(self, scope)
			raise tok || self, '":" or "..." expected' if not tok = skipspaces or tok.type != :punct or (tok.raw != ':' and tok.raw != '.')
			if tok.raw == '.'
				raise tok || self, '".." expected' if not tok = skipspaces or tok.type != :punct or tok.raw != '.'
				raise tok || self,  '"." expected' if not tok = skipspaces or tok.type != :punct or tok.raw != '.'
				raise tok if not exprup = CExpression.parse(self, scope)
				raise tok || self, '":" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ':'
			end
			body = parse_statement scope
			Case.new expr, exprup, body
		when 'while'
			raise tok || self, '"(" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != '('
			raise tok, 'expr expected' if not expr = CExpression.parse(self, scope)
			raise tok || self, '")" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ')'
			body = parse_statement scope
			While.new expr, body
		when 'do'
			body = parse_statement scope
			raise tok || self, '"while" expected' if not tok = skipspaces or tok.type != :string or tok.raw != 'while'
			raise tok || self, '"(" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != '('
			raise tok, 'expr expected' if not expr = CExpression.parse(self, scope)
			raise tok || self, '")" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ')'
			DoWhile.new expr, body
		when 'for'
			raise tok || self, '"(" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != '('
			init = forscope = Block.new
			if not parse_definition(forscope)
				forscope = scope
				raise tok, 'expr expected' if not init = CExpression.parse(self, forscope)
				raise tok || self, '";" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ';'
			end
			raise tok, 'expr expected' if not test = CExpression.parse(self, forscope)
			raise tok || self, '";" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ';'
			raise tok, 'expr expected' if not iter = CExpression.parse(self, forscope)
			raise tok || self, '")" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ')'
			body = parse_statement forscope
			For.new init, test, iter, body
		when 'goto'
			raise tok || self, 'label expected' if not tok = skipspaces or tok.type != :string
			name = tok.raw
			raise tok || self, '";" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ';'
			Goto.new name
		when 'return'
			expr = CExpression.parse self, scope	# nil allowed
			raise tok || self, '";" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ';'
			Return.new expr
		when 'continue'
			raise tok || self, '";" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ';'
			Continue.new
		when 'break'
			raise tok || self, '";" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ';'
			Break.new
		when 'asm', '__asm', '__asm__'
			tok = skipspaces
			if tok and tok.type == :string and (tok.raw == 'volatile' or tok.raw == '__volatile__')
				volatile = true
				tok = skipspaces
			end
			body = []
			loop do
				raise tok || self, 'qstring expected' if not tok = skipspaces or tok.type != :quoted
				body << tok
				raise tok || self, '":" or ")" expected' if not tok = skipspaces or tok.type != :punct or (tok.raw != ':' and tok.raw != ')')
				break if tok.raw == ')'
			end
			Asm.new body.shift, body
		else
			if ntok = skipspaces and ntok.type == :punct and ntok.raw == ':'
				Label.new tok.raw, parse_statement(scope)
			else
				unreadtok ntok
				unreadtok tok
				expr = CExpression.parse self, scope
				raise tok || self, '";" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ';'
				expr
			end
		end
	end

	class CExpression
		def is_lvalue
			true
		end

		def is_constant
		end

		def reduce
		end

		def walk
			yield @lexpr
			yield @rexpr
		end

	class << self
		RIGHTASSOC = [:'=', :'+=', :'-=', :'*=', :'/=', :'%=', :'&=',
			:'|=', :'^=', :'<<=', :'>>=', :'?:'
		].inject({}) { |h, op| h.update op => true }

		# key = operator, value = hash regrouping operators of lower precedence
		# funcall/array index/member dereference/sizeof are handled in parse_expr
		OP_PRIO = [[:','], [:'?'], [:'=', :'+=', :'-=', :'*=', :'/=',
			:'%=', :'&=', :'|=', :'^=', :'<<=', :'>>='], [:'||'],
			[:'&&'], [:|], [:^], [:&], [:'==', :'!='],
			[:'<', :'>', :'<=', :'>='], [:<<, :>>], [:+, :-],
			[:*, :/, :%], ].inject({}) { |h, oplist|
				lessprio = h.keys.inject({}) { |hh, op| hh.update op => true }
				oplist.each { |op| lessprio.update op => true } if RIGHTASSOC[oplist.first]
				oplist.each { |op| h[op] = lessprio }
				h }

		# reads a binary operator from the parser, returns the corresponding symbol or nil
		def readop(parser, allowcoma=true)
			if not tok = parser.readtok or tok.type != :punct
				parser.unreadtok tok
				return
			end

			op = tok
			case op.raw
			# << >> || &&
			when '>', '<', '|', '&'
				if ntok = parser.readtok and ntok.type == :punct and ntok.raw == op.raw
					op.raw << parser.readtok.raw
				else
					parser.unreadtok ntok
				end
			# != (mandatory)
			when '!'
				if not ntok = parser.nexttok or ntok.type != :punct and ntok.raw != '='
					parser.unreadtok tok
					return
				end
				op.raw << parser.readtok.raw
			when '+', '-', '*', '/', '%', '^', '=', '&', '|', ',', '?', ':'
				# ok
			else
				# bad
				parser.unreadtok tok
				return
			end

			# may be followed by '='
			case tok.raw
			when '+', '-', '*', '/', '%', '^', '&', '|', '>>', '<<', '<', '>', '='
				if ntok = parser.nexttok and ntok.type == :punct and ntok.raw == '='
					op.raw << parser.readtok.raw
				else
					parser.unreadtok ntok
				end
			end

			op.value = op.raw.to_sym
			op
		end

		# parse sizeof offsetof etc
		def parse_intfloat(parser, scope, tok)
			if tok.type == :string and not tok.value
				case tok.raw
				when 'sizeof'
					if ntok = parser.skipspaces and ntok.type == :punct and ntok.raw == '('
						# check type
						v = Variable.new
						parser.parse_type(scope, v, false)
						if v.type
							parser.parse_declarator(scope, v)
							raise tok if v.name != false
							raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'
						end
					else
						parser.unreadtok ntok
						v = parse_expr(parser, scope)
					end
					tok.value = parser.sizeof(v)
					return
				when '__builtin_offsetof'
					raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != '('
					raise tok if not ntok = parser.skipspaces or ntok.type != :string or ntok.raw != 'struct'
					raise tok if not ntok = parser.skipspaces or ntok.type != :string
					raise tok, 'unknown structure' if not struct = scope.struct_ancestors[ntok.raw] or not struct.members
					raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ','
					raise tok if not ntok = parser.skipspaces or ntok.type != :string
					tok.value = struct.offsetof(parser, ntok.raw)
					raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'
					return
				end
			end

			Expression.parse_num_value(parser, tok)	# TODO add type
		end

		def parse_lvalue(parser, scope)
			v = parse_value
			raise parser, "invalid lvalue #{v.inspect}" if not v or not v.is_lvalue
			v
		end

		# returns the next value from parser (parenthesised expression, immediate, variable, unary operators)
		def parse_value(parser, scope)
			return if not tok = parser.skipspaces
			case tok.type
			when :string
				parse_intfloat(parser, scope, tok)
				val = tok.value || tok.raw
				if val.kind_of? String
					raise tok, 'undefined variable' if not val = scope.symbol_ancestors[val]
				end
				case val
				when Type
					raise tok, 'invalid variable'
				when Variable
					val = parse_value_postfix(parser, scope, val)
				when Float
					# parse suffix
					type = :double
					if (?0..?9).include?(tok.raw[0])
						case tok.raw.downcase[-1]
						when ?l: type = :longdouble
						when ?f: type = :float
						end
					end
					val = CExpression.new(nil, nil, val, BaseType.new(type))

				when Integer
					type = :int
					specifier = []
					if (?0..?9).include?(tok.raw[0])
						specifier << :unsigned if tok.raw.downcase[-3, 3].include?('u') # XXX or tok.raw.downcase[1] == ?x
						type = :longlong if tok.raw.downcase[-3, 3].count('l') == 2
						type = :long if tok.raw.downcase[-3, 3].count('l') == 1
					end
					val = CExpression.new(nil, nil, val, BaseType.new(type, *specifier))
				end

			when :quoted
				if tok.raw[0] == ?'
					raise tok, 'invalid character constant' if tok.value.length > 1
					val = CExpression.new(nil, nil, tok.value[0], BaseType.new(:int))
				else
					val = CExpression.new(nil, nil, tok.value, BaseType.new(tok.raw[0, 1] == 'L"' ? :short : :int))
					val = parse_value_postfix(parser, scope, val)
				end

			when :punct
				case tok.raw
				when '('
					# cast ?
					v = Variable.new
					parser.parse_type(scope, v, false)
					if v.type
						parser.parse_declarator(scope, v)
						raise tok, 'bad cast' if v.name != false
						raise tok, 'no matching ")" found' if not ntok = parser.readtok or ntok.type != :punct or ntok.raw != ')'
						raise ntok, 'expression expected' if not val = parse_expr(parser, scope)
						# postfix already parsed by parse_expr
						val = CExpression.new(nil, nil, val, v.type)
					else
						if not val = parse(parser, scope)
							parser.unreadtok tok
							return
						end
						raise ntok || tok, 'no matching ")" found' if not ntok = parser.readtok or ntok.type != :punct or ntok.raw != ')'
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

				when '+', '-', '&', '!', '~', '*'
					# unary prefix
					
					raise parser if not ntok = parser.readtok
					# check for -- ++ &&
					if ntok.type == :punct and ntok.raw == tok.raw and %w[+ - &].include?(tok.raw)
						tok.raw << ntok.raw
					else
						parser.unreadtok ntok
					end

					case tok.raw
					when '&'
						raise tok, 'lexpr expected' if not val = parse_lexpr(parser, scope)
						val = CExpression.new(nil, tok.raw.to_sym, val, Pointer.new(val.type))
					when '++', '--'
						raise tok, 'lexpr expected' if not val = parse_lexpr(parser, scope)
						val = CExpression.new(nil, tok.raw.to_sym, val, val.type)
					when '&&'
						raise tok, 'label name expected' if not val = lexer.skipspaces or val.type != :string
						raise parser, 'GCC address of label unhandled'	# TODO
					when '*'
						raise tok, 'expr expected' if not val = parse_expr(parser, scope)
						raise tok, 'not a pointer' if not val.type.pointer?	# TODO typedef
						val = CExpression.new(nil, tok.raw.to_sym, val, val.type.type)
					when '~', '!', '+', '-'
						raise tok, 'expr expected' if not val = parse_expr(parser, scope)
						# check arithmetic
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
				when '-'	# -> --
					ntok = parser.skipspace
					if ntok and ntok.type == :punct and (ntok.raw == '-' or ntok.raw == '>')
						tok.raw << ntok.raw
						if tok.raw == '->'
							rexpr = parser.skipspaces
							# check val type + rexpr == member
							raise parser if not rexpr or rexpr.type != :string
						else
							raise parser, "invalid lvalue #{val.inspect}" if not val.is_lvalue
						end
						CExpression[val, tok.raw.to_sym, rexpr]
					else
						parser.unreadtok ntok
						parser.unreadtok tok
						nil
					end
				when '+'	# ++
					ntok = parser.skipspace
					if ntok and ntok.type == :punct and ntok.raw == '+'
						tok.raw << ntok.raw
						CExpression[val, tok.raw.to_sym, nil]
					else
						parser.unreadtok ntok
						parser.unreadtok tok
						nil
					end
				when '.'
					raise rexpr || parser if not rexpr = parse.skipspaces or rexpr.type != :string
					# check val type + rexpr == member
					m = val.type.members.find { |m| m.name == rexpr.raw }
					raise rexpr if not m
					CExpression.new(val, tok.raw.to_sym, rexpr.raw, m.type)

				when '['
					idx = parse(parser, scope)
					raise tok if not idx or not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ']'
					# check val & idx type
					CExpression.new(val, :'[]', idx, val.type.type)

				when '('
					list = parse(parser, scope)
					raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'

					args = []
					if list
						while list.kind_of? CExpression and list.op == :','
							args << list.lexpr
							list = list.rexpr
						end
						args << list
					end
					# check val type + arg count & type
					type = val.kind_of?(Pointer) ? val.type.type : val.type	# typedef ?
					CExpression.new(val, :funcall, args, type)
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

			return if not e = parse_value(parser, scope)

			stack << e

			while op = readop(parser)
				case op.value
				when :'?'
					tru = parse(parser, scope)
					raise if not nop = readop(parse) or nop.value != :':'
					parse_lexpr
				when :':'
					break
				else
					break if op.value == ',' and not allow_coma
					until opstack.empty? or OP_PRIO[op.value][opstack.last]
						l, r = stack.pop, stack.pop
						stack << CExpression.new(l, opstack.pop, r, kikoo)
					end
					opstack << op.value
					raise op, 'need rhs' if not e = parse_value(parser)
					stack << e
					opstack << op.value
				end
			end

			until opstack.empty?
				l, r = stack.pop, stack.pop
				stack << CExpression.new(l, opstack.pop, r, kikoo)
			end

			stack.first.kind_of?(CExpression) ? stack.first : CExpression.new(nil, nil, stack.first, stack.first.type)
		end
	end
	end
end
end
