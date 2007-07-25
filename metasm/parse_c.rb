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
	class Block
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
		attr_accessor :name		# 'int' 'long' 'long long' 'short' 'double' 'long double' 'float' 'char' 'void'
		attr_accessor :specifier	# sign specifier only

		def initialize(name, *specs)
			@name = name
			specs.each { |s|
				case s
				when :const, :volatile: (@qualifier ||= []) << s
				when :signed, :unsigned: @specifier = s
				end
			}
		end
	end
	class TypeDef < Type
		attr_accessor :name
		attr_accessor :type

		def initialize(var)
			@name, @type = var.name, var.type
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
	class Array < Pointer
		attr_accessor :length
	end

	class If
		# expression
		attr_accessor :test
		# blocks
		attr_accessor :then, :else
	end
	class For
		# expressions
		attr_accessor :init, :test, :iter
		attr_accessor :scope, :body
		# scope used for init
	end
	class While
		attr_accessor :test
		attr_accessor :body
	end
	class DoWhile < While
	end
	class Switch
		attr_accessor :test, :body
	end

	class Continue
	end
	class Break
	end
	class Goto
		attr_accessor :target
	end
	class Return
		# CExpr
		attr_accessor :value
	end
	class Label
		attr_accessor :name
	end
	class Case
		attr_accessor :case
	end

	class CExpression
		# op may be :,, :., :->, :() (function, [arglist]), :[] (array indexing)
		attr_accessor :lexpr, :op, :rexpr, :type
		def initialize(l, o, r, t)
			@lexpr, @op, @rexpr, @type = l, o, r, type
		end
	end

	# creates a new CParser, parses all top-level statements
	def self.parse(text, file='unknown', lineno=1)
		c = new
		c.lexer.feed text, file, lineno
		nil while not c.lexer.eos? and c.parse_definition(c.toplevel)
		raise self, 'EOF expected' if not c.lexer.eos?
		c.sanity_checks
		c
	end

	attr_accessor :lexer, :toplevel
	def initialize
		@lexer = Preprocessor.new(self)
		@toplevel = Block.new(nil)
		@unreadtoks = []
	end

	# C sanity checks
	#  typedef are not initialized
	#  no addr of register-class variable is taken
	#  toplevel initializers are constants (including struct members and bit length)
	#  array lengthes are constant on toplevel
	#  no variable is of type 'void'
	#  etc
	#  TODO
	def sanity_checks
		return if not $VERBOSE
	end

	# checks that the types are compatible for the same variable
	def check_compatible_type(tok, oldtype, newtype)
		if newtype.kind_of? Function
			raise tok, 'incompatible type' if not oldtype.kind_of? Function
			check_compatible_type(tok, oldtype.type, newtype.type)
			if oldtype.args and newtype.args
				raise tok, 'incompatible type' if oldtype.args.length != newtype.args.length or oldtype.varargs != newtype.varargs
				oldtype.args.zip(newtype.args) { |oa, na| check_compatible_type tok, oa, na }
			end
		else
			# TODO
		end
	end

	Reserved = %w[struct union enum  if else for while do switch goto
			register extern auto static typedef  const volatile
			void int float double char  signed unsigned long short
			case continue break return  __attribute__
	].inject({}) { |h, w| h.update w => true }

	# allows 'raise self'
	def exception(msg='EOF unexpected')
		raise @lexer, msg
	end

	# reads a token from self.lexer
	# concatenates strings, merges spaces/eol to ' '
	def readtok
		if not t = @unreadtoks.pop
			t = @lexer.readtok
			case t.type
			when :space, :eol
				t = t.dup
				t.type = :space
				t.raw = ' '
				nil while nt = @lexer.readtok and (nt.type == :eol or nt.type == :space)
				@lexer.unreadtok nt
			when :quoted
				t = t.dup
				while nt = @lexer.readtok and nt.type == :quoted
					t.raw << ' ' << nt.raw
					t.value << nt.value
				end
				@lexer.unreadtok nt
			end
		end
		t
	end

	def unreadtok(tok)
		@unreadtoks << tok
	end

	# returns the next non-space/non-eol token
	def skipspaces
		t = readtok if t = readtok and t.type == :space
		t
	end

	def sizeof(type)
		case type
		when Array
			type.length * sizeof(type.type)
		when Pointer
		when Function
		when BaseType
		when Enum
		when Struct
		when Union
		when TypeDef
			sizeof(type.type)
		end or raise self, 'TODO sizeof'	# TODO
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

			raise var.backtrace, 'redefinition' if prev = scope.symbol[var.name] and (not scope.symbol[var.name].kind_of?(Variable) or scope.symbol[var.name].initializer)
			if var.storage == :typedef
				var = TypeDef.new var
			elsif prev
				check_compatible_type(prev.type, var.type)
				# XXX forward attributes ?
			end
			scope.symbol[var.name] = var

			raise tok || self, 'punctuation expected' if not tok = skipspaces or tok.type != :punct

			case tok.raw
			when '{':
				raise tok if nofunc or not var.kind_of? Variable or not var.type.kind_of? Function
				var.initializer = Block.new scope
				var.type.args.each { |v|
					# put func parameters in func body scope
					if not v.name
						puts "unnamed argument in definition" if $VERBOSE
						# should raise
						next
					end
					# arg redefinition is checked in parse_declarator
					var.initializer.variable[v.name] = v
					# XXX will need special check in stack allocation
				}

				nil while parse_statement(var.initializer)
				raise tok || self, '"}" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != '}'
				break
			when '=':
				raise tok, '"{" or ";" expected' if var.type.kind_of? Function
				raise tok, 'cannot initialize extern variable' if var.storage == :extern
				parse_initializer(scope, var)
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
				name = 'int'
				loop do
					case tok.raw
					when 'const', 'volatile'
						qualifier << tok.raw.to_sym
					when 'long', 'short', 'signed', 'unsigned'
						specifier << tok.raw.to_sym
					when 'int', 'char', 'void', 'float', 'double'
						var.type.name = tok.raw
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

				raise self, 'invalid specifier list' if \
				case name
				when 'double'	# long double
					true if s != [] and s != [:long]
				when 'int'	# short, long, long long X signed, unsigned
					specifier = specifier - [:long] + [:longlong] if (specifier & [:long]).length == 2
					true if (specifier & [:signed, :unsigned]).length > 1 or (specifier & [:short, :long, :longlong]).length > 1
				when 'char'	# signed, unsigned
					# signed char != char and unsigned char != char
					true if (specifier & [:signed, :unsigned]).length > 1 or (specifier & [:short, :long]).length > 0
				else		# none
					true if not specifier.empty?
				end

				# normalize long/short in type.name
				case name
				when 'double'
					name = 'long double' if specifier.delete :long
				when 'int'
					name = 'long long' if specifier.delete :longlong
					name = 'long' if specifier.delete :long
					name = 'short' if specifier.delete :short
					specifier.delete :signed
				end if not specifier.empty?

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
			t = t.type while t.type and (t.type.kind_of?(Pointer) or t.type.kind_of?(Function))	# XXX typedefs ? should work as is apriori
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

		loop do
			break if not tok = skipspaces
			if tok.type == :punct and tok.raw == '['
				# array indexing
				t = var
				t = t.type while t.type and (t.type.kind_of?(Pointer) or t.type.kind_of?(Function))
				t.type = Array.new t.type
				t.type.length = CExpression.parse(self, scope)	# may be nil
				raise self, '"]" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ']'
			elsif tok.type == :punct and tok.raw == '('
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

						args << v if not v.type.kind_of? BaseType or v.type.name != 'void'

						parse_attribute(v) while tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'

						if tok and tok.type == :punct and tok.raw == ','
							raise self if args.last != v		# last arg of type 'void'
						elsif tok and tok.type == :punct and tok.raw == ')'
							break
						else raise tok || self, '"," or ")" expected'
						end
					end
				end
				parse_attribute(var) while tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'
				unreadtok tok
			else
				unreadtok tok
				break
			end
		end
	end

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
		raise self if not tok = skipspaces
		if tok.type == :punct and tok.raw == '{'
			# anonymous struct, ok
		elsif tok.type == :string
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
		else
			raise tok, 'struct name expected'
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
					raise self if not bits = CExpression.parse(self, scope)
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
	end

	def parse_enum(scope, var)
		raise self if not tok = skipspaces
		if tok.type == :punct and tok.raw == '{'
			# ok
		elsif tok.type == :string
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
		else
			raise tok, 'enum name expected'
		end

		val = -1
		loop do
			raise self if not tok = skipspaces
			break if tok.type == :punct and tok.raw == '}'

			raise tok if tok.type != :string or Reserved[tok.raw]
			name = tok.raw
			raise tok, 'enum value redefinition' if scope.enum[name]

			raise self if not tok = skipspaces
			if tok.type == :punct and tok.raw == '='
				nval = CExpression.parse(self, scope)
				raise self, 'need constant initializer' if not val = nval.reduce
				raise self if not tok = skipspaces
			else
				val += 1
			end
			(var.type.values ||= {})[name] = val
			scope.enum[name] = val

			if tok.type == :punct and tok.raw == '}'
				break
			elsif tok.type == :punct and tok.raw == ','
			else raise tok
			end
		end
		parse_attribute(var.type) while tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'
		unreadtok tok
	end

	def parse_c_statement(scope)
		return if not tok = readtok
		case tok.raw
		when 'if'
		when 'switch'
		when 'case'
		when 'while'
		when 'do'
		when 'for'
		when 'asm', '__asm', '__asm__'
		when 'goto'
		when 'return'
		when 'continue'
		when 'break'
		when '{'
			return
		when String
			raise if Reserved
			if ntok and notk.type == :punct and ntok.raw == ':'
				Label.new
			else
			end
		end
		raise if not tok = readtok or tok.type != :punct or tok.raw != ';'
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
					val = CExpression.new(nil, nil, val, val.type)
				else
					val = CExpression.new(nil, nil, val, kikoo)
				end
				val = parse_value_postfix(parser, scope, val)
			when :quoted
				if tok.raw[0] == ?'
					raise tok, 'invalid character constant' if tok.value.length > 1
					val = CExpression.new(nil, nil, tok.value[0], BaseType.new('int'))
				else
					val = ptr_to tok.value
					val = CExpression.new(nil, nil, tok, BaseType.new('int', :const))	# TODO L"toto"
					raise tok, 'how do i shot qstrings ?' # TODO
				end
				val = parse_value_postfix(parser, scope, val)
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
						val = CExpression.new(nil, nil, val, v.type)
					else
						val = parse(parser, scope)
						raise tok, 'no matching ")" found' if not ntok = parser.readtok or ntok.type != :punct or ntok.raw != ')'
						val = val.parse_value_postfix(parser, scope, val)
					end
				when '.'	# float
					parse_intfloat(parser, scope, tok)
					if not tok.value
						parser.unreadtok tok
						return
					end
					val = tok.value
					val = val.parse_value_postfix(parser, scope, val)
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
					rexpr = parser.skipspaces
					raise parser if not rexpr or rexpr.type != :string
					# check val type + rexpr == member
					CExpression[val, tok.raw.to_sym, rexpr]

				when '['
					idx = parse(parser, scope)
					raise tok if not idx or not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ']'
					# check val & idx type
					CExpression[val, :'[]', idx]

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
					CExpression[val, :'()', args]
				end
			end

			if nval
				parse_value_postfix(parser, scope, nval)
			else
				parser.unreadtok tok
				val
			end
		end

		def parse(parser, scope)
			opstack = []
			stack = []

			return if not e = parse_value(parser, scope)

			stack << e

			while op = readop(parser)
				parser.skip_space_eol
				until opstack.empty? or OP_PRIO[op.value][opstack.last]
					stack << new(opstack.pop, stack.pop, stack.pop)
				end
				
				opstack << op.value
				
				raise op, 'need rhs' if not e = parse_value(parser)
				stack << e
			end

			until opstack.empty?
				stack << new(opstack.pop, stack.pop, stack.pop)
			end

			CExpression[stack.first]
		end
	end
	end
end
end
