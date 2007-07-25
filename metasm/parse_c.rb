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
		# name => obj
		attr_accessor :variable	# hash name => Variable
		attr_accessor :type	# hash typedefd name => Type
		attr_accessor :struct	# hash name => Type
		attr_accessor :enum	# hash enum name => value
		attr_accessor :outer	# parent block
		attr_accessor :statements	# array of CExpr/If../Continue../Goto/Label/Block

		def initialize(outer)
			@variable, @type, @struct, @enum = {}, {}, {}, {}
			@statements = []
			@outer = outer
		end

		def variable_ancestors
			(outer ? outer.variable_ancestors : {}).merge @variables
		end
		def type_ancestors
			(outer ? outer.type_ancestors : {}).merge @types
		end
		def struct_ancestors
			(outer ? outer.struct_ancestors : {}).merge @struct
		end
		def enum_ancestors
			(outer ? outer.enum_ancestors : {}).merge @enum
		end
	end

	class Variable < Declaration
		attr_accessor :type, :initializer
		attr_accessor :name		# defined by parse_declarator
		attr_accessor :attributes
		attr_accessor :storage		# auto register static extern
	end

	class Type < Declaration
		attr_accessor :qualifier	# const volatile
		attr_accessor :attributes
	end
	class BaseType < Type
		attr_accessor :name		# a typedefed name or 'int' 'long' 'long long' 'short' 'double' 'long double' 'float' 'char' 'void'
		attr_accessor :specifier	# holds only sign specifier
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
		attr_accessor :members
		attr_accessor :bits		# name => len
	end
	class Struct < Union
		attr_accessor :align
	end
	class Enum < Type
		# hash name => value
		attr_accessor :values
	end
	class Pointer < Type
		attr_accessor :type

		def initialize(type=nil)
			@type = type
		end
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
		# op may be :,, :., :->, :funcall (funcname, :funcall, [arglist]), :cast (type, :cast, expr)
		# XXX cast to fnptr
		attr_accessor :lexpr, :op, :rexpr
		def initialize(l, o, r)
			@lexpr, @op, @rexpr = l, o, r
		end
	end

	# creates a new CParser, parses all top-level statements
	def self.parse(text, file='unknown', lineno=1)
		c = new
		c.lexer.feed text, file, lineno
		nil while not c.lexer.eos? and c.parse_definition(c.toplevel)
		raise c.lexer if not c.lexer.eos?
		c.sanity_checks
		c
	end

	attr_accessor :lexer, :toplevel
	def initialize
		@lexer = Preprocessor.new(self)
		@toplevel = Block.new(nil)
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

	# returns the next non-space/non-eol token
	def skipspaces
		nil while tok = @lexer.readtok and (tok.type == :space or tok.type == :eol)
		tok
	end

	# checks that the types are compatible for the same variable
	def check_compatible_type(oldtype, newtype)
	end

	Reserved = %w[struct union enum  if else for while do switch goto
			register extern auto static typedef  const volatile
			void int float double char  signed unsigned long short
			case continue break return  __attribute__
	].inject({}) { |h, w| h.update w => true }

	# parses variable/function definition/declaration/initialization
	# with allow_value false, disallow storage class specifier/initialization
	# populates scope.struct/scope.enum
	# if allow_value, populates scope.variable, else returns an array of Variables
	# raises on redefinition
	# returns the definitions if not allow_value, else true
	# returns false if no definition is found
	def parse_definition(scope, allow_value=true)
		defs = allow_value ? true : []

		basetype = Variable.new
		parse_type(scope, basetype, allow_value)	# filters out typedefs
		return false if not basetype.type

		# check struct predeclaration
		tok = skipspaces
		if allow_value and tok and tok.type == :punct and tok.raw == ';' and basetype.type
				and (basetype.type.kind_of? Union or basetype.type.kind_of? Enum)
			return true
		else @lexer.unreadtok tok
		end

		nofunc = false
		loop do
			var = basetype.dup
			parse_declarator(scope, var)

			if allow_value and var.name
				raise @lexer, "redefinition of #{var.name}" if scope.type[var.name] or (scope.variable[var.name] and (scope.variable[var.name].initializer or (var.storage and var.storage.include? :typedef))) or scope.enum[var.name]
				if var.storage and var.storage.include? :typedef
					scope.type[var.name] = var.type
				else
					check_compatible_type(scope.variable[var.name].type, var.type) if scope.variable[var.name]
					scope.variable[var.name] = var
				end
			else
				defs << var
			end

			raise @lexer if not tok = skipspaces
			raise tok, 'punctuation expected' if tok.type != :punct
			raise tok, 'no function definition allowed here' if (nofunc or not allow_value) and tok.type.kind_of? Function

			case tok.raw
			when '{':
				raise tok, '"=", "," or ";" expected' if not var.type.kind_of? Function
				body = Block.new scope
				var.type.args.each { |v|
					if not v.name
						puts "unnamed argument in definition" if $VERBOSE
						next
					end
					raise @lexer, "argument redefinition: #{v.name.inspect}" if body.variable[v.name]
					body.variable[v.name] = v
				}

				parse_function_body(scope, var)
				raise @lexer, '"}" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != '}'
				break
			when '=':
				raise tok, 'no initialization allowed here' if not allow_value
				raise tok, 'cannot initialize extern variable' if var.storage and var.storage.include?(:extern)
				raise tok, '"{" or ";" expected' if var.type.kind_of? Function
				parse_initializer(scope, var)
				raise @lexer, '"," or ";" expected' if not tok = skipspaces or tok.type != :punct
			end

			case tok.raw
			when ',': nofunc = true
			when ';': break
			else raise tok, '";" or "," expected'
			end
		end

		defs
	end

	# parses var basetype/qualifier/storage
	def parse_type(scope, var, allow_value)
		qualifier = nil
		loop do
			break if not tok = skipspaces
			if tok.type != :string
				@lexer.unreadtok tok
				break
			end

			case tok.raw
			when 'const', 'volatile'
				# XXX allow multiple qualifiers ?
				(qualifier ||= []) << tok.raw.to_sym
				next
			when 'register', 'auto', 'static', 'typedef', 'extern'
				raise tok, 'storage specifier not allowed here' if not allow_value
				# XXX allow multiple storage ?
				(var.storage ||= []) << tok.raw.to_sym
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
				var.type = BaseType.new
				loop do
					case tok.raw
					when 'long', 'short', 'signed', 'unsigned'
						(var.type.specifier ||= []) << tok.raw.to_sym
						raise @lexer if not tok = skipspaces
						if tok.type != :string or not %w[long short signed unsigned int double].include?(tok.raw)
							@lexer.unreadtok tok
							var.type.name ||= 'int'
							break
						end
					when 'int', 'char', 'void', 'float', 'double'
						var.type.name = tok.raw
						break
					end
				end
				if s = var.type.specifier
					raise @lexer, "invalid specifier list" if \
					case var.type.name
					when 'double'	# long double
						true if s != [:long]
					when 'int'	# short, long, long long X signed, unsigned
						s = s - [:long] + [:longlong] if (s & [:long]).length == 2
						true if (s & [:signed, :unsigned]).length > 1 or (s & [:short, :long, :longlong]).length > 1
					when 'char'	# signed, unsigned
						# signed char != char and unsigned char != char
						true if (s & [:signed, :unsigned]).length > 1 or (s & [:short, :long]).length > 0
					else		# none
						true
					end

					# normalize long/short in type.name
					case var.type.name
					when 'double'
						var.type.name = 'long double'
						var.type.specifier = nil
					when 'int'
						if s.delete :longlong
							var.type.name = 'long long'
						elsif s.delete :long
							var.type.name = 'long'
						elsif s.delete :short
							var.type.name = 'short'
						end
						s.delete :signed
						var.type.specifier = nil if var.type.specifier.empty?
					end
				end
			else
				if type = scope.type_ancestors[tok.raw]
					var.type = BaseType.new
					var.type.name = type
				else
					@lexer.unreadtok tok
				end
			end

			break
		end

		if not var.type
			raise @lexer, 'bad type name' if qualifier or var.storage
			return
		end

		var.type.qualifier = qualifier if qualifier

		loop do
			return if not tok = skipspaces
			if tok.type == :string and tok.raw == '__attribute__'
				var.type = var.type.dup
				parse_attribute(var.type)
			else
				@lexer.unreadtok tok
				break
			end
		end
	end

	# updates var.type and var.name, parses pointer/arrays/function declarations
	# parses anonymous declarators (var.name will be false)
	# the caller is responsible for detecting redefinitions
	# scope used only in CExpression.parse for array sizes and function prototype argument types
	def parse_declarator(scope, var)
		return if not tok = skipspaces
		if tok.type == :punct and tok.raw == '*'
			ptr = Pointer.new

			parse_attribute(ptr) while tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'
			@lexer.unreadtok tok

			parse_declarator(scope, var)
			t = var
			t = t.type while t.type and (t.type.kind_of?(Pointer) or t.type.kind_of?(Function))
			ptr.type = t.type
			t.type = ptr
			return
		elsif tok.type == :punct and tok.raw == '('
			parse_declarator(scope, var)
			raise @lexer, '")" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ')'
		elsif tok.type == :string
			raise tok, 'bad var name' if Reserved[tok.raw]
			raise tok if var.name or var.name == false
			var.name = tok.raw
		else
			# unnamed
			raise tok if var.name or var.name == false
			var.name = false
			@lexer.unreadtok tok
		end

		loop do
			break if not tok = skipspaces
			if tok.type == :punct and tok.raw == '['
				t = var
				t = t.type while t.type and (t.type.kind_of?(Pointer) or t.type.kind_of?(Function))
				t.type = Array.new t.type
				t.type.length = CExpression.parse(@lexer, scope)	# may be nil
				raise @lexer, '"]" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ']'
			elsif tok.type == :punct and tok.raw == '('
				t = var
				t = t.type while t.type and (t.type.kind_of?(Pointer) or t.type.kind_of?(Function))
				t.type = Function.new t.type
				tok = skipspaces
				if not tok or tok.type != :punct or tok.raw != ')'
					t.type.args = []
					loop do
						v = Variable.new
						raise @lexer if not tok = skipspace
						if tok.type == :punct and tok.raw == '.'	# variadic function
							raise @lexer, '"..." expected' if not tok = skipspaces or tok.type != :punct or tok.raw != '.'
							raise @lexer, '"..." expected' if not tok = skipspaces or tok.type != :punct or tok.raw != '.'
							raise @lexer, '")" expected'   if not tok = skipspaces or tok.type != :punct or tok.raw != ')'
							t.type.varargs = true
							break
						elsif tok.type == :string and tok.raw == 'register'
							v.storage = tok.raw.to_sym
						else
							@lexer.unreadtok tok
						end

						parse_type(scope, v, false)
						raise @lexer if not v.type
						parse_declarator(scope, v)

						args << v if not v.type.kind_of? BaseType or v.type.name != 'void'

						parse_attribute(v) while tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'

						if tok and tok.type == :punct and tok.raw == ','
							raise @lexer if args.last != v		# last arg of type 'void'
						elsif tok and tok.type == :punct and tok.raw == ')'
							break
						else raise @lexer
						end
					end
				end
				parse_attribute(t.type) while tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'
				@lexer.unreadtok tok
			else
				@lexer.unreadtok tok
				break
			end
		end
	end

	def parse_attribute(obj)
		raise @lexer if not tok = skipspaces or tok.type != :punct or tok.type != '('
		raise @lexer if not tok = skipspaces or tok.type != :punct or tok.type != '('
		nest = 0
		attrib = ''
		loop do
			raise @lexer if not tok = skipspaces
			if tok.type == :punct and tok.raw == ')'
				if nest == 0
					raise @lexer if not tok = skipspaces or tok.type != :punct or tok.raw != ')'
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
	# XXX add backtrace info ? (declaration/definition)
	def parse_type_unionstruct(scope, var)
		raise @lexer if not tok = skipspaces
		if tok.type == :punct and tok.raw == '{'
			# ok
		elsif tok.type == :string
			# a struct name
			name = tok.raw
			raise tok, 'bad struct name' if Reserved[name]
			parse_attribute(var.type) while ntok = skipspaces and ntok.type == :string and ntok.raw == '__attribute__'
			raise @lexer if not ntok
			if ntok.type != :punct or ntok.raw != '{'
				@lexer.unreadtok ntok
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
			raise @lexer if not tok = skipspaces
			break if tok.type == :punct and tok.raw == '}'
			@lexer.unreadtok tok

			basetype = Variable.new
			parse_type(scope, basetype, false)
			raise @lexer if not basetype.type
			loop do
				member = basetype.dup
				parse_declarator(scope, member)
				# raise @lexer if not member.name	# can be useful while hacking: struct foo {int; int*; int iwant;};
				parse_attribute(member) while tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'
				raise @lexer, 'member redefinition' if member.name and var.type.members.find { |m| m.name == member.name }
				var.type.members << member

				raise @lexer if not tok or tok.type != :punct

				if tok.raw == ':'	# bits
					raise @lexer if not bits = CExpression.parse(@lexer, scope)
					(var.type.bits ||= {})[member.name] = bits if member.name
					raise @lexer if not tok = skipspaces or tok.type != :punct
				end

				case tok.raw
				when ';': break
				when ','
				else raise tok, '"," or ";" expected'
				end
			end
		end
		parse_attribute(var.type) while tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'
		@lexer.unreadtok tok
	end

	def parse_enum(scope, var)
		raise @lexer if not tok = skipspaces
		if tok.type == :punct and tok.raw == '{'
			# ok
		elsif tok.type == :string
			# enum name
			name = tok.raw
			raise tok, 'bad enum name' if Reserved[name]
			parse_attribute(var.type) while ntok = skipspaces and ntok.type == :string and ntok.raw == '__attribute__'
			raise @lexer if not ntok
			if ntok.type != :punct or ntok.raw != '{'
				@lexer.unreadtok ntok
				if ntok.type == :punct and ntok.raw == ';'
					# predeclaration
					# allow redefinition
					scope.enum[name] ||= var.type
				else
					# check that the enum exists
					enum = scope.enum_ancestors[name]
					raise tok, 'undeclared enum' if not enum
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
			raise @lexer if not tok = skipspaces
			break if tok.type == :punct and tok.raw == '}'

			raise tok if tok.type != :string or Reserved[tok.raw]
			name = tok.raw
			raise tok, 'enum value redefinition' if scope.enum[name]

			raise @lexer if not tok = skipspaces
			if tok.type == :punct and tok.raw == '='
				nval = CExpression.parse(@lexer, scope)
				raise @lexer, 'need constant initializer' if not val = nval.reduce
				raise @lexer if not tok = skipspaces
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
		@lexer.unreadtok tok
	end

	def parse_c_statement(tok)
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
		when String
			raise if Reserved
			if ntok and notk.type == :punct and ntok.raw == ':'
				Label.new
			else
			end
		end
	end

	class CExpression
	class << self
		# key = operator, value = hash regrouping operators of lower precedence
		# XXX . -> |= ^= += ++ -- ',', unary & * cast sizeof funcall, ternary x?x:x
		OP_PRIO = [[:','], [:'=', :'+=', :'-=', :'*=', :'/=', :'%=',
			:'&=', :'|=', :'^=', :'<<=', :'>>='], [:'||'], [:'&&'],
			[:|], [:^], [:&], [:'==', :'!='],
			[:'<', :'>', :'<=', :'>='], [:<<, :>>], [:+, :-],
			[:*, :/, :%]].inject({}) { |h, oplist|
			lessprio = h.keys.inject({}) { |hh, op| hh.update op => true }
			oplist.each { |op| h[op] = lessprio }
			h }

		RIGHTTOLEFT = [:'=', :'+=', :'-=', :'*=', :'/=', :'%=', :'&=',
			:'|=', :'^=', :'<<=', :'>>=', :cast
		].inject({}) { |h, op| h.update op => true }


		# reads an operator from the lexer, returns the corresponding symbol or nil
		def readop(lexer)
			if not tok = lexer.readtok or tok.type != :punct
				lexer.unreadtok tok
				return
			end

			if tok.value
				if OP_PRIO[tok.value]
					return tok
				else
					lexer.unreadtok tok
					return
				end
			end

			op = tok
			case op.raw
			# may be followed by itself or '='
			when '>', '<'
				if ntok = lexer.nexttok and ntok.type == :punct and (ntok.raw == op.raw or ntok.raw == '=')
					op.raw << lexer.readtok.raw
				end
			# may be followed by itself
			when '|', '&'
				if ntok = lexer.nexttok and ntok.type == :punct and ntok.raw == op.raw
					op.raw << lexer.readtok.raw
				end
			# must be followed by '='
			when '!', '='
				if not ntok = lexer.nexttok or ntok.type != :punct and ntok.raw != '='
					lexer.unreadtok tok
					return
				end
				op.raw << lexer.readtok.raw
			# ok
			when '^', '+', '-', '*', '/', '%'
			# unknown
			else
				lexer.unreadtok tok
				return
			end
			op.value = op.raw.to_sym
			op
		end

		# parse sizeof offsetof etc
		def parse_intfloat(lexer, tok)
			Expression.parse_num_value(lexer, tok)
		end

		# returns the next value from lexer (parenthesised expression, immediate, variable, unary operators)
		def parse_value(lexer)
			lexer.skip_space
			return if not tok = lexer.readtok
			case tok.type
			when :string
				parse_intfloat(lexer, tok)
				val = tok.value || tok.raw
			when :quoted
				if tok.raw[0] != ?'
					lexer.unreadtok tok
					return
				end
				s = tok.value || tok.raw[1..-2]	# raise tok, 'need ppcessing !'
				s = s.reverse if lexer.program and lexer.program.cpu and lexer.program.cpu.endianness == :little
				val = s.unpack('C*').inject(0) { |sum, c| (sum << 8) | c }
			when :punct
				case tok.raw
				when '('
					lexer.skip_space_eol
					val = parse(lexer)
					lexer.skip_space_eol
					raise tok, 'syntax error, no ) found' if not ntok = lexer.readtok or ntok.type != :punct or ntok.raw != ')'
				when '!', '+', '-', '~'
					lexer.skip_space_eol
					raise tok, 'need expression after unary operator' if not val = parse_value(lexer)
					val = Expression[tok.raw.to_sym, val]
				when '.'
					parse_intfloat(lexer, tok)
					if not tok.value
						lexer.unreadtok tok
						return
					end
					val = tok.value
				else
					lexer.unreadtok tok
					return
				end
			else
				lexer.unreadtok tok
				return
			end
			lexer.skip_space
			val
		end

		# for boolean operators, true is 1 (or anything != 0), false is 0
		def parse(lexer)
			opstack = []
			stack = []

			return if not e = parse_value(lexer)

			stack << e

			while op = readop(lexer)
				lexer.skip_space_eol
				until opstack.empty? or OP_PRIO[op.value][opstack.last]
					stack << new(opstack.pop, stack.pop, stack.pop)
				end
				
				opstack << op.value
				
				raise op, 'need rhs' if not e = parse_value(lexer)
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
