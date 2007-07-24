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

		def initialize(type)
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

			if allow_value
				if var.storage and var.storage.include? :typedef
					raise @lexer, "redefinition of type #{var.name}" if scope.type[var.name]
					scope.type[var.name] = var.type
				else
					raise @lexer, "redefinition of #{var.name}" if scope.variable[var.name] and scope.variable[var.name].initializer
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
			ptr = Pointer.new nil

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
					var.type = scope.struct_ancestors[name]
					raise tok, 'undeclared struct' if not var.type
				end
				return
			end
			raise tok, 'struct redefinition' if scope.struct[name]
			scope.struct[name] = var.type
		else
			raise tok, 'struct name expected'
		end

		var.type.members = []
		# parse struct/union members in definition
		loop do
			basetype = Variable.new
			parse_type(scope, basetype, false)
			loop do
				member = basetype.dup
				parse_declarator(scope, member)
				# raise @lexer if not member.name	# can be useful in hacking: struct foo {int; int*; int iwant;};
				parse_attribute(member) while tok = skipspaces and tok.type == :string and tok.raw == '__attribute__'
				raise @lexer if not tok or tok.type != :punct

				var.type.members << member
				case tok.raw
				when ';'
					break
				when ':'

					# bits
				when ','
				else raise tok, '",", ":" or ";" expected'
				end
			end
		end
		

			if ntok.type == :string
				# variable declaration using preexisting structure
				@lexer.unreadtok ntok
				struct = scope.struct_ancestors[name]
				raise tok, 'undeclared structure' if not struct
				# do not check undeclared structure now (don't know if the variable following 
				var.type = struct
			elsif ntok.type == :punct and ntok.raw == '{'
			end
		elsif tok.type == :punct or tok.raw == '{'
		elsif tok.type == :punct or tok.raw == ';'
		end
	end

	def parse_enum(scope)
		raise @lexer if not tok = skipspaces
			loop do
				raise @lexer if not tok = skipspaces
				if tok.type == :string and tok.raw == '__attribute__'
					parse_type_attribute(scope, var)
				else break
				end
			end
	end

	# parses a variable name, may include pointer/array specification with qualifiers
	# does not parse initializer
	def parse_declarator(scope, var)
		# TODO check undeclared struct
		raise @lexer if not tok = skipspaces
		if tok.type == :punct and tok.raw == '*'
			var.type = Pointer.new(var.type)
			raise @lexer if not tok = skipspace
			if tok.type == :string and (tok.raw == 'const' or tok.raw == 'volatile')
				(tok.type.qualifier ||= []) << tok.raw.to_sym
				# allow many ?
			end
		end
		raise tok if tok.type != :string or Reserved[tok.raw]
		tok.name = tok.raw
		loop do
			raise @lexer if not tok = skipspaces
			if tok.type != :punct or tok.raw != '['
				@lexer.unreadtok tok
				break 
			end
			var.type = Array.new(var.type)
			var.length = parse_cexpr_single(scope)
			raise @lexer if not tok = skipspaces
			raise tok if tok.type != :punct or tok.raw != ']'
		end
			loop do
				raise @lexer if not tok = skipspaces
				if tok.type == :string and tok.raw == '__attribute__'
					parse_type_attribute(scope, var)
				else break
				end
			end
	end

# XXX undone XXX #
# XXX undone XXX #
# XXX undone XXX #
# XXX undone XXX #

			u = parse_union

			parse_union @toplevel.scope
			type = parse_union tok
			ntok = readtok(tok)
			return if ntok.type == :punct and ntok.raw == ';'
			@lexer.unreadtok ntok
		when 'struct'
			type = parse_struct tok
			ntok = readtok(tok)
			return if ntok.type == :punct and ntok.raw == ';'
			@lexer.unreadtok ntok
		else
			if not reserved(tok.raw)
				type = Type.new('int')
				@lexer.unreadtok tok
			else
				type = parse_type tok
			end
		end

		loop do
			name = readtok(tok, :string)
			case readtok(name, :punct).raw
			when '('	# function declaration/definition
				func = Function.new
				func.name = name
				func.return_type = type
				func.args = []
				seentype = false
				# read argument list
				loop do
					func.args << Variable.new
					a = readtok(name, :string)
					if not reserved(a.raw)
						func.args.last.name = a
					else
						seentype = true
						func.args.last.type = parse_type a
					end
					ntok = readtok(tok)
					if not oldstyledef and ntok.type == :string
						func.args.last.name = ntok
						ntok = readtok(tok)
					end
					raise name if ntok.type != :punct or (ntok.raw != ',' and ntok.raw != ')')
					break if ntok.raw == ')'
				end
				if not seentype
					# oldstyle: int toto(a, b, c) int a; int b; double c; { kikoo lol }
					loop do
						ntok = readtok(tok)
						if ntok.type == :punct and ntok.raw == '{'
							@lexer.unreadtok ntok
							break
						end
						raise name if ntok.type != :string
						atype = parse_type(ntok)
						aname = readtok(name, :string)
						if not arg = func.args.find { |a| a.name.raw == aname.raw } or arg.type != atype
							raise name, 'syntax error'
						end
						arg.type = atype
						raise name if readtok(name, :punct).raw != ';'
					end
				end
				func.args.each { |a| a.type ||= Type.new('int') }
				# check redefinition
				if o = @curscope.find_var(name.raw)
					if not o.kind_of? Function or o.body or o.return_type != func.return_type or
					(o.args.length > 0 and func.args.length > 0 and (o.args.length != func.args.length or
					(o.args.zip(func.args).any? { |t1, t2| t1 != t2 })))
						raise name, 'bad redeclaration'
					end
				end
				@curscope.variables[name.tok] = func
				# read body
				case readtok(name, :punct).raw
				when ',': next
				when ';': break
				when '{'
					func.scope = @curscope = Scope.new(@curscope)
					loop do
						ntok = readtok(name)
						break if ntok.type == :punct and ntok.raw == '}'
						@lexer.unreadtok ntok
						@curscope << parse_c_statement(ntok)
					end
					@curscope = @curscope.parent
					break
				else raise name
				end

			when '='	# variable initialization
				raise name, 'redefinition' if v = @curscope.variables[name] and (v.initializer or v.type != type)
				raise name if type.modifiers.include? 'extern'
				var = Variable.new
				var.name = name
				var.type = type
				var.initializer = parse_initializer(name, var)
				@curscope.variables[name] = var
			when ','	# next variable
				raise name, 'redefinition' if v = @curscope.variables[name] and (v.initializer or v.type != type)
				var = Variable.new
				var.name = name
				var.type = type
				@curscope.variables[name] = var
			when ';'	# done
				break
			else raise name
			end
		end
	end

	def parse_typedef(tok)
		type = parse_type(tok)
		newtype = readtok(tok, :string)
		raise tok if readtok(tok, :punct).raw != ';'
		@type[newtype.raw] = type
	end

	def parse_struct(tok)
		ntok = readtok(tok)
		if ntok.type == :string
			name = ntok.raw
			ntok = readtok(tok, :punct)
			if ntok.raw == ';'
				s = Struct.new
				s.name = name
				@type["struct #{name.raw}"] ||= s
				return s
			end
		end
		raise tok if ntok.raw != '{'
		s = Struct.new
		s.name = name
		s.members = []
		@type["struct #{name.raw}"] = s if name
		loop do
			ntok = readtok(tok)
			if ntok.type == :punct and ntok.raw == '}'
				break
			end
			s.members << Variable.new
			s.members.last.type = parse_type(ntok)
			s.members.last.name = readtok(tok, :string)
			ntok = readtok(tok, :punct)
			if ntok.raw == ':'
				s.bits ||= {}
				s.bits[s.members.last.name.raw] = readtok(tok, :string).raw.to_i
				ntok = readtok(tok, :punct)
			end
			raise tok if readtok(tok, :punct).raw != ';'
		end
		s
	end

	def parse_union(tok)
		ntok = readtok(tok)
		if ntok.type == :string
			name = ntok.raw
			ntok = readtok(tok, :punct)
			if ntok.raw == ';'
				u = Union.new
				u.name = name
				@type["union #{name.raw}"] ||= u
				return u
			end
		end
		raise tok if ntok.raw != '{'
		u = Union.new
		u.name = name
		u.members = []
		@type["union #{name.raw}"] = u if name
		loop do
			ntok = readtok(tok)
			if ntok.type == :punct and ntok.raw == '}'
				break
			end
			u.members << Variable.new
			u.members.last.type = parse_type(ntok)
			u.members.last.name = readtok(tok, :string)
			raise tok if readtok(tok, :punct).raw != ';'
		end
		u
	end

	def parse_type(tok)
		# XXX int (*foo)(void); : we read type and unreadtok name
	end

	def parse_initializer(tok, var)
		ntok = readtok(tok)
		if ntok.type == :punct and ntok.raw == '{'	# struct/array initialization
			members = []
			if var.type.type.kind_of? Struct
				members = var.type.type.members
			end
			type = var.type
			ret = []
			loop do
				ntok = readtok(tok)
				if ntok.type == :punct and ntok.type == '.'
					raise tok if not members.include?((name = readtok(tok, :string)).raw)
					raise tok if readtok(tok, :punct).raw != '='
					ret << CExpression.new(name.raw, :'=', parse_c_expression(name))
				else
					@lexer.unreadtok ntok
					ret << parse_c_expression(tok)
				end
				case readtok(tok, :punct).raw
				when ','
				when '}': break
				else raise tok
				end
			end
			ret
		else parse_c_expression(tok)
		end
	end

	def parse_c_expression(tok)
		p1 = parse_c_value
		loop do
			op = readop
			p2 = parse_c_value
		end
	end

	def parse_c_statement(tok)
		case ntok
		when 'if'
		when 'switch'
		when 'while'
		when 'do'
		when 'for'
		when 'asm'
		else
			if reserved ntok
				parse_def
			end
		end
	end

	class CExpression
	class << self
		# key = operator, value = hash regrouping operators of lower precedence
		OP_PRIO = [[:'||'], [:'&&'], [:'<', :'>', :'<=', :'>=', :'==', :'!='],
			[:|], [:^], [:&], [:<<, :>>], [:+, :-], [:*, :/, :%]].inject({}) { |h, oplist|
			lessprio = h.keys.inject({}) { |hh, op| hh.update op => true }
			oplist.each { |op| h[op] = lessprio }
			h }


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
