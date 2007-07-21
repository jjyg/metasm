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
		attr_accessor :statements	# array of CExpr/If../Continue../Goto/Label

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
		attr_accessor :name
		attr_accessor :attributes
		attr_accessor :storage		# auto register static extern
	end

	class Type < Declaration
		attr_accessor :qualifier	# const volatile
	end
	class BaseType < Type
		attr_accessor :name
		attr_accessor :attributes
	end
	class FunctionType < Type
		attr_accessor :return_type
		attr_accessor :args_type

		def initialize(rt)
			@return_type = rt
			@args_type = []
		end
	end
	class Union < Type
		# [[name, Type, bits=nil], ...]
		attr_accessor :members
		attr_accessor :attributes
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
	end
	class Array < Type
		attr_accessor :type
		attr_accessor :length
	end

	class Function
		attr_accessor :type	# FunctionType
		attr_accessor :args	# array of Variables
		attr_accessor :varargs	# true/false
		attr_accessor :attributes
		attr_accessor :name
		attr_accessor :body

		# parser helper
		def initialize(var)
			@name = var.name
			@type = FunctionType.new(var.type)
			@args = []
			@attributes = var.attributes
		end
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
		while not c.lexer.eos?
			c.parse_toplevel
		end
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
	#  toplevel initializers are constants
	#  etc
	#  TODO
	def sanity_checks
	end

	# returns the next non-space/non-eol token
	def skipspaces
		nil while tok = @lexer.readtok and (tok.type == :space or tok.type == :eol)
		tok
	end

	Reserved = %w[struct union enum
			register extern auto static typedef  const volatile
			int float double char  signed unsigned long short
	].inject({}) { |h, w| h.update w => true }

	# root of the state machine
	# XXX __attributes__ ?
	# XXX forward struct declaration ?
	def parse_toplevel
		basetype = Variable.new
		parse_type(@toplevel, basetype)
		nofunc = false
		loop do
			var = basetype.dup
			parse_declarator(@toplevel, var)
			raise @lexer if not tok = skipspaces

			case tok.raw
			when '(':
				raise tok if nofunc
				var = Function.new(var)
				parse_function_arglist(@toplevel, var)
				raise @lexer if not tok = skipspaces
				case tok.raw
				when ';'
				when '{': parse_function_body(@toplevel, var)
				else raise tok
				end
				break
			when '=':
				raise tok if var.storage and var.storage.include?(:typedef)
				parse_initializer(@toplevel, var)
				raise @lexer if not tok = skipspaces
			end

			case tok.raw
			when ';': break
			when ',': nofunc = true
			else raise tok
			end
		end
	end

	# parses var base type/qualifier/storage
	def parse_type(scope, var)
		qualifier = nil
		loop do
			raise @lexer if not tok = skipspaces
			raise tok if tok.type != :string
			case tok.raw
			when 'const', 'volatile'
				(qualifier ||= []) << tok.raw.to_sym
				next
			when 'register', 'auto', 'static', 'typedef', 'extern'
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
			else
				raise tok if not var.type = scope.type_ancestors[tok.raw]
			end

			break
		end
		var.type.qualifier = qualifier if qualifier
	end

	# parses a structure/union declaration
	def parse_type_unionstruct(scope, var)
		raise @lexer if not tok = skipspaces
		if tok.type == :string
			name = tok.raw
			raise tok if Reserved[name]
			tok = skipspaces
			if tok.type == :string or tok.foo
			if scope.ancest_struct[name]
			end
			end
		end
	end

	def parse_enum(scope)
		raise @lexer if not tok = skipspaces
	end

	# parses a variable name, may include pointer/array specification with qualifiers
	# does not parse initializer
	def parse_declarator(scope, var)
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
