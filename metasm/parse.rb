require 'metasm/main'
require 'metasm/encode'

module Metasm
class ParseError < Exception ; end

#
# defines the methods nexttok and readtok
# they spits out tokens :
#  +String+ for words
#  +Symbol+ for punctuation/:eol
#  +Integer+ for ints (allowed: 0x123_456, 0777 (oct), 8BFh, 0b010010)
#  +Float+ for floats
#  +QString+ for quoted strings
#
# QStrings and Comments are the only place where non 7bit ascii codes are allowed
# lines end in \n (\r ignored)
# one-line comments start with ';', '#' or '//'
# multi-line in '/* ... */'
#
module Lexer
	class Comment
		attr_reader :text
		def initialize(text='')
			@text = text
		end
	end
	class QString
		attr_reader :delimiter, :text
		def initialize(delimiter)
			@delimiter = delimiter
			@text = ''
		end
	end

	def lexer_curpos
		"line #@lexer_lineno"
	end

	def exception(msg = '')
		ParseError.new "Parse error at #{lexer_curpos}: #{msg}"
	end

	attr_reader :lexer_pos, :lexer_text, :lexer_lineno

	# start parsing a new string
	# known macros are kept
	def feed(text)
		@lexer_queue = []
		@lexer_text = text
		@lexer_lineno = 0
		@lexer_pos = 0
	end

	# returns true if no more data is available
	def eos?
		@lexer_pos >= @lexer_text.length and @lexer_queue.empty?
	end

	def unreadtok(*tlist)
		tlist.reverse_each { |t|
			@lexer_queue << t if t
		}
	end

	# handles 2byte operators and floats
	def readtok
		tok = @lexer_queue.pop || readtok_basic

		case tok
		when :+, :-, :*, :/, :&, :|, :^, :'=', :%, :':', :<, :>
			ntok = @lexer_queue.pop || readtok_basic
			str = "#{tok}#{ntok}"
			if (ntok == :'=')
				tok = str.to_sym
			else
				case str
				when '&&', '||', '>>', '<<': tok = str.to_sym
				else unreadtok ntok
				end
			end
		end
		tok
	end

	# peek next token w/o consuming it
	def nexttok
		tok = readtok
		unreadtok tok
		tok
	end

	private
	# reads and return the next token (1char determinist, except for // /* comments delimiters) (LALR0 ?)
	def readtok_basic
		# skip spaces
		loop do
			case @lexer_text[@lexer_pos]
			when ?\ , ?\t, ?\r
			when ?\\
				nc = @lexer_text[@lexer_pos + 1]
				break if (nc != ?\n) and (nc != ?\r or @lexer_text[@lexer_pos+2] != ?\n)
				@lexer_pos += 1 until @lexer_text[@lexer_pos] == ?\n
			else break
			end
			@lexer_pos += 1
		end

		# read token
		case c = @lexer_text[@lexer_pos]
		# end of string
		when nil

		# end of line 
		when ?\n
			@lexer_lineno += 1
			@lexer_pos += 1
			:eol

		# string token
		when ?a..?z, ?A..?Z, ?_, ?$
			tok = ''
			loop do
				case c = @lexer_text[@lexer_pos]
				when ?a..?z, ?A..?Z, ?0..?9, ?_, ?$
					tok << c
				else break
				end
				@lexer_pos += 1
			end
			tok

		# integer/float
		when ?0..?9, ?.
			tok = ''
			loop do
				case c = @lexer_text[@lexer_pos]
				when ?_
				when ?0..?9, ?A..?Z, ?a..?z: tok << c
				else break
				end
				@lexer_pos += 1
			end

			case tok
			when /^0b([01]+)$/i, /^([01]+)b$/i: $1.to_i(2)
			when /^(0[0-7]*)$/: $1.to_i(8)
			when /^0x([0-9a-f]+)$/i, /^([0-9a-f]+)h$/i: $1.to_i(16)
			when /^([0-9]*)$/
				if @lexer_text[@lexer_pos] != ?.
					tok.to_i
				else
					# float
					tok << ?.
					@lexer_pos += 1
					loop do
						case c = @lexer_text[@lexer_pos]
						when ?_
						when ?0..?9: tok << c
						else break
						end
						@lexer_pos += 1
					end
					return :'.' if tok == '.'
					@lexer_pos += 1 while (c = @lexer_text[@lexer_pos]) == ?\ 
					if c == ?e or c == ?E
						tok << ?e
						@lexer_pos += 1
						loop do
							case c = @lexer_text[@lexer_pos]
							when ?\ 
							when ?+, ?-
								tok << c if c == ?+ or c == ?-
								@lexer_pos += 1 while @lexer_text[@lexer_pos] == ?\ 
							else break
							end
							@lexer_pos += 1
						end
						loop do
							case c = @lexer_text[@lexer_pos]
							when ?_
							when ?0..?9: tok << c
							else break
							end
							@lexer_pos += 1
						end
					end
					tok.to_f
				end
			else raise self, "Invalid integer #{tok.inspect}"
			end

		# quotedstr
		when ?', ?"
			startlineno = @lexer_lineno
			tok = QString.new c
			@lexer_pos += 1
			loop do
				case c = @lexer_text[@lexer_pos]
				when nil
					raise ParseError, "Unterminated string starting line #{startlineno}"
				when tok.delimiter
					@lexer_pos += 1
					break
				when ?\n
					@lexer_lineno += 1
					@lexer_pos += 1
					tok.text << c
				when ?\\
					# escape sequence
					@lexer_pos += 2
					tok.text << case c = @lexer_text[@lexer_pos-1]
					when nil
						raise ParseError, 'Unterminated escape sequence'
					when ?x
						ttok = ''
						while ttok.length < 2
							case c = @lexer_text[@lexer_pos]
							when ?0..?9, ?a..?f, ?A..?F: ttok << c
							else break
							end
							@lexer_pos += 1
						end
						ttok.to_i(16)
	
					when ?0..?7
						ttok = ''
						ttok << c
						while ttok.length < 3
							case c = @lexer_text[@lexer_pos]
							when ?0..?7: ttok << c
							else break
							end
							@lexer_pos += 1
						end
						ttok.to_i(8)

					when ?n: ?\n
					when ?r: ?\r
					when ?t: ?\t
					when ?a: ?\a
					when ?b: ?\b
					when ?\\, tok.delimiter: c

					when ?\r
					when ?\n
						#   "blablabla\
						# <skip ws>  bloblo"
						@lexer_lineno += 1
						loop do
							case @lexer_text[@lexer_pos]
							when ?\ ,?\t
							else break
							end
							@lexer_pos += 1
						end
					else
						raise ParseError, "Unknown escape sequence '\\#{c.chr}'"
						#c	# just ignore the backslash
					end
				else
					tok.text << c
					@lexer_pos += 1
				end
			end
			tok

		when ?#, ?;
			tok = Comment.new
			while c = @lexer_text[@lexer_pos]
				break if c == ?\n
				tok.text << c
				@lexer_pos += 1
			end
			tok

		when ?/
			@lexer_pos += 1
			case @lexer_text[@lexer_pos]
			when ?/
				tok = Comment.new
				tok.text << ?/
				while c = @lexer_text[@lexer_pos]
					break if c == ?\n
					tok.text << c
					@lexer_pos += 1
				end
				tok
			when ?*
				tok = Comment.new
				@lexer_pos += 1
				tok.text << ?/ << ?*
				seenstar = false
				while c = @lexer_text[@lexer_pos]
					tok.text << c
					@lexer_pos += 1

					break if seenstar and c == ?/
					seenstar = false
					case c
					when ?*: seenstar = true
					when ?\n: @lexer_lineno += 1
					end
				end
				tok
			else :/
			end

		# XXX hardcoded ascii table
		when 33..126
			@lexer_pos += 1
			c.chr.to_sym
			
		else raise ParseError, "Unhandled character #{c.inspect} in source"
		end
	end
end

class CPU
	# Parses prefix/name/arguments
	# Returns an +Instruction+, or nil on failure
	def parse_instruction(program)
		@opcode_list_byname ||= @opcode_list.inject({}) { |h, o| (h[o.name] ||= []) << o ; h }

		i = Instruction.new

		# find prefixes, break on opcode name
		tok = program.readtok
		while parse_prefix(i, tok)
			tok = program.readtok
		end

		return if not @opcode_list_byname[tok]
		i.opname = tok

		# find arguments
		loop do
			break if @opcode_list_byname[program.nexttok]
			break unless arg = parse_argument(program)
			i.args << arg
			break unless program.nexttok == :','
			program.readtok
			program.readtok while program.nexttok == :eol
		end

		@opcode_list_byname[i.opname].to_a.find { |o|
			o.args.length == i.args.length and o.args.zip(i.args).all? { |f, a| parse_arg_valid?(o, f, a) }
		} or raise program, "invalid instruction #{i}"

		parse_instruction_fixup(program, i)

		i
	end

	def parse_init(program)
	end

	def parse_instruction_fixup(program, i)
	end

	# returns true if a prefix was found
	def parse_prefix(i, tok)
	end

	# returns a parsed argument
	# add your own arguments parser here (registers, memory references..)
	#def parse_argument(lex)
	#	Expression.parse(@program)
	#end

	# handle all .instructions
	# handle HLA here
	def parse_parser_instruction(pgm, instr)
		raise pgm, "Unknown parser instruction #{instr.inspect}"
	end
end


class Program
	class Macro
		attr_reader :name, :args, :body, :local_labels
		def initialize(name, body=[])
			@name, @body = name, body
			@args, @local_labels = [], []
			@apply_count = 0
		end

		def apply(args)
			@apply_count += 1
			args = @args.zip(args).inject({}) { |h, (k, v)| h.update k => v }
			labels = @local_labels.inject({}) { |h, k| h.update k => true }
			@body.map { |e|
				if args[e]: args[e]
				elsif labels[e]: "macrolocal_#{@name}_#{e}_#{@apply_count}"
				else e
				end
			}.flatten
		end
	end
	

	include Lexer

	attr_reader :lexer_macro, :lexer_equ
	def feed(*a)
		@lexer_equ   ||= {}
		@lexer_macro ||= {}
		super
	end

	def new_unique_label
		@unique_label_counter ||= 0
		"metasmintern_uniquelabel_#{object_id}_#{@unique_label_counter += 1}"
	end

	# handles 'equ' and '$'/'$$' special label, and macros
	# can return anything Lexer#readtok may return, plus Expression
	def readtok
		case tok = super
		when '$$'
			# start of current section
			if @cursection.source.first.class != Label
				@cursection.source.unshift(Label.new(new_unique_label))
			end
			tok = @cursection.source.first.name
		when '$'
			# start of current item
			if @cursection.source.last.class != Label
				@automaticlabelcount ||= 0
				@cursection << Label.new(new_unique_label)
			end
			tok = @cursection.source.last.name

		when 'equ', 'macro'
			raise self, "Unexpected #{tok.inspect}"

		when String
			# check for equ
			case ntok = super
			when 'equ'
				raise self, "Redefining equ #{tok.inspect}" if @lexer_equ[tok]
				@lexer_equ[tok] = Expression.parse(self)
				tok = readtok
			when 'macro'
				raise self, "Redefining macro #{tok.inspect}" if @lexer_macro[tok]
				@lexer_macro[tok] = lexer_new_macro(Macro.new(tok))
				tok = readtok
			else
				unreadtok ntok
				if m = @lexer_macro[tok]
					lexer_apply_macro m
					tok = readtok
				elsif m = @lexer_equ[tok]
					tok = m
				end
			end
		end

		case tok
		when Comment
			raise self, "#{tok.text} not implemented" if tok.text[0..2] == '#if'
			readtok
		else tok
		end
	end

	def lexer_new_macro(m)
		args  = []
		state = :arg
		tok = nil
		loop do
			tok = readtok
			case state
			when :arg
				break if tok.class != String
				args << tok
				state = :coma
			when :coma
				break if tok != :','
				state = :arg
			end
		end
		m.args.replace args
		loop do
			case tok
			when nil
				raise self, 'unfinished macro definition'
			when 'endm'
				break
			else
				m.local_labels << m.body.last if tok == :':' and m.body[-1].class == String and m.body[-2] == :eol
				m.body << tok
			end
			tok = readtok
		end
		m.local_labels.find_all { |ll| m.body.find_all { |lll| lll == ll }.length == 1 }.each { |ll| m.local_labels.delete ll }
		m
	end

	def lexer_apply_macro(m)
		# checks if the macro has arguments
		args = [[]]
		state = :start
		loop do
			tok = readtok
			case state
			when :start
				case tok
				when :'('
					state = :arg
				else
					unreadtok tok
					break
				end
			when :arg
				case tok
				when :','
					args << []
				when :')'
					args << []
					break
				when nil
					raise ParseError, 'Unterminated macro argument list'
				else
					args.last << tok
				end
			end
		end
		args.pop
		raise self, "Incompatible number of arguments for macro : #{args.inspect} vs #{m.args.inspect}" if args.length != m.args.length
		m.apply(args).reverse_each { |t| unreadtok t }
	end


	# XXX should
	#   add eax, toto
	#   toto equ 42
	# work ? (need to preparse for macro/equ definitions)
	def parse(str)
		if not defined? @parse_cpu_init
			@parse_cpu_init = true
			@cpu.parse_init self
			@lexer_lineno = 0
		end

		feed str

		until eos?
			case tok = readtok
			when :eol
			when :'.'
				# HLA
				tok = readtok
				# XXX .486 ?  => Float
				raise self, "Expected parser instruction, found #{tok.inspect}" if tok.class != String
				parse_parser_instruction ".#{tok}"
				# XXX nasm 'weak labels'

			when String
				if ['db', 'dw', 'dd', :':'].include?(ntok = nexttok)
					# label
					readtok if ntok == :':'
					@knownlabel ||= {}
					raise self, "Redefinition of label #{tok} (defined at #{@knownlabel[tok]})" if @knownlabel[tok]
					@knownlabel[tok] = lexer_curpos
					@cursection << Label.new(tok)
				elsif %w[db dw dd].include? tok
					# data
					type = tok.to_sym
					arr = []
					loop do
						arr << parse_data(type)
						if nexttok == :','
							readtok
						else break
						end
					end
					@cursection << Data.new(type, arr)

				elsif tok == 'align'
					e = Expression.parse(self)
					raise self, 'need immediate alignment size' unless (e = e.reduce).kind_of? Integer
					@cursection << Align.new(e)

				else
					# allow '.' in opcode name
					while nexttok == :'.'
						tok << readtok
						raise self, "Invalid instruction name #{tok}" unless nexttok.kind_of? String
						tok << readtok
					end

					# cpu instruction
					unreadtok tok
					if i = @cpu.parse_instruction(self)
						@cursection << i
					else
						raise self, "Unknown thing to parse: #{tok.inspect}"
					end
				end
			when nil
				break
			else
				raise self, "Unknown thing to parse: #{tok.inspect}"
			end
		end
	end

	# handle global import/export
	# .export foo [, "teh_foo_function"] (public name)
	# .import "user32.dll" "MessageBoxA"[, messagebox] (name of thunk/plt entry, will be generated automatically. When applicable, imports with thunkname are considered 'code imports' and the other 'data import' (ELF))
	def parse_parser_instruction(instr)
		case instr.downcase
		when '.export'
			label = readtok
			if nexttok == :','
				readtok
				name = readtok
				name = name.text if name.kind_of? QString
			else
				name = label
			end
			@export[name] = label

		when '.import'
			libname = readtok
			libname = libname.text if libname.kind_of? QString
			readtok if nexttok == :','
			importfunc = readtok
			importfunc = importfunc.text if importfunc.kind_of? QString
			raise self, 'Improper argument to .import' unless libname.kind_of? String and importfunc.kind_of? String
			if nexttok == :','
				readtok
				thunkname = readtok
				# XXX when thunkname == importname, name should point to thunk and import masked
			end
			(@import[libname] ||= []) << [importfunc, thunkname]

		when '.text', '.data', '.rdata', '.bss'
			secname = instr
			if not @cursection = @sections.find { |s| s.name == secname }
				@cursection = Section.new(self, secname)
				@cursection.mprot = 
				case secname
				when '.text': [:read, :exec]
				when '.data', '.bss': [:read, :write]
				when '.rdata': [:read]
				end
				@sections << @cursection
			end

		when '.section'
			secname = readtok
			secname = secname.text if secname.kind_of? QString
			args = []
			args << readtok while nexttok and nexttok != :eol
			readtok
			args.delete :','
			if not @cursection = @sections.find { |s| s.name == secname }
				@cursection = Section.new(self, secname)
				@sections << @cursection
			end
			while a = args.shift
				case a.downcase
				when 'exec', 'execute', 'x': @cursection.mprot |= [:exec]
				when 'noexec', 'noexecute', 'nx': @cursection.mprot -= [:exec]
				when 'read', 'r':    @cursection.mprot |= [:read]
				when 'noread', 'nr': @cursection.mprot -= [:read]
				when 'write', 'w':   @cursection.mprot |= [:write]
				when 'nowrite', 'nw', 'ro', 'readonly': @cursection.mprot -= [:write]
				when 'align'
					a = args.shift if (a = args.shift) == :'='
					@cursection.align = a
				when 'base'
					a = args.shift if (a = args.shift) == :'='
					@cursection.base = a
				when 'discard': @cursection.mprot |= [:discard]
				when 'shared':  @cursection.mprot |= [:shared]
				else raise self, "Unknown section specifier #{a.inspect}"
				end
			end

		else
			@cpu.parse_parser_instruction(self, instr)
		end
	end

	def parse_data(type)
		case tok = readtok
		when QString
			if tok.text.length > Expression::INT_SIZE[Data::INT_TYPE[type]]/8
				Data.new type, tok.text
			else
				unreadtok tok
				i = Expression.parse(self) or raise self, "Invalid data"
				Data.new type, i
			end
		when :'?'
			Data.new type, Data::Uninitialized
		else
			unreadtok tok
			i = Expression.parse(self) or raise self, "Invalid data"

			if nexttok == 'dup'
				raise "Invalid data count #{i}" unless (count = i.reduce).kind_of? Integer
				readtok # consume 'dup'
				raise self, "Invalid dup data : '(' expected" if readtok != :'('
				content = []
				loop do
					content << parse_data(type)
					if nexttok != :','
						break
					else readtok
					end
				end
				raise self, "Invalid dup data: ')' expected" if readtok != :')'
				Data.new type, content, count
			else
				Data.new type, i
			end
		end
	end
end

class Expression
	class << self
		# key = operator, value = hash regrouping operators of lower precedence
		OP_PRIO = [[:|], [:^], [:&], [:<<, :>>], [:+, :-], [:*, :/, :%]].inject({}) { |h, oplist|
			lessprio = h.keys.inject({}) { |hh, op| hh.update op => true }
			oplist.each { |op| h[op] = lessprio }
			h }

		# returns an Expression or nil if unparsed
		def parse(pgm)
			opstack = []
			stack = []

			return if pgm.eos? or not e = parse_expr(pgm)
			stack << e

			loop do
				case tok = pgm.readtok
				when :-, :+, :*, :/, :%, :|, :&, :<<, :>>
					lessprio = OP_PRIO[tok]
					
					until opstack.empty? or lessprio[opstack.last]
						stack << new(opstack.pop, stack.pop, stack.pop)
					end
					
					opstack << tok
					
					raise pgm, "Invalid expression" unless e = parse_expr(pgm)
					stack << e
				else
					pgm.unreadtok tok
					break
				end
			end
				
			until opstack.empty?
				stack << new(opstack.pop, stack.pop, stack.pop)
			end

			e = stack.first
			e = new(:+, e, nil) unless e.kind_of? self
			e
		end

		def parse_expr(pgm)
			case tok = pgm.readtok
			when :+, :-, :~
				# unary operator
				return unless e = parse_expr(pgm)
				new(tok, e, nil)
			when :'('
				# parenthesis
				return unless e = parse(pgm)
				raise pgm, "Expression: ')' expected" unless pgm.readtok == :')'
				e
			when Numeric, self
				tok
			when String
				if %w[addr near short offset].include?(tok)
					puts "#{tok} modifier ignored" if $VERBOSE
					parse_expr(pgm)
				else
					tok
				end
			when Lexer::QString
				t = tok.text
				t = t.reverse if pgm.cpu.endianness == :little
				t.unpack('C*').inject(0) { |v, b| (v << 8) | b }
			when :eol
				pgm.unreadtok tok
				nil
			else
				raise pgm, "Expression parser: #{tok.inspect} unexpected"
			end
		end
	end
end
end
