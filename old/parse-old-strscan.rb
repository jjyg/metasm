require 'metasm/main'

module Metasm
class ParseError < Exception ; end

# reads a source string, spits out tokens :
#  +String+ for words
#  +Symbol+ for punctuation
#  +Integer+ for ints
#  +QString+ for quoted strings
#
# QStrings and Comments are the only place where non 7bit ascii codes are allowed
# lines end in \n (\r ignored)
# one-line comments start with ';', '#' or '//'
# multi-line in '/* ... */'
#
class Lexer
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

	def exception(msg = '')
		ParseError.new("Parse error at line #@lineno: #{msg}")
	end

	attr_reader :pos, :text, :lineno
	def initialize(text = '')
		@queue = []
		feed text
	end

	# start parsing a new string
	# known macros are kept
	def feed(text)
		@text = text
		@lineno = 0
		@pos = 0
		@queue.clear
	end

	# returns true if no more data is available
	def eos?
		@pos >= @text.length and @queue.empty?
	end

	def unreadtok(t)
		@queue << t
	end

	# handles 2byte operators
	def readtok
		if @queue.empty?
			tok = readtok_basic
		else
			tok = @queue.pop
		end

		case tok
		when :+, :-, :*, :/, :&, :|, :^, :'=', :%, :':', :<, :>
			ntok = @queue.empty? ? readtok_basic : @queue.pop
			if (ntok == :'=') or (tok == :'=' and (ntok == :< or ntok == :>))
				tok = "#{tok}#{ntok}".to_sym
			else
				unreadtok ntok
			end
		end
		tok
	end

	private
	# reads and return the next token (1char determinist, except for // /* comments delimiters) (LALR0 ?)
	def readtok_basic
		# skip spaces
		loop do
			case @text[@pos]
			when ?\n: @lineno += 1
			when ?\ , ?\t, ?\r
			else break
			end
			@pos += 1
		end

		# read token
		case c = @text[@pos]
		# eos
		when nil

		# string token
		when ?a..?z, ?A..?Z, ?_
			tok = ''
			loop do
				case c = @text[@pos]
				when ?a..?z, ?A..?Z, ?0..?9, ?_
					tok << c
				else break
				end
				@pos += 1
			end
			tok

		# integer
		when ?0..?9, ?.
			tok = ''
			@pos += 1
			# XXX handle floats in fetch_tok ? (fetch int -> check :., int, 'e', :+/:-, int)
			if c == ?.
				case @text[@pos]
				when ?0..?9
					raise ParseError, 'Floats not supported'
				else :'.'
				end
			elsif c == ?0 and (@text[@pos] == ?x or @text[@pos] == ?X)
				@pos += 1
				loop do
					case c = @text[@pos]
					when ?_ # allow 0x123_456_789
					when ?0..?9, ?a..?f, ?A..?F: tok << c
					when ?a..?z, ?A..?Z: raise ParseError, 'Invalid hex constant'
					else break
					end
					@pos += 1
				end
				tok.to_i(16)
			elsif c == ?0 and (@text[@pos] == ?b or @text[@pos] == ?B)
				@pos += 1
				loop do
					case c = @text[@pos]
					when ?_
					when ?0, ?1: tok << c
					when ?a..?z, ?A..?Z, ?2..?9: raise ParseError, 'Invalid bin constant'
					else break
					end
					@pos += 1
				end
				tok.to_i(2)
			else
				tok << c
				nooct = nodec = false
				loop do
					case c = @text[@pos]
					when ?_
					when ?0..?7
						tok << c
					when ?8, ?9
						toc << c
						nooct = true
					when ?a..?f, ?A..?F
						tok << c
						nooct = nodec = true
					when ?h
						case @text[@pos+1]
						when ?a..?z, ?A..?Z, ?0..?9, ?_: raise ParseError, 'Invalid numeric constant'
						else
							@pos += 1
							return tok.to_i(16)
						end
					when ?a..?z, ?A..?Z: raise ParseError, 'Invalid numeric constant'
					else break
					end
					@pos += 1
				end
				if tok[0] == ?0
					raise ParseError, 'Invalid numeric constant' if nooct
					tok.to_i(8)
				else
					raise ParseError, 'Invalid numeric constant' if nodec
					tok.to_i
				end
			end

		# quotedstr
		when ?', ?"
			startlineno = @lineno
			tok = QString.new c
			@pos += 1
			loop do
				case c = @text[@pos]
				when nil
					raise ParseError, "Unterminated string starting line #{startlineno}"
				when tok.delimiter
					@pos += 1
					break
				when ?\n
					@lineno += 1
					@pos += 1
					tok.text << c
				when ?\\
					# escape sequence
					@pos += 2
					tok.text << case c = @text[@pos-1]
					when nil
						raise ParseError, 'Unterminated escape sequence'
					when ?x
						ttok = ''
						while ttok.length < 2
							case c = @text[@pos]
							when ?0..?9, ?a..?f, ?A..?F: ttok << c
							else break
							end
							@pos += 1
						end
						ttok.to_i(16)
	
					when ?0..?7
						ttok = ''
						ttok << c
						while ttok.length < 3
							case c = @text[@pos]
							when ?0..?7: ttok << c
							else break
							end
							@pos += 1
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
						@lineno += 1
						loop do
							case @text[@pos]
							when ?\ ,?\t
							else break
							end
							@pos += 1
						end
					else
						raise ParseError, "Unknown escape sequence '\\#{c.chr}'"
						#c	# just ignore the backslash
					end
				else
					tok.text << c
					@pos += 1
				end
			end
			tok

		when ?#, ?;
			tok = Comment.new
			while c = @text[@pos]
				break if c == ?\n
				tok.text << c
				@pos += 1
			end
			tok

		when ?/
			@pos += 1
			case @text[@pos]
			when ?/
				tok = Comment.new
				tok.text << ?/
				while c = @text[@pos]
					break if c == ?\n
					tok.text << c
					@pos += 1
				end
				tok
			when ?*
				tok = Comment.new
				@pos += 1
				tok.text << ?/ << ?*
				seenstar = false
				while c = @text[@pos]
					tok.text << c
					@pos += 1

					break if seenstar and c == ?/
					seenstar = false
					case c
					when ?*: seenstar = true
					when ?\n: @lineno += 1
					end
				end
				tok
			else :/
			end

		# XXX hardcoded ascii table
		when 33..126
			@pos += 1
			c.chr.to_sym
			
		else raise ParseError, "Unhandled character #{c.inspect} in source"
		end
	end
end

# lexer handling macros/labels
# macro arguments are mandatory, use 'equ' or put a comment otherwise (bla macro /* */)
#  
#   foobar macro bar, baz
#     add eax, bar
#   endm
#   foobar(1, 2)
#   
#   foo equ bla
#
#  labels in a macro body are converted to (hopefully) unique label names (per macro invocation)
#
class AssemblyLexer < Lexer
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

	attr_reader :macros
	def initialize(*a)
		super
		@macros = {}
	end

	# reinit, forget known macros
	def clear
		feed ''
		@macros.clear
	end

	alias lex_readtok readtok
	# returns a token, consuming it
	def readtok
		case tok = lex_readtok
		when 'equ', 'macro'
			raise self, "unexpected #{tok.inspect}"
		when String
			case ntok = lex_readtok
			when 'equ'
				new_macro tok, [apply_macro(lex_readtok)]
				readtok
			when 'macro'
				new_macro tok
				readtok
			when :':'
				Label.new tok
			else
				unreadtok ntok
				apply_macro tok
			end
		else
			tok
		end
	end

	private
	def new_macro(name, body=nil)
		raise self, "redefinition of #{m.name.inspect}" if @macros[name]
		m = Macro.new(name)
		if body
			m.body.replace body
		else
			args  = []
			state = :arg
			tok   = nil
			loop do
				tok = apply_macro lex_readtok
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
				raise self, 'unfinished macro definition' unless tok
				break if tok == 'endm'
				m.local_labels << m.body.last if tok == :':' and m.body.last.class == String
				m.body << tok
				tok = apply_macro lex_readtok
			end
		end
		@macros[name] = m
	end

	# if name is a macro, applies the macro
	# returns the first token
	def apply_macro(name)
		if m = @macros[name]
			# checks if the macro has arguments
			args = [[]]
			state = :start
			loop do
				tok = lex_readtok
				
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
			toks = m.apply(args)
			name = toks.shift
			toks.reverse_each { |t| unreadtok t }
		end
		name
	end
end

class Program
	attr_reader :cpu, :lexer, :sections


end

class CPU
	# Parses prefix/name/arguments
	# Returns an +Instruction+, or nil on failure
	def parse_instruction(ss)
		@good_opcode_name ||= @opcode_list.inject({}) { |h, o| h.update o.name => true }

		i = Instruction.new

		# find prefixes, break on opcode name
		prepos = ss.pos
		while parse_prefix(ss, i)
			ss.scan(/\s*/)
			prepos = ss.pos
		end

		ss.pos = prepos
		tok = ss.scan(/\w+/)
		return if not @good_opcode_name[tok]
		i.opname = tok
	
		# avoid \s (it matches newlines and could find 'toto\ntata:' to be toto with arg tata)
		ss.scan(/[ \t]*/)

		# find arguments
		loop do
			prepos = ss.pos
			arg = parse_argument(ss)
			if not arg
				ss.pos = prepos
				break
			else
				i.args << arg
				break unless ss.scan(/\s*,\s*/)
			end
		end

		i
	end

	# returns true if a prefix was found
	#def parse_prefix(ss, i)

	# returns a parsed argument
	# add your own arguments parser here (registers, memory references..)
	#def parse_argument(ss)
	#	Expression.parse(ss)
	#end

	# handle all .instructions
	# handle HLA here
	def parse_parser_instruction(ss, instr)
		raise "Unknown parser instruction #{instr.inspect}"
	end
end


# XXX create a Program class, it should own the sections and things like global label list
#     the parser should know only the macros etc
class Parser
	# Returns the content of a string, with eg \x42 interpreted
	# Unknown escape sequences raise a ParseError
	# arguments: a stringscanner with the first quote just scanned, and a character constant representing the delimiter
	# the delimiter is used to find the end of the string and an allowed escape character
	def self.parse_string(ss, delimiter)
		delimiter = delimiter[0] if delimiter.class == String

		str = ''
		loop do
			str <<
			case c = ss.getch
			when nil
				# eof
				raise ParseError, "Unterminated string #{str[0..10].inspect}"
				
			when delimiter.chr
				# eos
				return str

			when '\\'
				# escape sequence

			else
				# normal char
				c
			end
		end
	end


	attr_reader :cpu, :sections

	def initialize(cpu)
		@cpu = cpu
		@sections = {}
		@macros = {}
	end

	# TODO structs
	#      count lines (to allow 'parse error on line 28') (handle macros)
	def parse(str)
		ss = StringScanner.new(str)

		class << ss ; attr_accessor :parser end
		ss.parser = self

		# XXX reset cursection for another #parse call ?
		@cursection ||= (@sections[nil] ||= Section.new(self, nil))

		# TODO '.include <foobar.h>' or handle predefined constants (found by an external header parser)
		@macros.each_key { |k| apply_macro ss, k }

		# TODO #ifdef foo #ifdef bar #endif #else #endif 

		# XXX pre-remove comments ?
		# would allow
		#   foo 1, ; comment
		#       2, ; again
		#       3
		# but fail on
		#   db "kikoo lol ; haha"
		# XXX should use a tokenizer instead of the stringscanner

		loop do
			ss.scan(/\s*/)
			posori = ss.pos
			if ss.eos?
				break

			# label
			elsif ss.scan(/(\w+)(?::|\s+(?=d[bwd]\b))/)
				# "kikoo: blah" or "kikoo db 48h"
				@label_names ||= {}
				lbl = ss[1]
				raise ParseError, "Redefinition of label #{lbl}" if @label_names[lbl]
				@label_names[lbl] = lbl
				@cursection << Label.new(lbl)

			# equ
			elsif ss.scan(/(\w+)\s+equ\s+(\S+)/)
				name, val = ss[1], ss[2]
				raise ParseError, "Redefinition of equ #{name}" if @macros[name]
				# XXX should add () only for immediates
				# is equ used for other things ?
				@macros[name] = [[], '(' << val << ')', 0]
				apply_macro ss, name

			# macro
			elsif ss.scan(/(\w+)\s+macro\b(.*)\s*/)
				name = ss[1]
				args = ss[2].split(',').map { |a| a.strip }

				# XXX nested macros ?
				raise ParseError, "Missing 'endm'" unless ss.scan(/(.*?)\s*endm\b/m)
				body = ss[1]

				raise ParseError, "Redefinition of macro #{name}" if @macros[name]
				@macros[name] = [args, body, 0]
				apply_macro ss, name

				# XXX multi-lines macro VS one-line comment fails
				# "bla macro\n x\n y\n endm\n // bla" => "//x\n y\n"

			# one-line comment
			elsif ss.scan(%r~(?:;|#|//).*~)
			# multi-line comment
			elsif ss.scan(%r~/\*.*?\*/~m)

			# meta instruction / high level assembly
			elsif ss.scan(/(\.\w+)\s*/)
				parse_parser_instruction(ss, ss[1])

			# data
			elsif ss.scan(/(d[bwd])\s+/)
				type = ss[1].to_sym
				arr = []
				loop do
					arr << parse_data(ss, type)
					break unless ss.scan(/\s*,\s*/)
				end
				@cursection << Data.new(type, arr)

			# cpu instruction
			elsif i = @cpu.parse_instruction(ss)
				@cursection << i

			else
				ss.pos = posori
				raise ParseError, "Unknown thing to parse : #{ss.peek(30).inspect}"
			end
		end

		ss
	end

private
	def apply_macro(ss, name)
		args, body, local_label_count = @macros[name]
		if args.empty?
			argregex = '(?:\(\s*\))?'
		else
			argregex = '\(' << args.map{ '\\s*(\\S+)\\s*' }.join(',') << '\)'
		end

		local_labels = body.scan(/^\s*(\w+)(?::|\s+(?=d[bwd]\b))/).flatten - args	# is '- args' needed ?

		# TODO detect macro call with invalid number of arguments ?
		ss.string = ss.rest.gsub(/\b#{name}#{argregex}/) {
			tmpbody = body.dup

			unless args.empty?
				# arguments
				args.zip($~.captures).each { |a, m| tmpbody.gsub!(/\b#{a}\b/, m) }
			end

			unless local_labels.empty?
				# macro-local labels
				tmppfx = "macrolabel_#{name}_#{local_label_count += 1}_"
				local_labels.each { |ll| tmpbody.gsub!(/\b#{ll}\b/, tmppfx+ll) }
			end

			tmpbody
		}

		# update label_count for further #parse calls
		@macros[name][2] = local_label_count
	end

	def parse_parser_instruction(ss, instr)
		case instr
		when '.code', '.data', '.rodata'
			# TODO find exhaustive list of well-known section names
			#      handle meta-instructions to modify the current section (set readonly, discardable...)

			# get rid of default section if unused
			@sections.delete(nil) if @sections[nil] == @cursection and @cursection.source.empty?

			# allows things like '.code foo .data bar .code baz'
			@cursection = (@sections[instr] ||= Section.new(self, instr))
		else
			@cpu.parse_parser_instruction(ss, instr)
		end
	end

	def parse_data(ss, type)
		if ss.scan(/"/)
			Data.new type, Parser.parse_string(ss, ?")
		elsif ss.scan(/\?/)
			Data.new type, Data::Uninitialized
		else
			if not i = Expression.parse(ss)
				raise ParseError, "Invalid data: #{ss.peek(30).inspect}"
			end

			# check dup() construct
			if ss.scan(/\s*dup\s*\(/)
				raise "Invalid data count #{i}" unless (count = i.reduce).kind_of? Immediate
				content = []
				loop do
					content << parse_data(ss, type)
					break unless ss.scan(/\s*,\s*/)
				end
				raise ParseError, "Data dup parser: ')' expected, found #{ss.peek(30).inspect}" unless ss.scan(/\s*\)/)
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
	# if a block is given, it is used to check if an external ref name is valid
	def parse(ss)
		opstack = []
		tokstack = []

		return unless tok = parse_tok(ss)
		tokstack.push tok

		while ss.scan(/([-+*\/%|&^]|<<|>>)\s*/)
			op = ss[1].to_sym
			lessprio = OP_PRIO[op]

			until opstack.empty? or lessprio[opstack.last]
				tokstack.push new(opstack.pop, tokstack.pop, tokstack.pop)
			end

			opstack.push op

			return unless tok = parse_tok(ss)
			tokstack.push tok
		end

		until opstack.empty?
			tokstack.push new(opstack.pop, tokstack.pop, tokstack.pop)
		end

		ret = tokstack.first
		ret = new(:+, ret, nil) unless ret.kind_of? self
		ret
	end

	def parse_tok(ss)
		if ss.scan(/([-~+])\s*/)
			# unary operator
			return unless tok = parse_tok(ss)
			tok = new(ss[1].to_s, tok, nil) unless ss[1] == '+' 
		elsif ss.scan(/\(\s*/)
			# parenthesis
			return unless tok = parse(ss)
			raise ParseError, 'expected )' unless ss.scan(/\)/)
		else
			tok = parse_immediate(ss) || parse_external(ss)
		end
		ss.scan(/\s*/)
		tok
	end

	def parse_immediate(ss)
		if ss.scan(/0x([0-9a-f]+)\b/i) or ss.scan(/([0-9a-f]+)h\b/i)
			ss[1].hex
		elsif ss.scan(/0b([01]+)\b/i) or ss.scan(/([01]+)b\b/i)
			ss[1].to_i(2)
		elsif ss.scan(/0([0-7]+)\b/)
			ss[1].to_i(8)
		elsif ss.scan(/([0-9]+)\b/)
			# match '0'
			ss[1].to_i
		elsif ss.scan(/'/)
			str = Parser.parse_string(ss, ?')
			str.reverse! if ss.parser.cpu.endianness == :little rescue nil
			str.unpack('C*').inject(0) { |v, b| (v << 8) | b }
		end
	end

	def parse_external(ss)
		puts "ignored #{ss[1]} immediate modifier for #{ss.peek(30).inspect}" if $VERBOSE if ss.scan(/(offset|addr|near|short)\s+/)
		# XXX is prc used anywhere ?
		return if not tok = ss.scan(/\w+/)
		tok
	end
end
end

end
