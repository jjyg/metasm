require 'metasm/main'
require 'metasm/encode'

module Metasm
class ParseError < Exception ; end

#
# defines the methods nexttok and readtok
# they spits out tokens :
#  +String+ for words
#  +Symbols+ for punctuation
#  :eol for newline
#  +Integer+ for ints  (positive only)
#  +Float+ for floats (positive only)
#  +QString+ for quoted strings
#  nil on end of stream
#
# spaces are ignored: '[]' same as '[ \t]'
# \ at the end of a line make the lexer ignore the newline
# integers (positive): multiple formats handled : 0x123_456, 0777 (that's octal), 8BFh, 0b010010 (check regexes)
# floats: '9234.23234 e + 23', '.2', '23.e42'
# words are sequence of a-Z0-9_$, not starting by 0-9
# punctuation is any special character not in the above set. Groups allowed: see the next-to-last case statement (>>, ->, =~, !== etc)
# QStrings start with ' or " (indifferent). They are the only place where non 7bit ascii codes are allowed. \n are allowed in, after it the indentation is ignored.
# escape sequence are handled ("\x42\0\n\024\"")
# lines end in \n (\r ignored)
#
class Lexer
	class QString
		attr_reader :delimiter, :text
		def initialize(delimiter)
			@delimiter = delimiter
			@text = ''
		end
	end

	attr_reader :text, :lineno, :filename, :queue
	attr_accessor :pos
	def initialize(text, filename, lineno)
		@text = text
		@queue = []
		@filename = filename
		@lineno = lineno
		@pos = 0
	end

	def curpos
		"#@filename - line #@lineno"
	end

	def exception(msg = '')
		ParseError.new "Parse error at #{curpos}: #{msg}"
	end


	# returns true if no more data is available
	def eos?
		@pos >= @text.length and @queue.empty?
	end

	def unreadtok(t)
		@queue << t
	end

	# peek next token w/o consuming it
	def nexttok
		tok = readtok
		unreadtok tok
		tok
	end

	# reads and return the next token
	def readtok
		return @queue.pop unless @queue.empty?

		# skip spaces
		loop do
			case @text[@pos]
			when nil: break
			when ?\ , ?\t, ?\r
			when ?\\
				nc = @text[@pos + 1]
				break if (nc != ?\n) and (nc != ?\r or @text[@pos+2] != ?\n)
				@pos += 1 until @text[@pos] == ?\n
			else break
			end
			@pos += 1
		end

		# read token
		case c = @text[@pos]
		# end of string
		when nil
			nil

		# end of line 
		when ?\n
			@lineno += 1
			@pos += 1
			:eol

		# string token
		when ?a..?z, ?A..?Z, ?_, ?$
			tok = ''
			loop do
				case c = @text[@pos]
				when nil: break
				when ?a..?z, ?A..?Z, ?0..?9, ?_, ?$
					tok << c
				else break
				end
				@pos += 1
			end
			tok

		# integer/float
		when ?0..?9, ?.
			tok = ''
			loop do
				case c = @text[@pos]
				when nil: break
				when ?_
				when ?0..?9, ?A..?Z, ?a..?z: tok << c
				else break
				end
				@pos += 1
			end

			case tok
			when /^0b([01]+)$/i, /^([01]+)b$/i: $1.to_i(2)
			when /^(0[0-7]*)$/: $1.to_i(8)
			when /^0x([0-9a-f]+)$/i, /^([0-9a-f]+)h$/i: $1.to_i(16)
			when /^([0-9]*)$/
				if @text[@pos] != ?.
					tok.to_i
				else
					# float
					tok << ?.
					@pos += 1
					loop do
						case c = @text[@pos]
						when ?_
						when ?0..?9: tok << c
						else break
						end
						@pos += 1	# break shortcircuit this one
					end
					return :'.' if tok == '.'
					@pos += 1 while (c = @text[@pos]) == ?\ 
					if c == ?e or c == ?E
						tok << ?e
						@pos += 1
						loop do
							case c = @text[@pos]
							when ?\ 
							when ?+, ?-
								tok << c
								@pos += 1
								@pos += 1 while @text[@pos] == ?\ 
								break
							else break
							end
							@pos += 1	# broken over
						end
						loop do
							case c = @text[@pos]
							when ?_
							when ?0..?9: tok << c
							else break
							end
							@pos += 1
						end
					end
					tok.to_f
				end
			else raise self, "Invalid integer #{tok.inspect}"
			end

		# quotedstr
		when ?', ?"
			startlineno = @lineno
			tok = QString.new c
			@pos += 1
			loop do
				case c = @text[@pos]
				when nil
					raise self, "Unterminated string starting line #{startlineno}"
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
						raise self, 'Unterminated escape sequence'
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
						raise self, "Unknown escape sequence '\\#{c.chr}'"
						#c	# just ignore the backslash
					end
				else
					tok.text << c
					@pos += 1
				end
			end
			tok

		when ?+, ?-, ?*, ?/, ?&, ?|, ?^, ?=, ?%, ?:, ?<, ?>, ?!
			# may start a multichar punctuation
			case str = @text[pos, 2]
			when '>>', '<<', '&&', '||', '==', '!='
				case @text[pos+2]
				when ?=
					@pos += 3
					(str << ?=).to_sym
				else
					@pos += 2
					str.to_sym
				end
			when /.=/, '->', '//', '/*', '*/', '!~', '=~', '++', '--'
				@pos += 2
				str.to_sym
			else
				@pos += 1
				c.chr.to_sym
			end

		when 33..126
			# other punctuation signs
			# XXX ?. is handled in floats
			# XXX hardcoded ascii table
			@pos += 1
			c.chr.to_sym
			
		else raise self, "invalid character #{c.chr.inspect}"
		end
	end
end

class CPU
	# Parses prefix/name/arguments
	# Returns an +Instruction+, or nil on failure
	def parse_instruction(parser)
		i = Instruction.new self

		# find prefixes, break on opcode name
		tok = parser.readtok
		while parse_prefix(i, tok)
			tok = parser.readtok
		end
	
		# allow '.' in opcode name
		while parser.nexttok == :'.'
			tok << parser.readtok.to_s
			tok << parser.readtok.to_s
		end

		if not opcode_list_byname[tok]
			parser.unreadtok tok
			return
		end

		i.opname = tok

		# find arguments
		loop do
			break if opcode_list_byname[parser.nexttok] or parser.nexttok == :eol
			break unless arg = parse_argument(parser)
			i.args << arg
			break unless parser.nexttok == :','
			parser.readtok
			parser.readtok while parser.nexttok == :eol
		end

		opcode_list_byname[i.opname].to_a.find { |o|
			o.args.length == i.args.length and o.args.zip(i.args).all? { |f, a| parse_arg_valid?(o, f, a) }
		} or raise parser, "invalid instruction #{i}"

		parse_instruction_fixup(parser, i)

		i
	end

	def parse_init
		''
	end

	def parse_instruction_fixup(parser, i)
	end

	# returns true if a prefix was found
	def parse_prefix(i, tok)
	end

	# returns a parsed argument
	# add your own arguments parser here (registers, memory references..)
	#def parse_argument(lexer)
	#	Expression.parse(lexer)
	#end

	# handle all .instructions
	# handle HLA here
	def parse_parser_instruction(lexer, instr)
		raise lexer, "Unknown parser instruction #{instr.inspect}"
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
				elsif labels[e]: "metasmintern_macrolocal_#{@name}_#{e}_#{@apply_count}"
				else e
				end
			}.flatten
		end
	end
	
	attr_reader :parser_macro

	def exception(msg = '')
		loc = (@backtrace + [@lexer.curpos]).reverse.join ' included from '
		ParseError.new "Parse error at #{loc}: #{msg}"
	end

	def new_unique_label(pfx = 'metasmintern_uniquelabel')
		k = (pfx << '_' << pfx.object_id.to_s(16)).freeze
		(@unique_labels ||= {}).update(k => nil)
		k
	end

	def unreadtok(t)
		@lexer.unreadtok t
	end

	def nexttok
		t = readtok
		unreadtok t
		t
	end

	def eos?
		@lexer.eos?
	end

	# discards comments
	def readtok_nocomment
		case tok = @lexer.readtok
		when :'//', :';'
			# single line comment
			while tok
				tok = @lexer.queue.pop
				return tok if tok == :eol
			end
			@lexer.pos += 1 while not @lexer.eos? and @lexer.text[@lexer.pos] != ?\n	# XXX interfaces ftw \o/ This avoids lexer errors in comments, and newlines in QStrings, and \-continued comment line
			@lexer.pos += 1
			:eol
		when :'/*'
			# multiline comment
			while tok
				tok = @lexer.queue.pop
				return readtok_nocomment if tok == :'*/'
			end
			@lexer.pos += 1 while not @lexer.eos? and @lexer.text[@lexer.pos, 2] != '*/'
			@lexer.pos += 2
			readtok_nocomment
		else
			tok
		end
	end

	# handles preprocessor commands (#include, #ifdef..)
	# handles '$'/'$$' special label, and asm macros / equ
	# can return anything Lexer#readtok may return
	def readtok
		@pp_nesting ||= [] # :ok accept all, :ignore ignore prepro/macro but handle #else, :ignore_all ignore all
		discard = true if @pp_nesting.last == :ignore or @pp_nesting.last == :ignore_all

		tok = readtok_nocomment
		
		case tok
		when :'#'
			# preprocessor command
			case tok = @lexer.readtok
			when 'ifdef', 'ifndef', 'if'
				if discard
					foo = @pp_nesting.length
					@pp_nesting << :ignore_all
					readtok while @pp_nesting.length > foo and not eos?
				else
					case tok
					when 'ifdef'
						name = readtok_nocomment
						cond = true if @parser_macro[name]
					when 'ifndef'
						name = readtok_nocomment
						cond = true unless @parser_macro[name]
					when 'if'
						cond = Expression.parse_bool(self).reduce
						cond = false if cond == 0	# '#if 0'
					end

					if cond
						@pp_nesting << :ok
					else
						foo = @pp_nesting.length
						@pp_nesting << :ignore
						readtok while @pp_nesting[foo] == :ignore and not eos?
					end
				end
			when 'elif', 'else'	# '#else if' ?
				raise self, "##{tok} out of context" if @pp_nesting.empty?

				if @pp_nesting.last == :ok
					@pp_nesting[-1] = :ignore_all
					foo = @pp_nesting.length - 1
					readtok while @pp_nesting[foo] == :ignore_all and not eos?
				elsif @pp_nesting.last == :ignore and (tok == 'else' or (e = Expression.parse_bool(self).reduce and e != 0))
					@pp_nesting[-1] = :ok
				end
			when 'endif'
				raise self, "##{tok} out of context" if @pp_nesting.empty?
				@pp_nesting.pop
			when 'include', 'include_c'
				return nil if discard

				case filename = readtok_nocomment
				when Lexer::QString
					filename = filename.text
				when :<		# '#include <foobar>'
						# XXX '#include <Program Files/sux>'   <- space + :'/' operator...
					filename = ''
					while (curtok = readtok_nocomment) != :>
						case curtok
						when String
							filename << curtok
						when :'.', :/, :-	# XXX need exhaustive list !
							filename << curtok.to_s
						else
							raise self, "invalid filename to include : unexpected #{curtok.inspect}"
						end
					end

					@path_include ||= { 'include' => ['/usr/include/'], 'include_c' => ['/usr/include/'] }
					f = @path_include[tok].map { |dir| File.join(dir, filename) }.find { |f| File.exist? f }
					raise self, "unable to find <#{filename}> to include" if not f
					filename = f
				end
				raise self, "inexistant included file #{filename.inspect}" unless File.exist? filename

				@backtrace << @lexer.curpos
				case tok
				when 'include'
					curlexer, curnesting = @lexer, @pp_nesting
					@pp_nesting = []
					# XXX should push @lexer in an array, call parse_init and just return
					parse(nil, filename)
					@lexer, @pp_nesting = curlexer, curnesting
				when 'include_c'
					raise self, 'Go write a C parser'
					parse_c(nil, filename)	# TODO
				end
				@backtrace.pop
			when 'define'
				return nil if discard

				tok = readtok_nocomment
#				raise self, "macro by #define not implemented yet" if nexttok == :'('	# TODO # XXX XXX '#define FOO (BAR+4)'
				raise self, "redefinition of #{tok}" if @parser_macro[tok]
				m = @parser_macro[tok] = Macro.new(tok)
				while tok = readtok and tok != :eol
					m.body << tok
				end
			else
				return nil if discard
				raise self, "unsupported preprocessor command #{tok.inspect}"
			end
			:eol

		when 'defined'
			return tok if discard and @pp_nesting.last == :ignore_all
			# allowed in :ignore, which is the context of '#elif defined(foo)'

			raise self, "bad use of keyword 'defined'" if readtok_nocomment != :'(' or not (name = readtok_nocomment).kind_of? String or readtok_nocomment != :')'
			Expression[1, :==, (@parser_macro[name] ? 1 : 0)]

		when '$$'
			return tok if discard
			# start of current section
			if @cursection.source.first.class != Label
				@cursection.source.unshift(Label.new(new_unique_label))
			end
			@cursection.source.first.name
		when '$'
			return tok if discard
			# start of current item
			if @cursection.source.last.class != Label
				@automaticlabelcount ||= 0
				@cursection << Label.new(new_unique_label)
			end
			@cursection.source.last.name

		when 'equ', 'macro'
			return tok if discard
			raise self, "Unexpected #{tok.inspect}"

		when String
			return tok if discard
			case ntok = readtok_nocomment
			when 'equ'
				raise self, "Redefining equ #{tok.inspect}"   if @parser_macro[tok]
				# @parser_equ[tok] = Expression.parse(self)	# allows things like foo equ 1+1 \n foo * 2 => (1+1)*2, disallows things like foo equ "bar"
				m = @parser_macro[tok] = Macro.new(tok)
				while tok = readtok and tok != :eol	# toto db "foo" \n toto_len equ $-toto   must work
					m.body << tok
				end
				:eol
			when 'macro'
				raise self, "Redefining macro #{tok.inspect}" if @parser_macro[tok]
				@parser_macro[tok] = parser_new_macro(Macro.new(tok))
				:eol
			else
				unreadtok ntok
				if m = @parser_macro[tok]
					parser_apply_macro m
					readtok
				else
					tok
				end
			end
		else
			tok
		end
	end

	def parser_new_macro(m)
		m.args.clear
		loop do
			case tok = readtok_nocomment
			when :eol, nil: break
			when String: m.args << tok
			# allow ',' as arg separator (and anything else)
			end
		end
		loop do
			case tok = readtok_nocomment
			when nil: raise self, 'unfinished macro definition'
			when 'endm': break
			else
				if (tok == :':' or DataSpec.include? tok) and m.body.last.kind_of? String and (m.body[-2] == :eol or not m.body[-2])
					m.local_labels << m.body.last
				end
				m.body << tok
			end
		end
		m
	end

	def parser_apply_macro(m)
		# checks if the macro has arguments
		args = [[]]
		state = :start
		loop do
			tok = readtok
			case state
			when :start
				case tok
				when :'('	# XXX make them optionnal ?
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
					raise self, 'Unterminated macro argument list'
				else
					args.last << tok
				end
			end
		end
		args.pop
		raise self, "Incompatible number of arguments for macro : #{args.inspect} vs #{m.args.inspect}" if args.length != m.args.length
		m.apply(args).reverse_each { |t| unreadtok t }
	end


	def parse_init(str, filename = '<stdin>', lineno = 0)
		if not defined? @parse_cpu_init
			@parse_cpu_init = true
			parse @cpu.parse_init, 'cpu parser initialization'
		end

		@parser_macro ||= {}
		@backtrace ||= []
		if not str
			str = File.read(filename)
			str = str.to_a[lineno..-1].join if lineno != 0
		end
		@lexer = Lexer.new(str, filename, lineno)
	end

	# dumps the output of the lexer to stdout (kind of gcc -E)
	def dump_parse(*a)
		parse_init(*a)

		until eos?
			tok = readtok
			case tok
			when :eol
				puts :eol.inspect
			when :'.'
				tok = readtok
				raise self, "Expected parser instruction, found #{tok.inspect}" if tok.class != String
				print ".#{tok}".inspect, ' '
			else
				print tok.inspect, ' '
			end
		end
	end

	DataSpec = %w[db dw dd dq]

	def parse(*a)
		parse_init(*a)

		until eos?
			tok = readtok
			case tok
			when :eol, nil

			when :'.'
				# HLA
				tok = readtok
				# XXX .486 => Float, should be HLA
				raise self, "Expected parser instruction, found #{tok.inspect}" if tok.class != String
				parse_parser_instruction ".#{tok}"
				# XXX nasm 'weak labels'

			when String
				parse_parser_instruction '.text' if not defined? @cursection or not @cursection

				if nexttok == :':' or DataSpec.include? nexttok
					# label
					readtok if nexttok == :':'
					@knownlabel ||= {}
					raise self, "Redefinition of label #{tok} (defined at #{@knownlabel[tok].reverse.join(' included from ')})" if @knownlabel[tok]
					@knownlabel[tok] = @backtrace + [@lexer.curpos]
					@cursection << Label.new(tok)
				elsif DataSpec.include? tok
					# data
					unreadtok tok
					@cursection << parse_data_withspec

				else
					unreadtok tok

					# cpu instruction
					if i = @cpu.parse_instruction(self)
						@cursection << i
					else
						raise self, "Unknown instruction: #{nexttok.inspect}"
					end
				end
			else
				raise self, "Unknown thing to parse: #{tok.inspect}"
			end
		end
	end

	# handle global import/export
	# .export foo [, "teh_foo_function"] (public name)
	# .import "user32.dll" "MessageBoxA"[, messagebox] (name of thunk/plt entry, will be generated automatically)
	# When applicable, imports with thunkname are considered 'code imports' and the other 'data import' (ELF)) (TODO: add parser support for symbol type/size)
	def parse_parser_instruction(instr)
		case instr.downcase
		when '.export'
			label = readtok
			if nexttok == :','
				readtok
				name = readtok
				name = name.text if name.kind_of? Lexer::QString
			else
				name = label
			end
			@export[name] = label

		when '.import'
			libname = readtok
			libname = libname.text if libname.kind_of? Lexer::QString
			readtok if nexttok == :','
			importfunc = readtok
			importfunc = importfunc.text if importfunc.kind_of? Lexer::QString
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
			secname = secname.text if secname.kind_of? Lexer::QString
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

		when '.align', '.padto'
			e = Expression.parse(self).reduce
			raise self, 'need immediate alignment size' unless e.kind_of? Integer	# XXX sucks (db dup count as well)
			if nexttok == :','
				# want to fill with something specific
				readtok
				# allow single byte value or full data statement
				unreadtok 'db' unless DataSpec.include? nexttok
				fillwith = parse_data_withspec
			end
			@cursection << Align.new(e, fillwith, instr == '.align')

		else
			@cpu.parse_parser_instruction(self, instr)
		end
	end

	def parse_data_withspec
		raise 'invalid data type' unless DataSpec.include? nexttok
		type = readtok.to_sym
		arr = []
		loop do
			arr << parse_data(type)
			if nexttok == :',': readtok
			else break
			end
		end
		Data.new(type, arr)
	end

	def parse_data(type)
		case tok = readtok
		when :eol
			parse_data(type)
		when Lexer::QString
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
				readtok	# consume 'dup'
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
	# returns :bool or :value, or :invalid (eg 1 + (2 > 3))
	def check_type
		l = @lexpr.kind_of?(self.class) ? @lexpr.check_type : :value
		r = @rexpr.kind_of?(self.class) ? @rexpr.check_type : :value
		case @op
		when :'!'
			r == :bool ? :bool : :invalid
		when :'&&', :'||'
			r == l ? r == :bool  ? :bool  : :invalid : :invalid
		when :<, :>, :==, :'!='
			r == l ? r == :value ? :bool  : :invalid : :invalid
		else
			r == l ? r == :value ? :value : :invalid : :invalid
		end
	end

	class << self
		# key = operator, value = hash regrouping operators of lower precedence
		OP_PRIO = [[:'||'], [:'&&'], [:<, :>, :'==', :'!='], [:|], [:^], [:&], [:<<, :>>], [:+, :-], [:*, :/, :%]].inject({}) { |h, oplist|
			lessprio = h.keys.inject({}) { |hh, op| hh.update op => true }
			oplist.each { |op| h[op] = lessprio }
			h }

		def parse_bool(lexer)
			opstack = []
			stack = []

			return if lexer.eos? or not e = parse_bool_expr(lexer)

			stack << e

			loop do
				case tok = lexer.readtok
				when :<, :>, :'==', :'!=', :'||', :'&&',
				     :-, :+, :*, :/, :%, :|, :&, :<<, :>>
					until opstack.empty? or OP_PRIO[tok][opstack.last]
						stack << new(opstack.pop, stack.pop, stack.pop)
					end

					opstack << tok

					raise lexer, "Invalid bool expression" unless e = parse_bool_expr(lexer)
					stack << e
				else
					lexer.unreadtok tok
					break
				end
			end

			until opstack.empty?
				stack << new(opstack.pop, stack.pop, stack.pop)
			end

			e = stack.first
			e = new(:+, e, nil) unless e.kind_of? self
			raise lexer, 'Invalid bool expression' if e.check_type == :invalid
			e
		end

		def parse_bool_expr(lexer)
			case tok = lexer.readtok
			when :'!'
				return unless e = parse_bool_expr(lexer)
				new(tok, e, nil)
			when :'('
				return unless e = parse_bool(lexer)
				raise lexer, "Bool expression: ')' expected" unless lexer.readtok == :')'
				e
			when :eol
				parse_bool_expr lexer
			else
				lexer.unreadtok(tok)
				parse_expr(lexer)
			end
		end

		# returns an Expression or nil if unparsed
		def parse(lexer)
			opstack = []
			stack = []

			return if lexer.eos? or not e = parse_expr(lexer)
			stack << e

			loop do
				case tok = lexer.readtok
				when :-, :+, :*, :/, :%, :|, :&, :<<, :>>
					lessprio = OP_PRIO[tok]
					
					until opstack.empty? or lessprio[opstack.last]
						stack << new(opstack.pop, stack.pop, stack.pop)
					end
					
					opstack << tok
					
					raise lexer, "Invalid expression" unless e = parse_expr(lexer)
					stack << e
				else
					lexer.unreadtok tok
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

		def parse_expr(lexer)
			case tok = lexer.readtok
			when :+, :-, :~
				# unary operator
				return unless e = parse_expr(lexer)
				new(tok, e, nil)
			when :'('
				# parenthesis
				return unless e = parse(lexer)
				raise lexer, "Expression: ')' expected" unless lexer.readtok == :')'
				e
			when Numeric, self, String
# TODO				if %w[addr near short offset].include?(tok)
#					puts "#{tok} modifier ignored" if $VERBOSE
#					parse_expr(lexer)
				tok
			when Lexer::QString
				t = tok.text
				t = t.reverse if lexer.cpu.endianness == :little rescue nil
				t.unpack('C*').inject(0) { |v, b| (v << 8) | b }
			when :eol
				parse_expr lexer
			when nil
				nil
			else
				raise lexer, "Expression parser: #{tok.inspect} unexpected"
			end
		end
	end
end
end
