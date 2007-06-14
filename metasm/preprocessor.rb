require 'metasm/main'
require 'metasm/parse'

module Metasm
class Preprocessor
	class Macro
		attr_accessor :trace_dep
		def initialize(name)
			@name = name
			@body, @args = [], []
			@trace_dep = nil
		end

		# applies a preprocessor macro
		# parses arguments if needed 
		# returns an array of tokens
		def apply(lexer)
			# read arguments
			args = []
			lexer.skip_space
			if not @args.empty? and tok = lexer.nexttok and tok.type == :punct and tok.raw == '('
				lexer.readtok
				loop do
					lexer.skip_space_eol
					args << Expression.parse_toks(lexer)
					lexer.skip_space_eol
					raise @name, 'invalid arg list' if not tok = lexer.readtok or tok.type != :punct or (tok.raw != ')' and tok.raw != ',')
					break if tok.raw == ')'
				end
			end
			raise @name, 'invalid argument count' if args.length != @args.length

			lexer.traceary |= [self] if lexer.traceary and lexer.definition[@name.raw].trace_dep

			# apply macro
			@body.map { |t|
				if a = @args.find { |a| a.raw == t.raw }
					args[@args.index(a)]
				else
					t = t.dup
					t.backtrace += @name.backtrace[-2..-1] if not @name.backtrace.empty?
					t
				end
			}.flatten
		end

		# parses the argument list and the body from lexer
		def parse_definition(lexer)
			if tok = lexer.readtok_nopp and tok.type == :punct and tok.raw == '('
				loop do
					nil while tok = lexer.readtok_nopp and tok.type == :space
					raise @name, 'invalid arg definition' if not tok or tok.type != :string
					@args << tok
					nil while tok = lexer.readtok_nopp and tok.type == :space
					raise @name, 'invalid arg separator' if not tok or tok.type != :punct or (tok.raw != ')' and tok.raw != ',')
					break if tok.raw == ')'
				end
			else lexer.unreadtok tok
			end
			nil while tok = lexer.readtok_nopp and tok.type == :space
			lexer.unreadtok tok

			msg = (lexer.traceary and lexer.traceignore) ? :readtok_nopp : :readtok
			@trace_dep = [] if msg == :readtok_nopp
			while tok = lexer.send(msg) and tok.type != :eol
				@body << tok
				@trace_dep |= [lexer.definition[tok.raw]] if @trace_dep and lexer.definition[tok.raw]
			end
			lexer.unreadtok tok
		end

		def dump
			str = "// from #{@name.backtrace[-2]}:#{@name.backtrace[-1]}\n"
			str << "#define #{@name.raw}"
			if not @args.empty?
				str << '(' << @args.map { |t| t.raw }.join(', ') << ')'
			end
			str << ' ' << @body.map { |t| t.raw }.join << "\n"
		end
	end

	# set self.trace = [] to trace macro usage
	attr_accessor :traceignore, :traceary
	def initialize
		@queue = []
		@backtrace = []
		@definition = {}
		@include_search_path = @@include_search_path
		# stack of :accept/:discard/:discard_all/:testing, represents the current nesting of #if..#endif
		@ifelse_nesting = []
		@text = ''
		@pos = 0
		@filename = nil
		@lineno = nil
		@traceignore = false
		@traceary = nil
	end

	# preprocess text, and retrieve all macros defined in #included <files> and used in the text
	# returns a string useable as source
	# may not work if some macro is #defined, used, #undefined and then re-#defined differently
	def trace_macros(text, maxdepth=40)
		feed text
		@traceary = []
		readtok while not eos?
		str = []
		walk = proc { |a, d| @traceary |= a ; a.each { |m| walk[m.trace_dep, d-1] } if d > 0 }
		walk[@traceary, maxdepth]
		while not @traceary.empty?
			ngen = @traceary.find_all { |m| m.trace_dep.empty? }
			raise 'circular dependency ?' if ngen.empty?
			ngen.each { |m| str << m.dump }
			@traceary -= ngen
			@traceary.each { |m| m.trace_dep -= ngen }
		end
		str.join("\n")
	end

	# starts a new lexer, with the specified initial filename/line number (for backtraces)
	def feed(text, filename='<ruby>', lineno=0)
		raise ParseError, 'cannot start new text, did not finish current source' if not eos?
		@text = text
		@filename = filename
		@lineno = lineno
		@pos = 0
	end

	# reads one character from self.text
	# updates self.lineno
	def getchar
		c = @text[@pos]
		@lineno += 1 if c == ?\n
		@pos += 1
		c
	end

	# returns true if no more data is available
	def eos?
		@pos >= @text.length and @queue.empty? and @backtrace.empty?
	end

	# consumes all :space tokens
	def skip_space
		readtok while tok = nexttok and tok.type == :space
	end
	
	# consumes all :space or :eol tokens
	def skip_space_eol
		readtok while tok = nexttok and (tok.type == :space or tok.type == :eol)
	end
	
	# push back a token, will be returned on the next readtok/nexttok
	# lifo
	def unreadtok(tok)
		@queue << tok if tok
	end

	# peek next token w/o consuming it
	def nexttok
		tok = readtok
		unreadtok tok
		tok
	end

	# calls readtok_nopp and handles preprocessor directives
	def readtok_cpp
		lastpos = @pos
		tok = readtok_nopp

		if not tok
			# end of file: resume parent
			if not @backtrace.empty?
				@filename, @lineno, @text, @pos, @traceignore = @backtrace.pop
				tok = readtok
			end

		elsif tok.type == :eol or lastpos == 0
			unreadtok tok if lastpos == 0
			# detect preprocessor directive
			# state = 1 => seen :eol, 2 => seen #
			pretok = []
			rewind = true
			state = 1
			loop do
				pretok << (ntok = readtok_nopp)
				break if not ntok
				if ntok.type == :space	# nothing
				elsif state == 1 and ntok.type == :punct and ntok.raw == '#': state = 2
				elsif state == 2 and ntok.type == :string
					rewind = false if preprocessor_directive(ntok)
					break
				else break
				end
			end
			if rewind
				# false alarm: revert
				pretok.reverse_each { |t| unreadtok t }
			end
			tok = readtok if lastpos == 0

		elsif tok.type == :string and @definition[tok.raw]
			# expand macros
			body = @definition[tok.raw].apply(self)
			body.reverse_each { |t| unreadtok t }
			tok = body.empty? ? readtok : readtok_nopp

		elsif @ifelse_nesting.last == :testing and tok.type == :string and tok.raw == 'defined'
			preprocessor_directive(tok)
			tok = readtok_nopp
		end

		tok
	end
	alias readtok readtok_cpp

	# read and return the next token
	# parses quoted strings (set tok.value) and C/C++ comments (:space/:eol)
	def readtok_nopp
		return @queue.pop unless @queue.empty?

		tok = Token.new((@backtrace.map { |fn, lnn, *a| [fn, lnn] } + [@filename, @lineno]).flatten)

		case c = @text[@pos]
		when nil
			return nil
		when ?', ?"
			# read quoted string value
			tok.type = :quoted
			delimiter = c
			tok.raw << getchar
			tok.value = ''
			loop do
				raise tok, 'unterminated string' if not c = getchar
				tok.raw << c
				case c
				when delimiter: break
				when ?\\
					raise tok, 'unterminated escape' if not c = getchar
					tok.raw << c
					tok.value << \
					case c
					when ?n: ?\n
					when ?r: ?\r
					when ?t: ?\t
					when ?a: ?\a
					when ?b: ?\b
					# ruby's str.inspect chars
					when ?v: ?\v
					when ?f: ?\f
					when ?e: ?\e
					when ?#, ?\\, ?', ?": c
					when ?\n: ''
					when ?x:
						hex = ''
						while hex.length < 2
							raise tok, 'unterminated escape' if not c = @text[@pos]
							case c
							when ?0..?9, ?a..?f, ?A..?F
							else break
							end
							hex << c
							tok.raw << getchar
						end
						raise tok, 'unterminated escape' if hex.empty?
						hex.hex
					when ?0..?7:
						oct = '' << c
						while oct.length < 3
							raise tok, 'unterminated escape' if not c = @text[@pos]
							case c
							when ?0..?7
							else break
							end
							oct << c
							tok.raw << getchar
						end
						oct.oct
					else b	# raise tok, 'unknown escape sequence'
					end
				when ?\n: raise tok, 'unterminated string'
				else tok.value << c
				end
			end

		when ?a..?z, ?A..?Z, ?0..?9, ?$, ?_
			tok.type = :string
			loop do
				case @text[@pos]
				when ?a..?z, ?A..?Z, ?0..?9, ?$, ?_
					tok.raw << getchar
				else break
				end
			end

		when ?\\
			if @text[@pos+1] == ?\n
				tok.type = :space	# not :eol !
				tok.raw << getchar << getchar
			else
				tok.type = :punct
				tok.raw << getchar
			end

		when ?\ , ?\t, ?\r, ?\n
			tok.type = :space
			loop do
				case @text[@pos]
				when ?\ , ?\t, ?\r, ?\n
					tok.raw << getchar
				else break
				end
			end
			tok.type = :eol if tok.raw.index(?\n)

		when ?/
			# comment
			case @text[@pos+1]
			when ?/
				# till eol
				# a backslash before eol does not discard eol here (== C, != ruby)
				tok.type = :eol
				tok.raw << getchar << getchar
				while @text[@pos]
					tok.raw << (c = getchar)
					break if c == ?\n
				end
			when ?*
				tok.type = :space
				tok.raw << getchar << getchar
				seenstar = false
				loop do
					raise tok, 'unterminated c++ comment' if not @text[@pos]
					tok.raw << (c = getchar)
					case c
					when ?*: seenstar = true
					when ?/: break if seenstar	# no need to reset seenstar, already false
					else seenstar = false
					end
				end
			else
				# just a slash
				tok.type = :punct
				tok.raw << getchar
			end

		else
			tok.type = :punct
			tok.raw << getchar
		end

		tok
	end

	# handles #directives
	# returns true if the command is valid
	# second parameter for internal use
	def preprocessor_directive(cmd, ocmd = cmd)
		# read spaces, returns the next token
		skipspc = proc {
			loop do
				tok = readtok_nopp
				next if tok and tok.type == :space
				break tok
			end
		}

		case cmd.raw
		when 'if'
			case @ifelse_nesting.last
			when :accept, nil
				@ifelse_nesting << :testing
				test = Expression.parse(self)
				eol = skipspc[]
				raise cmd, 'pp syntax error' if eol and eol.type != :eol
				unreadtok eol
				case test.reduce
				when 0:       @ifelse_nesting[-1] = :discard
				when Integer: @ifelse_nesting[-1] = :accept
				else raise cmd, 'pp cannot evaluate condition'
				end
			when :discard, :discard_all
				@ifelse_nesting << :discard_all
			end

		when 'ifdef'
			case @ifelse_nesting.last
			when :accept, nil
				tok = skipspc[]
				eol = skipspc[]
				raise cmd, 'pp syntax error' if not tok or tok.type != :string or (eol and eol.type != :eol)
				unreadtok eol
				@ifelse_nesting << (@definition[tok.raw] ? :accept : :discard)
			when :discard, :discard_all
				@ifelse_nesting << :discard_all
			end

		when 'ifndef'
			case @ifelse_nesting.last
			when :accept, nil
				tok = skipspc[]
				eol = skipspc[]
				raise cmd, 'pp syntax error' if not tok or tok.type != :string or (eol and eol.type != :eol)
				unreadtok eol
				@ifelse_nesting << (@definition[tok.raw] ? :discard : :accept)
			when :discard, :discard_all
				@ifelse_nesting << :discard_all
			end

		when 'elif'
			case @ifelse_nesting.last
			when :accept
				@ifelse_nesting[-1] = :discard_all
			when :discard
				@ifelse_nesting[-1] = :testing
				test = Expression.parse(self)
				eol = skipspc[]
				raise cmd, 'pp syntax error' if eol and eol.type != :eol
				unreadtok eol
				case test.reduce
				when 0:       @ifelse_nesting[-1] = :discard
				when Integer: @ifelse_nesting[-1] = :accept
				else raise cmd, 'pp cannot evaluate condition'
				end
			when :discard_all
			else raise cmd, 'pp syntax error'
			end

		when 'else'
			eol = skipspc[]
			raise cmd, 'pp syntax error' if @ifelse_nesting.empty? or (eol and eol.type != :eol)
			unreadtok eol
			case @ifelse_nesting.last
			when :accept
				@ifelse_nesting[-1] = :discard_all
			when :discard
				@ifelse_nesting[-1] = :accept
			when :discard_all
			end

		when 'endif'
			eol = skipspc[]
			raise cmd, 'pp syntax error' if @ifelse_nesting.empty? or (eol and eol.type != :eol)
			unreadtok eol
			@ifelse_nesting.pop

		when 'defined'
			return false if not @ifelse_nesting.last == :testing
			opn = skipspc[]
			tok = skipspc[]
			cls = skipspc[]
			raise cmd, 'pp syntax error' if not cls or opn.type != :punct or opn.raw != '(' or cls.type != :punct or cls.raw != ')' or tok.type != :string
			ret = cmd.dup
			ret.type = :string
			ret.raw = @definition[tok.raw] ? '1' : '0'
			unreadtok ret

		when 'define'
			return if @ifelse_nesting.last and @ifelse_nesting.last != :accept

			tok = skipspc[]
			raise cmd, 'pp syntax error' if not tok or tok.type != :string
			puts "W: pp: redefinition of #{tok.raw} #{tok.backtrace_str}, prev def at #{@definition[tok.raw].name.backtrace_str}" if @definition[tok.raw]
			@definition[tok.raw] = Macro.new(tok)
			@definition[tok.raw].parse_definition(self)

		when 'undef'
			return if @ifelse_nesting.last and @ifelse_nesting.last != :accept

			tok = skipspc[]
			eol = skipspc[]
			raise cmd, 'pp syntax error' if not tok or tok.type != :string or (eol and eol.type != :eol)
			@definition.delete tok.raw
			unreadtok eol

		when 'include'
			return if @ifelse_nesting.last and @ifelse_nesting.last != :accept

			tok = skipspc[]
			raise cmd, 'pp syntax error' if not tok or (tok.type != :quoted and (tok.type != :punct or tok.raw != '<'))
			if tok.type == :quoted
				path = tok.raw[1..-2]	# XXX decode arbitrary bytes ?
			else
				path = readtok_nopp
				path.type = :string
				while tok = readtok_nopp and (tok.type != :punct or tok.raw != '>')
					path.raw << tok.raw
				end
				raise cmd, 'pp syntax error, unterminated path' if not tok
				path = path.raw
				dir = @include_search_path.find { |d| File.exist? File.join(d, path) }
				path = File.join(dir, path) if dir
				traceignore = true
			end
			raise cmd, 'pp: cannot find file to include' if not File.exist? path

			@backtrace << [@filename, @lineno, @text, @pos, @traceignore]
			@text = File.read(path)
			@pos = 0
			@filename = path
			@lineno = 0
			@traceignore ||= traceignore if @traceary

		else return false
		end

		# skip #undef'd parts of the source
		state = 1	# just seen :eol
		while @ifelse_nesting.last == :discard or @ifelse_nesting.last == :discard_all
			begin 
				tok = skipspc[]
			rescue ParseError
				# react as gcc -E: " unterminated in #undef => ok, /* unterminated => error
				retry
			end

			if not tok: raise ocmd, 'pp unterminated conditional'
			elsif tok.type == :eol: state = 1
			elsif state == 1 and tok.type == :punct and tok.raw == '#': state = 2
			elsif state == 2 and tok.type == :string: state = preprocessor_directive(tok, ocmd) ? 1 : 0
			else state = 0
			end
		end

		true
	end
end
end
