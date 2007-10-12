#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# 
# this is a linux/x86 debugger with a console interface
#

require 'rubstop'

module Ansi
	CursHome = "\e[H".freeze
	ClearLineAfter  = "\e[0K"
	ClearLineBefore = "\e[1K"
	ClearLine = "\e[2K"
	ClearScreen = "\e[2J"
	def self.set_cursor_pos(y=1,x=1) "\e[#{y};#{x}H" end
	Reset = "\e[m"
	Colors = [:black, :red, :green, :yellow, :blue, :magenta, :cyan, :white, :aoeu, :reset]
	def self.color(*args)
		fg = true
		"\e[" << args.map { |a|
			case a
			when :bold: 2
			when :negative: 7
			when :normal: 22
			when :positive: 27
			else
				if col = Colors.index(a)
					add = (fg ? 30 : 40)
					fg = false
					col+add
				end
			end
		}.compact.join(';') << 'm'
	end
	def self.hline(len) "\e(0"<<'q'*len<<"\e(B" end

	TIOCGWINSZ = 0x5413
	TCGETS = 0x5401
	TCSETS = 0x5402
	CANON = 2
	ECHO  = 8
	def self.get_terminal_size
		s = ''.ljust(8)
		$stdin.ioctl(TIOCGWINSZ, s) >= 0 ? s.unpack('SS') : [80, 25]
	end
	def self.set_term_canon(bool)
		tty = ''.ljust(256)
		$stdin.ioctl(TCGETS, tty)
		if bool
			tty[12] &= ~(ECHO|CANON)
		else
			tty[12] |= ECHO|CANON
		end
		$stdin.ioctl(TCSETS, tty)
	end

	ESC_SEQ = {'A' => :up, 'B' => :down, 'C' => :right, 'D' => :left,
		'1~' => :home, '2~' => :inser, '3~' => :suppr, '4~' => :end,
		'5~' => :pgup, '6~' => :pgdown,
		'P' => :f1, 'Q' => :f2, 'R' => :f3, 'S' => :f4,
		'15~' => :f5, '17~' => :f6, '18~' => :f7, '19~' => :f8,
		'20~' => :f9, '21~' => :f10, '23~' => :f11, '24~' => :f12 }
	def self.getkey
		c = $stdin.getc
		return c if c != ?\e
		c = $stdin.getc
		if c != ?[ and c != ?O
			$stdin.ungetc c
			return ?\e
		end
		seq = ''
		loop do
			c = $stdin.getc
			seq << c
			case c; when ?a..?z, ?A..?Z, ?~: break end
		end
		ESC_SEQ[seq] || seq
	end
end

class Indirect
	attr_accessor :ptr, :sz
	UNPACK_STR = {1 => 'C', 2 => 'S', 4 => 'L'}
	def initialize(ptr, sz) @ptr, @sz = ptr, sz end
	def bind(bd)
		raw = bd['tracer_memory'][@ptr.bind(bd).reduce, @sz]
		Metasm::Expression[raw.unpack(UNPACK_STR[@sz]).first]
	end
end

class ExprParser < Metasm::Expression
	def self.parse_intfloat(lex, tok)
		case tok.raw
		when 'byte', 'word', 'dword'
			nil while ntok = lex.readtok and ntok.type == :space
			nil while ntok = lex.readtok and ntok.type == :space if ntok and ntok.raw == 'ptr'
			if ntok and ntok.raw == '['
				tok.value = Indirect.new(parse(lex), {'byte' => 1, 'word' => 2, 'dword' => 4}[tok.raw])
				nil while ntok = lex.readtok and ntok.type == :space
				nil while ntok = lex.readtok and ntok.type == :space if ntok and ntok.raw == ']'
				lex.unreadtok ntok
			end
		else super
		end
	end
	def self.parse_value(lex)
		nil while tok = lex.readtok and tok.type == :space
		lex.unreadtok tok
		if tok.type == :punct and tok.raw == '['
			tt = tok.dup
			tt.type = :string
			tt.raw = 'dword'
			lex.unreadtok tt
		end
		super
	end
end

class LinDebug
	attr_accessor :win_data_height, :win_code_height, :win_prpt_height
	def init_screen
		@console_height, @console_width = Ansi.get_terminal_size
		Ansi.set_term_canon(true)
		@win_data_height = 20
		@win_code_height = 20
		@win_prpt_height = @console_height-(@win_data_height+@win_code_height+2)
	end

	def fini_screen
		Ansi.set_term_canon(false)
	end

	def win_data_start; 2 end
	def win_code_start; win_data_start+win_data_height end
	def win_prpt_start; win_code_start+win_code_height end

	Color = {:changed => Ansi.color(:blue, :bold), :border => Ansi.color(:green),
		:normal => Ansi.color(:white, :black, :normal), :hilight => Ansi.color(:blue, :white, :normal)}

	def initialize(target)
		@rs = Metasm::Rubstop.new(target)
		@regs = {}
		@oldregs = {}
		readregs
		@breakpoints = {}
		@singleshot = {}
		@wantbp = nil
		@symbols = {}
		@symbols_len = {}
		@filemap = {}
		@has_pax = false
		@dataptr = 0
		@datafmt = 'db'

		@prompthistlen = 20
		@prompthistory = []
		@promptloglen = 200
		@promptlog = []
		@promptbuf = ''
		@promptpos = 0
		@log_off = 0

		@focus = :prompt
		@command = {}
		load_commands

		begin
			begin
				init_screen
				main_loop
			ensure
				fini_screen
				puts
			end
		rescue
			puts $!, $!.backtrace
		end
		puts @promptlog[-1]
		((target.to_i == 0) ? @rs.kill : @rs.detach) rescue nil
	end
	
	def update
		#print Color[:normal] + Ansi::ClearScreen
		print Ansi.set_cursor_pos(0, 0) + updateregs + updatedata + updatecode + updateprompt
	end

	EFLAGS = {0 => 'c', 2 => 'p', 4 => 'a', 6 => 'z', 7 => 's', 9 => 'i', 10 => 'd', 11 => 'o'}
	def updateregs
		@oldregs = @regs.dup if @oldregs.empty?
		text = ''
		text << ' '
		x = 1
		%w[eax ebx ecx edx eip].each { |r|
			text << Color[:changed] if @regs[r] != @oldregs[r]
			text << r.upcase << ?=
			text << ('%08X' % @regs[r])
			text << Color[:normal] if @regs[r] != @oldregs[r]
			text << '  '
			x += r.length + 11
		}
		text << (' '*(@console_width-x)) << "\n" << ' '
		x = 1
		%w[esi edi ebp esp].each { |r|
			text << Color[:changed] if @regs[r] != @oldregs[r]
			text << r.upcase << ?=
			text << ('%08X' % @regs[r])
			text << Color[:normal] if @regs[r] != @oldregs[r]
			text << '  '
			x += r.length + 11
		}
		EFLAGS.sort.each { |off, flag|
			val = @regs['eflags'] & (1<<off)
			flag = flag.upcase if val != 0
			if val != @oldregs['eflags'] & (1 << off)
				text << Color[:changed]
				text << flag
				text << Color[:normal]
			else
				text << flag
			end
			text << ' '
			x += 2
		}
		text << (' '*(@console_width-x)) << "\n"
	end

	def updatecode
		if @codeptr
			addr = @codeptr
		elsif @oldregs['eip'] and @oldregs['eip'] < @regs['eip'] and @oldregs['eip'] + 8 >= @regs['eip']
			addr = @oldregs['eip']
		else
			addr = @regs['eip']
		end

		if findfilemap(addr) == '???'
			base = addr & 0xffff_f000
			8.times {
				sig = @rs[base, 4]
				if sig == "\x7fELF"
					loadsyms(base, base.to_s(16))
					break
				end
				base -= 0x1000
			}
		end

		text = ''
		text << Color[:border]
		title = findsymbol(addr)
		pre  = [@console_width-100, 6].max
		post = @console_width - (pre + title.length + 2)
		text << Ansi.hline(pre) << ' ' << title << ' ' << Ansi.hline(post)
		text << Color[:normal]
		text << "\n"

		cnt = @win_code_height
		while (cnt -= 1) > 0
			if @symbols[addr]
				text << ('    ' << @symbols[addr] << ?:).ljust(@console_width) << "\n"
				break if (cnt -= 1) <= 0
			end
			text << Color[:hilight] if addr == @regs['eip']
			text << ('%08x' % addr)
			di = @rs.mnemonic_di(addr)
			@curinstr = di if addr == @regs['eip']
			len = di.instruction ? di.bin_length : 1
			text << '  '
			text << @rs[addr, [len, 10].min].unpack('C*').map { |c| '%02x' % c }.join.ljust(22)
			if di.instruction
				text << ((addr == @regs['eip'] ? '*' : ' ') << di.instruction.to_s).ljust(@console_width-32)
			else
				text << ' <unk>'.ljust(@console_width-32)
			end
			text << Color[:normal] if addr == @regs['eip']
			addr += len
			text << "\n"
		end
		text
	end

	def updatedata
		addr = @dataptr

		text = ''
		text << Color[:border]
		title = findsymbol(addr)
		pre  = [@console_width-100, 6].max
		post = @console_width - (pre + title.length + 2)
		text << Ansi.hline(pre) << ' ' << title << ' ' << Ansi.hline(post)
		text << Color[:normal]

		cnt = @win_data_height
		while (cnt -= 1) > 0
			raw = @rs[addr, 16]
			l = ('%08x' % addr) << '  '
			case @datafmt
			when 'db': l << raw[0,8].unpack('C*').map { |c| '%02x ' % c }.join << ' ' <<
				   raw[8,8].unpack('C*').map { |c| '%02x ' % c }.join
			when 'dw': l << raw.unpack('S*').map { |c| '%04x ' % c }.join
			when 'dd': l << raw.unpack('L*').map { |c| '%08x ' % c }.join
			end
			l << ' ' << raw.unpack('C*').map { |c| (0x20..0x7e).include?(c) ? c : ?. }.pack('C*')
			text << l.ljust(@console_width) << "\n"
		end
		text
	end

	def updateprompt
		text = ''
		text << Color[:border] << Ansi.hline(@console_width) << Color[:normal] << "\n"

		@log_off = @promptlog.length - 2 if @log_off >= @promptlog.length
		@log_off = 0 if @log_off < 0
		len = @win_prpt_height - 2
		len.times { |i|
			i += @promptlog.length - @log_off - len
			l = (@promptlog[i] if i >= 0) || ''
			text << l.ljust(@console_width) << "\n"
		}
		text << ':' << @promptbuf.ljust(@console_width-1) << Ansi.set_cursor_pos(@console_height, @promptpos+2)
	end

	def readregs
		%w[eax ebx ecx edx esi edi esp ebp eip eflags dr0 dr1 dr2 dr3 dr6 dr7].each { |r| @regs[r] = @rs.send(r) }
	end

	def checkbp
		::Process::waitpid(@rs.pid, ::Process::WNOHANG) if not $?
		return if not $?
		if not $?.stopped?
			if $?.exited?:      log "process exited with status #{$?.exitstatus}"
			elsif $?.signaled?: log "process exited due to signal #{$?.termsig} (#{Signal.list.index $?.termsig})"
			else                log "process in unknown status #{$?.inspect}"
			end
			return
		elsif $?.stopsig != Signal.list['TRAP']
			log "process stopped due to signal #{$?.stopsig} (#{Signal.list.index $?.stopsig})"
		end
		@codeptr = nil
		if @breakpoints[@regs['eip']-1] and @rs[@regs['eip']-1] == 0xcc
			@rs[@regs['eip']-1] = @breakpoints.delete @regs['eip']-1
			@rs.eip = @regs['eip'] -= 1
			@wantbp = @regs['eip'] if not @singleshot.delete @regs['eip']
		elsif @regs['dr6'] & 15 != 0
			dr = (0..3).find { |dr| @regs['dr6'] & (1 << dr) != 0 }
			@wantbp = "dr#{dr}" if not @singleshot.delete @regs['eip']
			@rs.dr6 = 0
			@rs.dr7 = @regs['dr7'] & (0xffff_ffff ^ (3 << (2*dr)))
			readregs
		end
	end

	def bpx(addr, singleshot=false)
		return if @breakpoints[addr]
		if @has_pax
			set_hwbp 'x', addr
		else
			begin
				@breakpoints[addr] = @rs[addr]
				@rs[addr] = 0xcc
			rescue Errno::EIO
				log 'i/o error when setting breakpoint, switching to PaX mode'
				@has_pax = true
				@breakpoints.delete addr
				bpx(addr)
			end
		end
		@singleshot[addr] = true if singleshot
	end

	def cont
		singlestep if @wantbp
		@rs.cont
		return if $?.exited?
		@oldregs.update @regs
		readregs
		checkbp
	end

	def singlestep(justcheck=false)
		@rs.singlestep
		return if $?.exited?
		case @wantbp
		when ::Integer: bpx @wantbp; @wantbp=nil
		when ::String: @rs.dr7 |= 1 << (2*@wantbp[2, 1].to_i) ; @wantbp=nil
		end
		return if justcheck
		@oldregs.update @regs
		readregs
		checkbp
	end

	def stepover
		if @curinstr.opcode and @curinstr.opcode.name == 'call'
			eaddr = @regs['eip'] + @curinstr.bin_length
			bpx eaddr, true
			cont
		else
			singlestep
		end
	end

	def syscall
		singlestep if @wantbp
		@rs.syscall
		return if $?.exited?
		@oldregs.update @regs
		readregs
		checkbp
	end

	def log(str)
		@promptlog << str
		@promptlog.shift if @promptlog.length > @promptloglen
	end

	def exec_prompt
		log ':'+@promptbuf
		return if @promptbuf == ''
		lex = Metasm::Preprocessor.new.feed @promptbuf
		@prompthistory << @promptbuf
		@prompthistory.shift if @prompthistory.length > @prompthistlen
		@promptbuf = ''
		@promptpos = @promptbuf.length
		argint = proc {
			begin
				raise if not e = ExprParser.parse(lex)
			rescue
				log 'syntax error'
				return
			end
			binding = @regs.dup
			ext = e.externals
			ext.map! { |exte| exte.kind_of?(Indirect) ? exte.ptr.externals : exte }.flatten! while not ext.grep(Indirect).empty?
			(ext - @regs.keys).each { |ex|
				if not s = @symbols.index(ex)
					log "unknown value #{ex}"
					return
				end
				binding[ex] = s
				if @symbols.values.grep(ex).length > 1
					log "multiple definitions found for #{ex}..."
				end
			}
			binding['tracer_memory'] = @rs
			e.bind(binding).reduce
		}

		cmd = lex.readtok
		cmd = cmd.raw if cmd
		nil while ntok = lex.readtok and ntok.type == :space
		lex.unreadtok ntok
		if @command.has_key? cmd
			@command[cmd].call(lex, argint)
		else
			if cmd and (poss = @command.keys.find_all { |c| c[0, cmd.length] == cmd }).length == 1
				@command[poss.first].call(lex, argint)
			else
				log 'unknown command'
			end
		end
	end

	def findfilemap(s)
		@filemap.keys.find { |k| @filemap[k][0] <= s and @filemap[k][1] > s } || '???'
	end

	def findsymbol(k)
		file = findfilemap(k) + '!'
		if s = @symbols.keys.find { |s| s <= k and s + @symbols_len[s] > k }
			file + @symbols[s] + (s == k ? '' : (k-s).to_s(16))
		else
			file + ('%08x' % k)
		end
	end

	def set_hwbp(type, addr, len=1)
		dr = (0..3).find { |dr| @regs['dr7'] & (1 << (2*dr)) == 0 and @wantbp != "dr#{dr}" }
		if not dr
			log 'no debug reg available :('
			return false
		end
		log "setting hwbp using dr#{dr}"
		@regs['dr7'] &= 0xffff_ffff ^ (0xf << (16+4*dr))
		case type
		when 'x': addr += 0x6000_0000 if @has_pax
		when 'r': @regs['dr7'] |= (((len-1)<<2)|3) << (16+4*dr)
		when 'w': @regs['dr7'] |= (((len-1)<<2)|1) << (16+4*dr)
		end
		@rs.send("dr#{dr}=", addr)
		@rs.dr6 = 0
		@rs.dr7 = @regs['dr7'] | (1 << (2*dr))
		readregs
		true
	end

	def loadsyms(baseaddr, name)
		@loadedsyms ||= {}
		return if @loadedsyms[name] or @rs[baseaddr, 4] != "\x7fELF"
		@loadedsyms[name] = true

		e = Metasm::LoadedELF.load @rs[baseaddr, 0x100_0000]
		begin
			e.decode
		rescue
			log "failed to load symbols from #{name}: #$!"
			($!.backtrace - caller).each { |l| log l.chomp }
			@filemap[baseaddr.to_s(16)] = [baseaddr, baseaddr+0x1000]
			return
		end

		name = e.tag['SONAME'] if e.tag['SONAME']
		#e = Metasm::ELF.decode_file name rescue return 	# read from disk

		last_s = e.segments.reverse.find { |s| s.type == 'LOAD' }
		vlen = last_s.vaddr + last_s.memsz
		vlen -= baseaddr if e.header.type == 'EXEC'
		@filemap[name] = [baseaddr, baseaddr + vlen]

		oldsyms = @symbols.length
		e.symbols.each { |s|
			next if not s.name or s.shndx == 'UNDEF'
			@symbols[baseaddr + s.value] = s.name
			@symbols_len[baseaddr + s.value] = s.size
		}
		if e.header.type == 'EXEC'
			@symbols[e.header.entry] = 'entrypoint'
			@symbols_len[e.header.entry] = 1
		end
		log "loaded #{@symbols.length-oldsyms} symbols from #{name} at #{'%08x' % baseaddr}"
		updateprompt
	end

	def main_loop
		@prompthistory = []
		@histptr = nil
		@running = true
		update
		while @running
			case k = Ansi.getkey
			when 4: log 'exiting'; break	 # eof
			when ?\e: focus = :prompt
			when :f5: cont
			when :f10: stepover
			when :f11: singlestep
			when :up
				if not @histptr
					@prompthistory << @promptbuf
					@histptr = 2
				else
					@histptr += 1
					@histptr = 1 if @histptr > @prompthistory.length
				end
				@promptbuf = @prompthistory[-@histptr].dup
				@promptpos = @promptbuf.length
			when :down
				if not @histptr
					@prompthistory << @promptbuf
					@histptr = @prompthistory.length
				else
					@histptr -= 1
					@histptr = @prompthistory.length if @histptr < 1
				end
				@promptbuf = @prompthistory[-@histptr].dup
				@promptpos = @promptbuf.length
			when :left:  @promptpos -= 1 if @promptpos > 0
			when :right: @promptpos += 1 if @promptpos < @promptbuf.length
			when :home:  @promptpos = 0
			when :end:   @promptpos = @promptbuf.length
			when :backspace, 0x7f: @promptbuf[@promptpos-=1, 1] = '' if @promptpos > 0
			when :suppr: @promptbuf[@promptpos, 1] = '' if @promptpos < @promptbuf.length
			when :pgup:  @log_off += @win_prpt_height-3
			when :pgdown: @log_off -= @win_prpt_height-3
			when ?\t:
				if not @promptbuf[0, @promptpos].include? ' '
					poss = @command.keys.find_all { |c| c[0, @promptpos] == @promptbuf[0, @promptpos] }
					if poss.length > 1
						log poss.sort.join(' ')
					elsif poss.length == 1
						@promptbuf[0, @promptpos] = poss.first + ' '
						@promptpos = poss.first.length+1
					end
				end
			when ?\n: @histptr = nil ; exec_prompt rescue log "#$!"
			when 0x20..0x7e
				@promptbuf[@promptpos, 0] = k.chr
				@promptpos += 1
			else log "unknown key pressed #{k.inspect}"
			end
			begin
				update
			rescue Errno::ESRCH
				break
			end
		end
		checkbp
	end

	def load_commands
		ntok = nil
		@command['kill'] = proc { |lex, int|
			@rs.kill
			@running = false
			log 'killed'
		}
		@command['quit'] = @command['detach'] = @command['exit'] = proc { |lex, int|
			@rs.detach
			@runing = false
		}
		@command['bpx'] = proc { |lex, int|
			addr = int[]
			bpx addr
		}
		@command['bphw'] = proc { |lex, int|
			type = lex.readtok.raw
			addr = int[]
			set_hwbp type, addr
		}
		@command['bl'] = proc { |lex, int|
			@breakpoints.sort.each { |addr, oct|
				log "bpx at #{findsymbol(addr)}"
			}
			(0..3).each { |dr|
				if @regs['dr7'] & (1 << (2*dr)) != 0
					log "bphw #{{0=>'x', 1=>'w', 2=>'?', 3=>'r'}[(@regs['dr7'] >> (16+4*dr)) & 3]} at #{findsymbol(@regs["dr#{dr}"])}"
				end
			}
		}
		@command['bc'] = proc { |lex, int|
			@breakpoints.each { |addr, oct| @rs[addr] = oct }
			@breakpoints.clear
			if @regs['dr7'] & 0xff != 0
				@rs.dr7 = 0 
				readregs
			end
		}
		@command['d'] = proc { |lex, int| @dataptr = int[] || return }
		@command['db'] = proc { |lex, int| @datafmt = 'db' ; @dataptr = int[] || return }
		@command['dw'] = proc { |lex, int| @datafmt = 'dw' ; @dataptr = int[] || return }
		@command['dd'] = proc { |lex, int| @datafmt = 'dd' ; @dataptr = int[] || return }
		@command['r'] = proc { |lex, int| 
			r = lex.readtok.raw
			nil while ntok = lex.readtok and ntok.type == :space
			if r == 'fl'
				flag = ntok.raw
				if not EFLAGS.index(flag)
					log "bad flag #{flag}"
				else
					@rs.eflags = @regs['eflags'] ^ (1 << EFLAGS.index(flag))
					readregs
				end
			elsif not @regs[r]
				log "bad reg #{r}"
			elsif ntok
				lex.unreadtok ntok
				@rs.send r+'=', int[]
				readregs
			else
				log "#{r} = #{@regs[r]}"
			end
		}
		@command['run'] = @command['cont'] = proc { |lex, int| cont }
		@command['syscall'] = proc { |lex, int| syscall }
		@command['singlestep'] = proc { |lex, int| singlestep }
		@command['stepover'] = proc { |lex, int| stepover }
		@command['g'] = proc { |lex, int| bpx int[], true ; cont }
		@command['u'] = proc { |lex, int| @codeptr = int[] || break }
		@command['has_pax'] = proc { |lex, int|
			@has_pax = int[]
			@has_pax = false if @has_pax == 0
			log "has_pax now #@has_pax"
		}
		@command['loadsyms'] = proc { |lex, int|
			File.read("/proc/#{@rs.pid}/maps").each { |l|
				name = l.split[5]
				loadsyms l.to_i(16), name if name and name[0] == ?/
			}
		}
		@command['sym'] = proc { |lex, int|
			sym = ''
			sym << ntok.raw while ntok = lex.readtok
			s = @symbols.keys.find_all { |s| @symbols[s] =~ /#{sym}/ }
			if s.empty?
				log "unknown symbol #{sym}"
			else
				s.each { |s| log "#{'%08x' % s} #{@symbols_len[s].to_s.ljust 6} #{findsymbol(s)}" }
			end
		}
		@command['help'] = proc { |lex, int|
			log 'commands: (addr/values are things like dword ptr [ebp+(4*byte [eax])] )'
			log ' bpx <addr>'
			log ' bphw [r|w|x] <addr>: debug register breakpoint'
			log ' bl: list breakpoints'
			log ' bc: clear breakpoints'
			log ' cont/run/F5'
			log ' d/db/dw/dd [<addr>]: change data type/address'
			log ' g <addr>: set a bp at <addr> and run'
			log ' has_pax [0|1]: set has_pax flag (hwbp+0x60000000 instead of bpx)'
			log ' kill'
			log ' loadsyms: load symbol information from mapped files (from /proc and disk)'
			log ' q/quit/detach/exit'
			log ' r <reg> [<value>]: show/change register'
			log ' r fl <flag>: toggle eflags bit'
			log ' sym <symbol regex>: show symbol information'
			log ' syscall: run til next syscall/bp'
			log ' u <addr>: disassemble addr'
			log ' reload: reload lindebug source'
			log ' ruby <ruby code>: instance_evals ruby code in current instance'
			log 'keys:'
			log ' F5: continue'
			log ' F10: step over'
			log ' F11: single step'
			log ' pgup/pgdown: move command history'
		}
		@command['reload'] = proc { |lex, int| load $0 ; load_commands }
		@command['ruby'] = proc { |lex, int|
			str = ''
			str << ntok.raw while ntok = lex.readtok
			instance_eval str
		}
		@command['resize'] = proc { |lex, int| @console_height, @console_width = Ansi.get_terminal_size }
		@command['wd'] = proc { |lex, int|
			@focus = :data
			@win_data_height = int[] || return
			@win_prpt_height = @console_height-(@win_data_height+@win_code_height+2)
		}
		@command['wc'] = proc { |lex, int|
			@focus = :code
			@win_code_height = int[] || return
			@win_prpt_height = @console_height-(@win_data_height+@win_code_height+2)
		}
	end
end


if $0 == __FILE__
	LinDebug.new(ARGV.shift)
end
