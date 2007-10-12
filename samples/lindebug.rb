#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# 
# this is a linux/x86 debugger with a curses interface
#

require 'rubstop'
require 'ncurses'

# fix the ^@$#$% ncurses interface
module Ncurses
	PAIRID = {}
	def self.my_init_pair(id, fg, bg)
		PAIRID[id] = PAIRID.values.max || 0
		init_pair(PAIRID[id], fg, bg)
	end
	class WINDOW
		%w[delwin getmaxx getmaxy mvwaddstr].each { |meth|
			define_method(meth) { |*a| Ncurses.send(meth, self, *a) }
		}
		def box(v=ACS_VLINE, h=ACS_HLINE) Ncurses.box(self, v, h) end
		def color(col) color_set(Ncurses.COLOR_PAIR(PAIRID[col]), nil) end
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
	def init_screen
		@curses_scr = Ncurses.initscr	# initialize screen
		@console_width  = @curses_scr.getmaxx
		@console_height = @curses_scr.getmaxy
		@windows = []
		Ncurses.curs_set 1		# show cursor
		Ncurses.noecho			# do not show keypresses
		Ncurses.keypad @curses_scr, 1	# activate keypad (needed to catch F1, arrows etc)
		Ncurses.cbreak			# config keyboard 
		Ncurses.start_color
		Ncurses.my_init_pair(:normal,  Ncurses::COLOR_WHITE, Ncurses::COLOR_BLACK)
		Ncurses.my_init_pair(:changed, Ncurses::COLOR_BLUE,  Ncurses::COLOR_BLACK)
		Ncurses.my_init_pair(:hilight, Ncurses::COLOR_BLACK, Ncurses::COLOR_YELLOW)
		Ncurses.my_init_pair(:border,  Ncurses::COLOR_GREEN, Ncurses::COLOR_BLACK)
		@regs_window = new_window 4
		@regs_window.color :border
		@regs_window.box
		@data_window = new_window(@data_height = 20)
		@code_window = new_window(@code_height = 20)
		cur_y = @windows.inject(0) { |cur_y, w| cur_y + w.getmaxy }
		@prpt_height = @console_height-cur_y
		@prpt_window = Ncurses::WINDOW.new(@prpt_height, @console_width, cur_y, 0)
	end

	def new_window(height)
		cur_y = @windows.inject(0) { |cur_y, w| cur_y + w.getmaxy }
		@windows << Ncurses::WINDOW.new(height, @console_width, cur_y, 0)
		@windows.last
	end

	def fini_screen
		@windows.each { |w| w.delwin }
		@prpt_window.delwin
		Ncurses.endwin
	end

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

		@prompthistlen = 20
		@prompthistory = []
		@promptloglen = 200
		@promptlog = ['']*50
		@dataptr = 0
		@datafmt = 'db'
		@has_pax = false

		begin
		begin
			init_screen
			main_loop
			@rs.detach rescue nil
		ensure
			fini_screen
			puts
		end
		rescue
			@rs.kill rescue nil
			puts $!, $!.backtrace
		end
	end

	def update
		@curses_scr.refresh
		updateregs
		updatecode
		updatedata
		updateprompt
	end

	EFLAGS = {0 => 'c', 2 => 'p', 4 => 'a', 6 => 'z', 7 => 's', 11 => 'o'}
	def updateregs
		@regs_window.erase
		@regs_window.color :border
		@regs_window.box
		@regs_window.color :normal

		x, y = 2, 1
		%w[eax ebx ecx edx eip].each { |r|
			@regs_window.mvwaddstr y, x, r + '='
			x += r.length+1
			@regs_window.color :changed if @regs[r] != @oldregs[r]
			@regs_window.mvwaddstr y, x, '%08x' % @regs[r]
			@regs_window.color :normal if @regs[r] != @oldregs[r]
			x += 10
		}
		x, y = 2, 2
		%w[esi edi ebp esp eflags].each { |r|
			@regs_window.mvwaddstr y, x, r + '='
			x += r.length+1
			@regs_window.color :changed if @regs[r] != @oldregs[r]
			@regs_window.mvwaddstr y, x, '%08x' % @regs[r]
			@regs_window.color :normal if @regs[r] != @oldregs[r]
			x += 10
		}
		EFLAGS.sort.each { |off, flag|
			val = @regs['eflags'] & (1<<off)
			flag = flag.upcase if val != 0
			if @oldregs['eflags'] and val != @oldregs['eflags'] & (1 << off)
				@regs_window.color :changed
				@regs_window.mvwaddstr y, x, flag
				@regs_window.color :normal
			else
				@regs_window.mvwaddstr y, x, flag
			end
			x += 2
		}
		
		@regs_window.refresh
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
					loadsyms(base, base.to_s(16)) rescue nil
					break
				end
				base -= 0x1000
			}
		end

		@code_window.erase
		@code_window.color :border
		@code_window.box
		@code_window.mvwaddstr 0, [@console_width-100, 1].max, ' ' + findsymbol(addr) + ' '
		@code_window.color :normal

		y = 1
		while y < @code_height-1
			if @symbols[addr]
				@code_window.mvwaddstr y, 1, "#{@symbols[addr]}:"
				y += 1
				break if y >= @code_height-1
			end
			@code_window.color :hilight if addr == @regs['eip']
			@code_window.mvwaddstr y, 1, '%08x' % addr
			di = @rs.mnemonic_di(addr)
			@curinstr = di if addr == @regs['eip']
			len = di.instruction ? di.bin_length : 1
			@code_window.mvwaddstr y, 12, @rs[addr, [len, 10].min].unpack('C*').map { |c| '%02x' % c }.join
			if di.instruction
				@code_window.mvwaddstr y, 34, '*' if addr == @regs['eip']
				@code_window.mvwaddstr y, 35, di.instruction.to_s
				addr += di.bin_length
			else
				@code_window.mvwaddstr y, 35, '<unk>'
				addr += 1
			end
			@code_window.color :normal if addr == @regs['eip']
			y += 1
		end

		@code_window.refresh
	end

	def updatedata
		addr = @dataptr

		@data_window.erase
		@data_window.color :border
		@data_window.box
		@data_window.mvwaddstr 0, [@console_width-100, 1].max, ' ' + findsymbol(addr) + ' '
		@data_window.color :normal

		(1..@data_height-2).each { |y|
			raw = @rs[addr, 16]
			@data_window.mvwaddstr y, 1, '%08x' % addr
			x = 11
			case @datafmt
			when 'db': raw.unpack('C*').each { |c| @data_window.mvwaddstr(y, x, '%02x'%c) ; x+=3 }
			when 'dw': raw.unpack('S*').each { |c| @data_window.mvwaddstr(y, x, '%04x'%c) ; x+=5 }
			when 'dd': raw.unpack('L*').each { |c| @data_window.mvwaddstr(y, x, '%08x'%c) ; x+=9 }
			end
			@data_window.mvwaddstr y, x+1, raw.unpack('C*').map { |c| (0x20..0x7e).include?(c) ? c : ?. }.pack('C*')
			addr += 16
		}

		@data_window.refresh
	end

	def updateprompt(back=0)
		@prpt_window.erase
		@prpt_window.color :border
		@prpt_window.box
		@prpt_window.color :normal

		y = 1
		@promptlog[-[(@prpt_height-3)*(back+1), @promptlog.length].min, @prpt_height-3].each { |l|
			@prpt_window.mvaddstr(y, 1, l)
			y += 1
		}

		@prpt_window.mvwaddstr(y, 1, ':'+@promptbuf)

		@prpt_window.move y, @promptpos+2

		@prpt_window.refresh
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
		case cmd
		when 'kill'
			@rs.kill
			@running = false
			log 'killed'
		when 'q', 'quit', 'detach', 'exit'
			@rs.detach
			@runing = false
		when 'bpx'
			addr = argint[] || return
			bpx addr
		when 'bphw'
			type = lex.readtok.raw if ntok
			addr = argint[] || return
			set_hwbp type, addr
		when 'bl'
			@breakpoints.sort.each { |addr, oct|
				log "bpx at #{findsymbol(addr)}"
			}
			(0..3).each { |dr|
				if @regs['dr7'] & (1 << (2*dr)) != 0
					log "bphw #{{0=>'x', 1=>'w', 2=>'?', 3=>'r'}[(@regs['dr7'] >> (16+4*dr)) & 3]} at #{findsymbol(@regs["dr#{dr}"])}"
				end
			}
		when 'bc'
			@breakpoints.each { |addr, oct| @rs[addr] = oct }
			@breakpoints.clear
			if @regs['dr7'] & 0xff != 0
				@rs.dr7 = 0 
				readregs
			end
		when 'd'
			@dataptr = argint[] || return
		when 'db', 'dw', 'dd'
			@datafmt = cmd.dup
			@dataptr = argint[] || return if ntok
		when 'r'
			return if not ntok
			r = lex.readtok.raw
			nil while ntok = lex.readtok and ntok.type == :space
			if r == 'fl'
				return if not ntok
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
				@rs.send r+'=', argint[] || return
				readregs
			else
				log "#{r} = #{@regs[r]}"
			end
		when 'run', 'cont'
			cont
		when 'syscall'
			syscall
		when 'g'
			addr = argint[] || return
			bpx addr, true
			cont
		when 'u'
			@codeptr = argint[] || return
		when 'has_pax'
			val = ntok ? argint[] || return : 1
			@has_pax = (val != 0)
			log "has_pax now #@has_pax"
		when 'loadsyms'
			File.read("/proc/#{@rs.pid}/maps").each { |l|
				name = l.split[5]
				loadsyms l.to_i(16), name if name and name[0] == ?/
			}
		when 'sym'
			sym = ''
			sym << ntok.raw while ntok = lex.readtok
			s = @symbols.keys.find_all { |s| @symbols[s] =~ /#{sym}/ }
			if s.empty?
				log "unknown symbol #{sym}"
			else
				s.each { |s| log "#{'%08x' % s} #{@symbols_len[s].to_s.ljust 6} #{findsymbol(s)}" }
			end
		when 'help'
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
			log 'keys:'
			log ' F10: step over'
			log ' F11: single step'
			log ' pgup/pgdown: move command history'
			log ' alt+pgup/pgdown/up/down: move data pointer'
		else log 'unknown command'
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
		e.decode
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
		log "loaded #{@symbols.length-oldsyms} symbols from #{name} at #{'%08x' % baseaddr}"
		updateprompt
	end

	def main_loop
		@promptbuf = ''
		@promptpos = 0
		@prompthistory = []
		@running = true
		logback=0
		update
		while @running and c = @curses_scr.getch
			# log "key #{c.to_s 16} (#{Ncurses.constants.find { |k| k[0,4]=='KEY_' and Ncurses.const_get(k) == c }})"
			case c
			when 4: log 'exiting'; break	 # eof
			when 27		# esc/composed key
				if IO::select([$stdin], nil, nil, 0) and c1 = @curses_scr.getch
					if IO::select([$stdin], nil, nil, 0) and c2 = @curses_scr.getch
						case [c1, c2]
						when [0x4f, 0x50]: c = Ncurses::KEY_F1; redo
						when [0x4f, 0x51]: c = Ncurses::KEY_F2; redo
						when [0x4f, 0x52]: c = Ncurses::KEY_F3; redo
						when [0x4f, 0x53]: c = Ncurses::KEY_F4; redo
						when [0x5b, 0x31]: c = Ncurses::KEY_F5; redo
						else log "unknown esc2 #{c1.to_s 16}h #{c2.to_s 16}h"; c = 0; redo
						end
					else
						case c1
						when Ncurses::KEY_PPAGE: @dataptr = (@dataptr - 16*(@data_height-2)) & 0xffff_ffff; updatedata; next
						when Ncurses::KEY_NPAGE: @dataptr = (@dataptr + 16*(@data_height-2)) & 0xffff_ffff; updatedata; next
						when Ncurses::KEY_UP:    @dataptr = (@dataptr - 16) & 0xffff_ffff; updatedata; next
						when Ncurses::KEY_DOWN:  @dataptr = (@dataptr + 16) & 0xffff_ffff; updatedata; next
						else log "unknown esc1 #{c1.to_s 16}h"; c = 0; redo
						end
					end
				end
				log 'exiting'
				break
			when Ncurses::KEY_F5: cont; break if $?.exited?
			when Ncurses::KEY_F10: stepover; break if $?.exited?
			when Ncurses::KEY_F11: singlestep; break if $?.exited?
			when Ncurses::KEY_DOWN
				@prompthistory |= [@promptbuf]
				@prompthistory.push @prompthistory.shift
				@promptbuf = @prompthistory.last
				@promptpos = @promptbuf.length
			when Ncurses::KEY_UP
				@prompthistory |= [@promptbuf]
				@prompthistory.unshift @prompthistory.pop
				@promptbuf = @prompthistory.last
				@promptpos = @promptbuf.length
			when Ncurses::KEY_LEFT:  @promptpos -= 1 if @promptpos > 0
			when Ncurses::KEY_RIGHT: @promptpos += 1 if @promptpos < @promptbuf.length
			when Ncurses::KEY_HOME:  @promptpos = 0
			when Ncurses::KEY_END:   @promptpos = @promptbuf.length
			when Ncurses::KEY_BACKSPACE: @promptbuf[@promptpos-=1, 1] = '' if @promptpos > 0
			when Ncurses::KEY_DC: @promptbuf[@promptpos, 1] = '' if @promptpos < @promptbuf.length
			when Ncurses::KEY_PPAGE: updateprompt(logback+=1); next
			when Ncurses::KEY_NPAGE: updateprompt(logback <= 0 ? logback : logback-=1); next
			#when ?\t:	# autocomplete
			when ?\n: exec_prompt
			when 0x20..0x7e
				@promptbuf[@promptpos, 0] = c.chr
				@promptpos += 1
			else log "unknown key pressed #{c.to_s 16} (#{Ncurses.constants.find { |k| k[0,4]=='KEY_' and Ncurses.const_get(k) == c }})"
			end
			begin
				update
			rescue Errno::ESRCH
				break
			end
		end
		logback=0
		checkbp
		updateprompt
	end
end

if $0 == __FILE__
	LinDebug.new(ARGV.shift)
end
