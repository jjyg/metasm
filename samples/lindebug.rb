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
	class WINDOW
		%w[delwin getmaxx getmaxy mvwaddstr].each { |meth|
			define_method(meth) { |*a| Ncurses.send(meth, self, *a) }
		}
		def box(v=ACS_VLINE, h=ACS_HLINE) Ncurses.box(self, v, h) end
		def color(col) color_set(Ncurses.COLOR_PAIR(col), nil) end
	end
end

class Indirect
	attr_accessor :ptr, :sz
	UNPACK_STR = {1 => 'C', 2 => 'S', 4 => 'L'}
	def initialize(ptr, sz) @ptr, @sz = ptr, sz end
	def bind(bd)
		raw = bd['tracer_memory'][@ptr.bind(bd).reduce, @sz]
		Metasm::Expression[(raw.unpack(UNPACK_STR[@sz]).first rescue 0)]
	end
end

class ExprParser < Metasm::Expression
	def parse_intfloat(lex, tok)
		case tok.raw
		when 'byte', 'word', 'dword'
			ntok = nil
			ntok = lex.readtok while ntok.type == :space
			ntok = lex.readtok while ntok.type == :space if ntok.raw == 'ptr'
			if ntok.raw == '['
				tok.value = Indirect.new(parse(lex), {'byte' => 1, 'word' => 2, 'dword' => 4}[tok.raw])
				ntok = lex.readtok while ntok.type == :space
				ntok = lex.readtok while ntok.type == :space if ntok.raw == ']'
				lex.unreadtok ntok
			end
		else super
		end
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
		Ncurses.init_pair(:normal,  Ncurses::COLOR_WHITE, Ncurses::COLOR_BLACK)
		Ncurses.init_pair(:changed, Ncurses::COLOR_BLUE,  Ncurses::COLOR_BLACK)
		Ncurses.init_pair(:hilight, Ncurses::COLOR_BLACK, Ncurses::COLOR_YELLOW)
		Ncurses.init_pair(:border,  Ncurses::COLOR_GREEN, Ncurses::COLOR_BLACK)
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
			init_screen
			main_loop
		ensure
			fini_screen
			@rs.detach rescue nil
			puts
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
		addr = @regs['eip']

		@code_window.erase
		@code_window.color :border
		@code_window.box
		@code_window.mvwaddstr 0, [@console_width-150, 1].max, ' ' + findsymbol(addr) + ' '
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
		@data_window.mvwaddstr 0, [@console_width-150, 1].max, ' ' + findsymbol(addr) + ' '
		@data_window.color :normal

		(1..@data_height-2).each { |y|
			raw = (@rs[addr, 16] rescue 0.chr*16)
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
		if @breakpoints[@regs['eip']-1] and @rs[@regs['eip']-1] == 0xcc
			@rs[@regs['eip']-1] = @breakpoints.delete @regs['eip']-1
			@rs.eip = @regs['eip'] -= 1
		end
	end

	def cont
		@rs.cont
		return if $?.exited?
		@oldregs.update @regs
		readregs
		checkbp
	end

	def singlestep
		@rs.singlestep
		return if $?.exited?
		@oldregs.update @regs
		readregs
		checkbp
	end

	def stepover
		if @curinstr.opcode and @curinstr.opcode.name == 'call'
			eaddr = @regs['eip'] + @curinstr.bin_length
			@breakpoints[eaddr] = @rs[eaddr]
			@rs[eaddr] = 0xcc
			cont
		else
			singlestep
		end
	end

	def syscall
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
		cmd, *args = @promptbuf.split ' '
		@promptbuf = ''
		@promptpos = @promptbuf.length

		argint = proc {
			e = ExprParser.parse Metasm::Preprocessor.new.feed(args.join(' '))
			e.bind(@symbols.invert.merge(@regs).merge('tracer_memory' => @rs)).reduce
		}

		case cmd
		when 'kill'
			@rs.kill
			@running = false
			log 'killed'
		when 'q', 'quit', 'detach', 'exit'
			@rs.detach
			@runing = false
		when 'bpx'
			addr = argint[]
			return if @breakpoints[addr]
			if @has_pax
				@breakpoints[addr] = @rs[addr] if set_hwbp 'x', addr
			else
				@breakpoints[addr] = @rs[addr]
				@rs[addr] = 0xcc
			end
		when 'bphw'
			type = args.shift
			addr = argint[]
			set_hwbp type, addr
			# TODO clear...
		when 'd'
			@dataptr = argint[]
		when 'db', 'dw', 'dd'
			@datafmt = cmd.dup
			@dataptr = argint[] if not args.empty?
		when 'r'
			r = args.shift
			if r == 'fl'
				flag = args.shift
				if not EFLAGS.index(flag)
					log "bad flag #{flag}"
				else
					@rs.eflags = @regs['eflags'] ^ (1 << EFLAGS.index(flag))
					readregs
				end
			elsif not @regs[r]
				log "bad reg #{r}"
			elsif not args.empty?
				@rs.send r+'=', argint[]
				readregs
			else
				log "#{r} = #{@regs[r]}"
			end
		when 'run', 'cont'
			cont
		when 'syscall'
			syscall
		when 'g'
			addr = argint[]
			return if @breakpoints[addr]
			if @has_pax
				@breakpoints[addr] = @rs[addr] if set_hwbp 'x', addr
			else
				@breakpoints[addr] = @rs[addr]
				@rs[addr] = 0xcc
			end
			cont
		when 'has_pax'
			val = args.empty? ? 1 : argint[]
			@has_pax = (val != 0)
			log "has_pax now #@has_pax"
		when 'help'
			log 'commands: (addr/values are things like dword ptr [ebp+(4*byte [eax])] )'
			log ' bpx <addr>'
			log ' bphw [r|w|x] <addr>: debug register breakpoint'
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
			log 'keys:'
			log ' F10: step over'
			log ' F11: single step'
			log ' pgup/pgdown: move command history'
			log ' alt+pgup/pgdown/up/down: move data pointer'
		when 'loadsyms'
			File.read("/proc/#{@rs.pid}/maps").each { |l| loadsyms l.to_i(16), l.split[5] }
update
		when 'sym'
			sym = args.shift
			s = @symbols.keys.find_all { |s| @symbols[s] =~ /#{sym}/ }
			if s.empty?
				log "unknown symbol #{sym}"
			else
				s.each { |s| log "#{'%08x' % s} #{@symbols_len[s]} #{findsymbol[s]}" }
			end
		when '', nil: return
		else
			log 'unknown command'
		end
		@prompthistory << @promptbuf
		@prompthistory.shift if @prompthistory.length > @prompthistlen
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
		if @regs['dr7'] & 0x55 == 0x55
			log 'no debug reg available :('
			return false
		end
		dr = (0..3).find { |dr| @regs['dr7'] & (1 << (2*dr)) == 0 }
		@regs['dr7'] &= 0xffff_ffff ^ (0xf << (16+4*dr))
		case type
		when 'x': addr |= 0x6000_0000 if @has_pax
		when 'r': @regs['dr7'] |= (((len-1)<<2)|3) << (16+4*dr)
		when 'w': @regs['dr7'] |= (((len-1)<<2)|1) << (16+4*dr)
		end
		@rs.send('dr'+dr+'=', addr)
		@rs.dr6 = 0
		@rs.dr7 = @regs['dr7'] | (1 << (2*dr))
		readregs
		true
	end

	def loadsyms(baseaddr, name)
		@loadedsyms ||= {0 => true} 	# TODO scan memory for pax-obfuscated pid/maps
		return if not name or name[0] != ?/ or @loadedsyms[name] or @loadedsyms[baseaddr] or @rs[baseaddr, 4] != "\x7fELF"
		@loadedsyms[name] = @loadedsyms[baseaddr] = true

		e = Metasm::ELF.decode_file name rescue return 	# read from disk

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
