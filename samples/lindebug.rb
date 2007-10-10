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

class LinDebug
	def init_screen
		@curses_scr = Ncurses.initscr	# initialize screen
		@console_width  = @curses_scr.getmaxx
		@console_height = @curses_scr.getmaxy
		@windows = []
		Ncurses.curs_set 0		# hide cursor
		Ncurses.noecho			# do not show keypresses
		Ncurses.keypad @curses_scr, 1	# activate keypad (needed to catch F1, arrows etc)
		Ncurses.cbreak			# catch everything, incl. ^C
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
		@prpt_height = @console_height-cur_y-1
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

		begin
			init_screen
			main_loop
		ensure
			fini_screen
			@rs.detach rescue nil
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
		@code_window.erase
		@code_window.color :border
		@code_window.box
		@code_window.color :normal

		addr = @regs['eip']
		(1..@code_height-2).each { |y|
			@code_window.color :hilight if y == 1
			@code_window.mvwaddstr y, 1, '%08x' % addr
			di = @rs.mnemonic_di(addr)
			@curinstr = di if y == 1
			len = di.instruction ? di.bin_length : 1
			@code_window.mvwaddstr y, 12, @rs[addr, [len, 10].min].unpack('C*').map { |c| '%02x' % c }.join
			if di.instruction
				@code_window.mvwaddstr y, 35, di.instruction.to_s
				addr += di.bin_length
			else
				@code_window.mvwaddstr y, 35, '<unk>'
				addr += 1
			end
			@code_window.color :normal if y == 1
		}

		@code_window.refresh
	end

	def updatedata
		@data_window.erase
		@data_window.color :border
		@data_window.box
		@data_window.color :normal

		@data_window.mvwaddstr 1, 1, 'TODO'

		@data_window.refresh
	end

	def updateprompt
		@prpt_window.erase
		@prpt_window.color :border
		@prpt_window.box
		@prpt_window.color :normal
		@prpt_window.mvwaddstr(@prpt_height-2, 1, ':'+@promptbuf)
		@prpt_window.refresh
	end

	def readregs
		%w[eax ebx ecx edx esi edi esp ebp eip eflags].each { |r|
			@regs[r] = @rs.send(r)
		}
	end

	def checkbp
		addr = @regs['eip']
		if @breakpoints[addr] and @rs[addr] == 0xcc
			@rs[addr] = @breakpoints.delete addr
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
			@rs.cont
			return if $?.exited?
			@oldregs.update @regs
			readregs
			checkbp
		else
			singlestep
		end
	end

	def exec_prompt
		case @promptbuf
		when 'kill'
			@rs.kill
			@running = false
		when 'q', 'quit'
			@rs.detach
			@running = false
		when /^bp (.*)/
			addr = Integer($1)
			return if @breakpoints[addr]
			@breakpoints[addr] = @rs[addr]
			@rs[addr] = 0xcc
		end
	end

	def main_loop
		@promptbuf = ''
		updateprompt
		@running = true
		while @running
			update
			case c = @curses_scr.getch
			when 27	# esc
				break
			when Ncurses::KEY_F5
				cont
				break if $?.exited?
			when Ncurses::KEY_F10
				stepover
				break if $?.exited?
			when Ncurses::KEY_F11
				singlestep
				break if $?.exited?
			# when Ncurses::Del
			# curcmd.chop
			when ?\n
				exec_prompt
				@promptbuf = ''
			when 0x32..0x7e
				@promptbuf << c
			end
		end
	end
end

if $0 == __FILE__
	LinDebug.new(ARGV.shift)
end
