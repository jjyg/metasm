#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'gtk2'

module Metasm
module GtkGui

# TODO disassemble_simple @eip on unknown instr ? (would need invalidation for selfmodifying code)
# TODO statusline? ('break due to signal 11', ...)
# TODO cli ? (bpx, r fl z, ...)
# TODO nonblocking @dbg ? (@dbg.continue -> still poke memory / run cmds, handle multiple threads)
# TODO customize child widgets (listing: persistent hilight of current instr, show/set breakpoints, ...)
# TODO mark changed register values after singlestep
# TODO handle debugee fork()
class DbgWidget < Gtk::VBox
	attr_accessor :dbg, :console, :regs, :code, :mem, :win
	def initialize(dbg)
		super()

		@dbg = dbg

		setup_keyboard_cb

		@console = DbgConsoleWidget.new(self, dbg)
		@regs = DbgRegWidget.new(self, dbg)
		@code = DisasmWidget.new(dbg.disassembler)
		@mem  = DisasmWidget.new(dbg.disassembler)
		@code.start_disassembling
		@dbg.disassembler.disassemble_fast(@dbg.pc)

		@code.keyboard_callback = @keyboard_cb
		@mem.keyboard_callback = @keyboard_cb

		self.spacing = 2
		add @regs, 'expand' => false
		add @mem, 'expand' => false
		add @code, 'expand' => false
		add @console

		# 1st child should be clonable (dasm)
		@children = [@code, @mem, @regs]
		@watchpoint = { @code => @dbg.register_pc }

		signal_connect('size_allocate') { |w, alloc|
			resize(alloc.width, alloc.height)
		}

		signal_connect('realize') {
			@code.focus_addr(@dbg.resolve_expr(@watchpoint[@code]), :graph)
			@mem.focus_addr(0, :hex)
			gui_update

			modify_bg Gtk::STATE_NORMAL, Gdk::Color.new(0, 0xffff, 0)
		}

		set_size_request(640, 600)
		@mem.set_height_request(150)
		@code.set_height_request(150)

		# XXX mem has always the focus
	end

	def resize(w, h)
		@regs.set_width_request w
		return if true

		# TODO FIXME
		h = h / 3 * 3
		@oldheight ||= h
		dh = @oldheight-h
		if dh != 0
			@mem.set_height_request(@mem.allocation.height + dh/3)
			@code.set_height_request(@code.allocation.height + dh/3)
			@console.set_height_request(@console.allocation.height - 2*dh/3)
sleep 0.01
		end
		true
	end

	include Gdk::Keyval
	def keypress(ev)
		return true if @keyboard_cb[ev.keyval] and @keyboard_cb[ev.keyval][ev]
	end

	attr_accessor :keyboard_cb
	def setup_keyboard_cb
		@keyboard_cb = {
			GDK_F5 => lambda { @win.protect { dbg_continue ; true } },
			GDK_F10 => lambda { @win.protect { dbg_stepover ; true } },
			GDK_F11 => lambda { @win.protect { dbg_singlestep ; true } },
			GDK_F12 => lambda { @win.protect { dbg_stepout ; true } },
			GDK_period => lambda { @console.grab_focus },
		}
	end

	def pre_dbg_run
		@regs.pre_dbg_run
	end

	def post_dbg_run
		want_redraw = true
		Gtk.idle_add {
			if not @dbg.check_target and @dbg.state == :running
				redraw if want_redraw
				want_redraw = false
				next true
			end
			@dbg.disassembler.sections.clear if @dbg.state == :dead
			@console.add_log "target #{@dbg.state} #{@dbg.info}" if @dbg.info
			@dbg.disassembler.disassemble_fast(@dbg.pc)
			@children.each { |c|
				if wp = @watchpoint[c]
					c.focus_addr @dbg.resolve_expr(wp), nil, true
				end
			}
			redraw
			false
		}
	end

	def wrap_run
		pre_dbg_run
		yield
		post_dbg_run
	end

	def dbg_continue(*a) wrap_run { @dbg.continue(*a) } end
	def dbg_singlestep(*a) wrap_run { @dbg.singlestep(*a) } end
	def dbg_stepover(*a) wrap_run { @dbg.stepover(*a) } end
	def dbg_stepout(*a) wrap_run { @dbg.stepout(*a) } end	# TODO idle_add etc


	def redraw
		window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false if window
		@console.redraw
		@children.each { |c| c.redraw }
	end

	def gui_update
		@console.redraw
		@children.each { |c|
			c = c.dasm_widget if c.kind_of? Gtk::Window
			c.gui_update rescue next
		}
	end

	def spawn_1stchild(title, page, addr)
		child = MainWindow.new(title)
		w = child.display(@dbg.disassembler)
		w.focus_addr(addr, page)
		register_child(child)
	end

	# opens a new window with a DasmWidget on the same dasm, store it in @children
	def new_child(title, page=:hex, watchpoint=nil)
		addr = watchpoint ? @dbg.resolve_expr(watchpoint) : 'entrypoint'
		child = @children.first.dasm_widget.clone_window(addr, page)
		child.title = title
		register_child(child, watchpoint)
		child
	end

	# stores child in @children, register its @keyboard_cb
	def register_child(child, watchpoint=nil)
		@children << child
		child.dasm_widget.keyboard_callback = @keyboard_cb
		@watchpoint[child] = watchpoint if watchpoint
	end
end


# a widget that displays values of registers of a Debugger
# also controls the Debugger and commands slave windows (showing listing & memory)
class DbgRegWidget < Gtk::DrawingArea
	attr_accessor :dbg

	def initialize(parent, dbg)
		@parent_widget = parent
		@dbg = dbg

		@caret_x = @caret_reg = 0
		@oldcaret_x = @oldcaret_reg = 42
		@layout = Pango::Layout.new Gdk::Pango.context
		@color = {}
		@write_pending = {}	# addr -> newvalue (bytewise)

		@registers = @dbg.register_list
		@register_size = @dbg.register_size	# in bits, 1 for flags
		@reg_cache = Hash.new(0)
		@reg_cache_old = {}
	
		super()

		set_font 'courier 10'

		# receive mouse/kbd events
		set_events Gdk::Event::ALL_EVENTS_MASK
		set_can_focus true

		# callbacks
		signal_connect('expose_event') { paint ; true }
		signal_connect('button_press_event') { |w, ev|
			case ev.event_type
			when Gdk::Event::Type::BUTTON_PRESS
				grab_focus
				case ev.button
				when 1; click(ev)
				when 3; rightclick(ev)
				end
			when Gdk::Event::Type::BUTTON2_PRESS
				case ev.button
				when 1; doubleclick(ev)
				end
			end
		}
		signal_connect('key_press_event') { |w, ev| keypress(ev) }
		signal_connect('realize') { # one-time initialize
			# raw color declaration
			{ :white => 'fff', :palegrey => 'ddd', :black => '000', :grey => '444',
			  :red => 'f00', :darkred => '800', :palered => 'fcc',
			  :green => '0f0', :darkgreen => '080', :palegreen => 'cfc',
			  :blue => '00f', :darkblue => '008', :paleblue => 'ccf',
			  :yellow => 'ff0', :darkyellow => '440', :paleyellow => 'ffc',
			}.each { |tag, val|
				@color[tag] = Gdk::Color.new(*val.unpack('CCC').map { |c| (c.chr*4).hex })
			}
			@color.each_value { |c| window.colormap.alloc_color(c, true, true) }

			set_color_association :label => :black, :data => :blue, :write_pending => :darkred,
				       	:changed => :darkgreen,
					:caret => :black, :bg => :white, :inactive => :palegrey
		}

		gui_update
	end

	def click(ev)
		@caret_x = [(ev.x-1).to_i / @font_width - x_data, 0].max
		@caret_reg = [ev.y.to_i / @font_height, @registers.length-1].min
		@caret_x = [@caret_x, @register_size[@registers[@caret_reg]]/4-1].min
		update_caret
	end

	def rightclick(ev)
		doubleclick(ev)	# XXX
	end

	def doubleclick(ev)
		gui_update	# XXX
	end

	def paint
		w = window
		gc = Gdk::GC.new(w)

		curaddr = 0
		x = 1
		y = 0

		a = allocation
		w_w = a.width

		render = lambda { |str, color|
			@layout.text = str
			gc.set_foreground @color[color]
			w.draw_layout(gc, x, y, @layout)
			x += @layout.pixel_size[0]
		}

		running = (@dbg.state != :stopped)
		xd = x_data*@font_width + 1
		@registers.each { |reg|
			x = 1
			render[reg.to_s, :label]
			v = @write_pending[reg] || @reg_cache[reg]
			x = xd
			col = @write_pending[reg] ? :write_pending : @reg_cache_old.fetch(reg, v) != v ? :changed : :data
			col = :inactive if running
			render["%0#{@register_size[reg]/4}x " % v, col]
			y += @font_height
		}

		if focus?
			# draw caret
			gc.set_foreground @color[:caret]
			cx = (x_data + @caret_x)*@font_width+1
			cy = @caret_reg*@font_height
			w.draw_line(gc, cx, cy, cx, cy+@font_height-1)
		end

		@oldcaret_x, @oldcaret_reg = @caret_x, @caret_reg
	end

	def set_width_request(w)
		super(w)
		set_height_request(@registers.length * @font_height)
	end

	# char x of start of reg value zone
	def x_data
		10
	end

	include Gdk::Keyval
	# keyboard binding
	# basic navigation (arrows, pgup etc)
	def keypress(ev)
		return @parent_widget.keypress(ev) if ev.state & Gdk::Window::CONTROL_MASK == Gdk::Window::CONTROL_MASK
		case ev.keyval
		when GDK_Left
			if @caret_x > 0
				@caret_x -= 1
				update_caret
			end
		when GDK_Right
			if @caret_x < @register_size[@registers[@caret_reg]]/4-1
				@caret_x += 1
				update_caret
			end
		when GDK_Up
			if @caret_reg > 0
				@caret_reg -= 1
				update_caret
			end
		when GDK_Down
			if @caret_reg < @registers.length-1
				@caret_reg += 1
				update_caret
			end
		when GDK_Home
			@caret_x = 0
			update_caret
		when GDK_End
			@caret_x = @register_size[@registers[@caret_reg]]/4-1
			update_caret
		when GDK_Tab
			if @caret_reg < @registers.length-1
				@caret_reg += 1
				update_caret
			end

		when 0x20..0x7e
			case v = ev.keyval
			when 0x20; v = nil	# keep current value
			when ?0..?9; v -= ?0
			when ?a..?f; v -= ?a-10
			when ?A..?F; v -= ?A-10
			else return @parent_widget.keypress(ev)
			end

			reg = @registers[@caret_reg]
			rsz = @register_size[reg]	# TODO flags
			if v
				oo = 4*(rsz/4-@caret_x-1)
				ov = @write_pending[reg] || @reg_cache[reg]
				ov &= ~(0xf << oo)
				ov |= v << oo
				@write_pending[reg] = ov
			end
			
			if @caret_x < rsz/4-1
				@caret_x += 1
			else
				@caret_x = 0
			end
			redraw
		when GDK_Return, GDK_KP_Enter
			commit_writes
			redraw
		when GDK_Escape
			@write_pending.clear
			redraw
		else
			return @parent_widget.keypress(ev)
		end
		true
	end

	def pre_dbg_run
		@reg_cache_old = @reg_cache.dup if @reg_cache
	end

	def commit_writes
		@write_pending.each { |k, v| @dbg.set_reg_value(k, v) }
		@write_pending.clear
	end

	# change the font of the listing
	# arg is a Gtk Fontdescription string (eg 'courier 10')
	def set_font(descr)
		@layout.font_description = Pango::FontDescription.new(descr)
		@layout.text = 'x'
		@font_width, @font_height = @layout.pixel_size
		redraw
	end

	# change the color association
	# arg is a hash function symbol => color symbol
	# color must be allocated
	# check #initialize/sig('realize') for initial function/color list
	def set_color_association(hash)
		hash.each { |k, v| @color[k] = @color[v] }
		modify_bg Gtk::STATE_NORMAL, @color[:bg]
		redraw
	end

	# redraw the whole widget
	def redraw
		@reg_cache = @registers.inject({}) { |h, r| h.update r => @dbg.get_reg_value(r) }
		window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false if window
	end

	def gui_update
		redraw
	end

	# hint that the caret moved
	def update_caret
		return if not window
		return if @oldcaret_x == @caret_x and @oldcaret_reg == @caret_reg

		x = (x_data + @oldcaret_x) * @font_width + 1
		y = @oldcaret_reg * @font_height
		window.invalidate Gdk::Rectangle.new(x-1, y, 2, @font_height), false

		x = (x_data + @caret_x) * @font_width + 1
		y = @caret_reg * @font_height
		window.invalidate Gdk::Rectangle.new(x-1, y, 2, @font_height), false

		@oldcaret_x, @oldcaret_reg = @caret_x, @caret_reg
	end

end


# a widget that displays logs of the debugger, and a cli interface to the dbg
class DbgConsoleWidget < Gtk::DrawingArea
	attr_accessor :dbg, :cmd_history, :log, :statusline, :commands, :cmd_help

	def initialize(parent, dbg)
		@parent_widget = parent
		@dbg = dbg
		@dbg.set_log_proc { |l| add_log l }

		@caret_x = 0
		@oldcaret_x = 42
		@layout = Pango::Layout.new Gdk::Pango.context
		@layout_stat = Pango::Layout.new Gdk::Pango.context
		@color = {}
		@log = []
		@log_length = 400
		@curline = ''
		@statusline = 'type \'help\' for help'
		@cmd_history = ['']
		@cmd_history_length = 80	# number of past commands to remember
		@cmd_histptr = nil

		super()

		set_font 'courier 10'

		# receive mouse/kbd events
		set_events Gdk::Event::ALL_EVENTS_MASK
		set_can_focus true

		# callbacks
		signal_connect('expose_event') { paint ; true }
		signal_connect('button_press_event') { |w, ev|
			case ev.event_type
			when Gdk::Event::Type::BUTTON_PRESS
				grab_focus
				case ev.button
				when 1; click(ev)
				when 3; rightclick(ev)
				end
			when Gdk::Event::Type::BUTTON2_PRESS
				case ev.button
				when 1; doubleclick(ev)
				end
			end
		}
		# TODO mousewheel to scroll history?
		signal_connect('key_press_event') { |w, ev| keypress(ev) }
		signal_connect('realize') { # one-time initialize
			# raw color declaration
			{ :white => 'fff', :palegrey => 'ddd', :black => '000', :grey => '444',
			  :red => 'f00', :darkred => '800', :palered => 'fcc',
			  :green => '0f0', :darkgreen => '080', :palegreen => 'cfc',
			  :blue => '00f', :darkblue => '008', :paleblue => 'ccf',
			  :yellow => 'ff0', :darkyellow => '440', :paleyellow => 'ffc',
			  :olive => '088',
			}.each { |tag, val|
				@color[tag] = Gdk::Color.new(*val.unpack('CCC').map { |c| (c.chr*4).hex })
			}
			@color.each_value { |c| window.colormap.alloc_color(c, true, true) }

			set_color_association :log => :palegrey, :curline => :white,
				:caret => :yellow, :bg => :black,
				:status => :black, :status_bg => :olive

			grab_focus
		}

		init_commands

		gui_update
	end

	def click(ev)
		@caret_x = (ev.x-1).to_i / @font_width - 1
		@caret_x = [[@caret_x, 0].max, @curline.length].min
		update_caret
	end

	def rightclick(ev)
	end

	def doubleclick(ev)
	end

	def paint
		w = window
		gc = Gdk::GC.new(w)

		x = 1
		y = 0

		a = allocation
		w_w = a.width
		w_h = a.height

		render = lambda { |str, color|
			@layout.text = str
			gc.set_foreground @color[color]
			y -= @font_height
			w.draw_layout(gc, 1, y, @layout)
		}

		y = w_h
		gc.set_foreground @color[:status_bg]
	       	y -= @font_height_stat
		w.draw_rectangle(gc, true, 0, y, w_w, @font_height_stat)
		gc.set_foreground @color[:status]
		@layout_stat.text = "#{@dbg.state} #{@dbg.info}"
		w.draw_layout(gc, w_w - @layout_stat.pixel_size[0] - 1, y, @layout_stat)
		@layout_stat.text = @statusline
		w.draw_layout(gc, 1+@font_width_stat, y, @layout_stat)

		w_w_c = w_w/@font_width
		if @caret_x < w_w_c-1
			render[':' + @curline, :curline]
		else
			render['~' + @curline[@caret_x-w_w_c+2, w_w_c], :curline]
		end
		@caret_y = y

		log.reverse.each { |l|
			l.scan(/.{1,#{w_w/@font_width}}/).reverse_each { |l_|
				render[l_, :log]
			}
			break if y < 0
		}

		if focus?
			# draw caret
			gc.set_foreground @color[:caret]
			cx = [@caret_x+1, w_w_c-1].min*@font_width+1
			cy = @caret_y
			w.draw_line(gc, cx, cy, cx, cy+@font_height-1)
		end

		@oldcaret_x = @caret_x
	end

	include Gdk::Keyval
	# keyboard binding
	# basic navigation (arrows, pgup etc)
	def keypress(ev)
		case ev.state & Gdk::Window::CONTROL_MASK
		when 0; keypress_simple(ev)
		else; @parent_widget.keypress(ev)
		end
	end

	# no ctrl-key
	def keypress_simple(ev)
		case ev.keyval
		when GDK_Left
			if @caret_x > 0
				@caret_x -= 1
				update_caret
			end
		when GDK_Right
			if @caret_x < @curline.length
				@caret_x += 1
				update_caret
			end
		when GDK_Up
			if not @cmd_histptr
				@cmd_history << @curline
				@cmd_histptr = 2
			else
				@cmd_histptr += 1
				@cmd_histptr = 1 if @cmd_histptr > @cmd_history.length
			end
			@curline = @cmd_history[-@cmd_histptr].dup
			@caret_x = @curline.length
			update_status_cmd
			redraw

		when GDK_Down
			if not @cmd_histptr
				@cmd_history << @curline
				@cmd_histptr = @cmd_history.length
			else
				@cmd_histptr -= 1
				@cmd_histptr = @cmd_history.length if @cmd_histptr < 1
			end
			@curline = @cmd_history[-@cmd_histptr].dup
			@caret_x = @curline.length
			update_status_cmd
			redraw

		when GDK_Home
			@caret_x = 0
			update_caret
		when GDK_End
			@caret_x = @curline.length
			update_caret
		when GDK_Tab
			# autocomplete
			if @caret_x > 0 and not @curline[0, @caret_x].index(?\ ) and st = @curline[0, @caret_x] and not @commands[st]
				keys = @commands.keys.find_all { |k| k[0, st.length] == st }
				while st.length < keys.first.to_s.length and keys.all? { |k| k[0, st.length+1] == keys.first[0, st.length+1] }
					st << keys.first[st.length]
					@curline[@caret_x, 0] = st[-1, 1]
					@caret_x += 1
				end
				update_status_cmd
				redraw
			end

		when 0x20..0x7e
			@curline[@caret_x, 0] = ev.keyval.chr
			@caret_x += 1
			update_status_cmd
			redraw
		when GDK_Return, GDK_KP_Enter
			@cmd_histptr = nil
			handle_command
			update_status_cmd
		when GDK_Escape
		when GDK_Delete
			if @caret_x < @curline.length
				@curline[@caret_x, 1] = ''
				update_status_cmd
				redraw
			end
		when GDK_BackSpace
			if @caret_x > 0
				@caret_x -= 1
				@curline[@caret_x, 1] = ''
				update_status_cmd
				redraw
			end
		else return @parent_widget.keypress(ev)
		end
		true
	end

	def update_status_cmd
		st = @curline.split.first
		if @commands[st]
			@statusline = "#{st}: #{@cmd_help[st]}"
		else
			keys = @commands.keys.find_all { |k| k[0, st.length] == st } if st
			if keys and not keys.empty?
				@statusline = keys.sort.join(' ')
			else
				@statusline = 'type \'help\' for help'
			end
		end
	end

	def new_command(*cmd, &b)
		hlp = cmd.pop if cmd.last.include? ' '
		cmd.each { |c|
			@cmd_help[c] = hlp || 'nodoc'
			@commands[c] = lambda { |*a|
				@parent_widget.win.protect { b.call(*a) }
			}
		}
	end

	# arg str -> expr value, with special codeptr/dataptr = code/data.curaddr
	def solve_expr(arg)
		return if not e = @dbg.parse_expr(arg) { |e|
			case e.downcase
			when 'code_addr', 'codeptr'
				@parent_widget.code.curaddr
			when 'data_addr', 'dataptr'
				@parent_widget.mem.curaddr
			end
		}
		@dbg.resolve_expr(e)
	end

	def init_commands
		@commands = {}
		@cmd_help = {}
		p = @parent_widget
		new_command('help') { add_log @commands.keys.sort.join(' ') } # TODO help <subject>
		new_command('d', 'focus data window on an address') { |arg| p.mem.focus_addr(solve_expr(arg)) }
		new_command('db', 'display bytes in data window') { p.mem.curview.data_size = 1 ; p.mem.gui_update }
		new_command('dw', 'display bytes in data window') { p.mem.curview.data_size = 2 ; p.mem.gui_update }
		new_command('dd', 'display bytes in data window') { p.mem.curview.data_size = 4 ; p.mem.gui_update }
		new_command('u', 'focus code window on an address') { |arg| p.code.focus_addr(solve_expr(arg)) }
		new_command('.', 'focus code window on current address') { p.code.focus_addr(solve_expr(@dbg.register_pc.to_s)) }
		new_command('wc', 'set code window height') { |arg| p.code.set_height_request(Integer(arg)*@font_height) }	# TODO check size against window
		new_command('wd', 'set data window height') { |arg| p.mem.set_height_request(Integer(arg)*@font_height) }
		new_command('width', 'set window width (chars)') { |arg|
			if a = solve_expr(arg); p.win.resize(a*@font_width, p.win.size[1])
			else add_log "width #{p.win.size[0]/@font_width}"
			end
		}
		new_command('height', 'set window height (chars)') { |arg|
			if a = solve_expr(arg); p.win.resize(p.win.size[0], a*@font_height)
			else add_log "height #{p.win.size[1]/@font_height}"
			end
		}
		new_command('continue', 'run', 'let the target run until something occurs') { |arg| p.dbg_continue(arg) }
		new_command('stepinto', 'singlestep', 'run a single instruction of the target') { p.dbg_singlestep }
		new_command('stepover', 'run a single instruction of the target, do not enter into subfunctions') { p.dbg_stepover }
		new_command('stepout', 'stepover until getting out of the current function') { p.dbg_stepout }
		new_command('bpx', 'set a breakpoint') { |arg| @dbg.bpx(solve_expr(arg)) }	# TODO conditions
		new_command('hwbp', 'set a hardware breakpoint') { |arg| @dbg.hwbp(solve_expr(arg)) }
		new_command('refresh', 'update', 'update the target memory/register cache') { @dbg.invalidate ; p.gui_update }
		new_command('bl', 'list breakpoints') {
			i = -1
			@dbg.breakpoint.sort.each { |a, b|
				add_log "#{i+=1} #{Expression[a]} #{b.type} #{b.state}"
			}
		}
		new_command('bc', 'clear breakpoints') { |arg|
			if arg == '*'
				@dbg.breakpoint.keys.each { |i| @dbg.remove_breakpoint(i) }
			else
				next if not i = solve_expr(arg)
				i = @dbg.breakpoint.sort[i][0] if i < @dbg.breakpoint.length
				@dbg.remove_breakpoint(i)
			end
		}
		new_command('break', 'interrupt a running target') { |arg| @dbg.break ; p.post_dbg_run }
		new_command('kill', 'kill the target') { |arg| @dbg.kill(arg) ; p.post_dbg_run }
		new_command('detach', 'detach from the target') { @dbg.detach ; p.post_dbg_run }
		new_command('g', 'wait until target reaches the specified address') { |arg|
			@dbg.bpx(solve_expr(arg), true)
			p.dbg_continue
		}
		new_command('r', 'read/write the content of a register') { |arg|
			reg, val = arg.split(/\s+/, 2)
			if reg == 'fl'
				@dbg.set_reg_value(val.to_sym, @dbg.get_reg_value(val.to_sym) == 0 ? 1 : 0)
			elsif not val
				add_log "#{reg} = #{Expression[@dbg.get_reg_value(reg.to_sym)]}"
			else
				val = solve_expr(val)
				@dbg.set_reg_value(reg.to_sym, val)
			end
		}
		new_command('?', 'display a value') { |arg|
			next if not v = solve_expr(arg)
			add_log "#{v} 0x#{v.to_s(16)} #{[v].pack('L').inspect}"
		}
		new_command('exit', 'quit', 'quit the debugger interface') { p.win.destroy }
		new_command('ruby', 'execute arbitrary ruby code') { |arg| eval arg }
		new_command('loadsyms', 'load symbols from a mapped module') { |arg|
			if arg = solve_expr(arg)
				@dbg.loadsyms(arg)
			else
				@dbg.loadallsyms
			end
		}
		new_command('scansyms', 'scan target memory for loaded modules') {
			if defined? @scan_addr and @scan_addr
				add_log 'scanning @%08x' % @scan_addr
				next
			end
			@scan_addr = 0
			Gtk.idle_add {
				if @scan_addr <= 0xffff_f000	# cpu.size?
					@dbg.loadsyms(@scan_addr)
					@scan_addr += 0x1000
					true
				else
					add_log 'scansyms finished'
					@scan_addr = nil
					nil
				end
			}
		}
	end

	def handle_command
		add_log(":#@curline")
		return if @curline == ''
		@cmd_history << @curline
		@cmd_history.shift if @cmd_history.length > @cmd_history_length
		cmd = @curline
		@curline = ''
		@caret_x = 0

		cn = cmd.split.first
		if not @commands[cn]
			a = @commands.keys.find_all { |k| k[0, cn.length] == cn }
			cn = a.first if a.length == 1
		end
		if pc = @commands[cn] 
			pc[cmd.split(/\s+/, 2)[1].to_s]
		else
			add_log 'unknown command'
		end
	end

	def add_log(l)
		@log << l.to_s
		@log.shift if log.length > @log_length
		redraw
	end

	# change the font of the listing
	# arg is a Gtk Fontdescription string (eg 'courier 10')
	def set_font(descr)
		@layout.font_description = Pango::FontDescription.new(descr)
		@layout.text = 'x'
		@font_width, @font_height = @layout.pixel_size
		@layout_stat.font_description = Pango::FontDescription.new(descr)
		@layout_stat.font_description.weight = Pango::WEIGHT_BOLD
		@layout_stat.text = 'x'
		@font_width_stat, @font_height_stat = @layout_stat.pixel_size
		redraw
	end

	# change the color association
	# arg is a hash function symbol => color symbol
	# color must be allocated
	# check #initialize/sig('realize') for initial function/color list
	def set_color_association(hash)
		hash.each { |k, v| @color[k] = @color[v] }
		modify_bg Gtk::STATE_NORMAL, @color[:bg]
		redraw
	end

	# redraw the whole widget
	def redraw
		window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false if window
	end

	def gui_update
		redraw
	end

	# hint that the caret moved
	def update_caret
		return if not window
		return if @oldcaret_x == @caret_x
		w_w = allocation.width - @font_width
		x1 = (@oldcaret_x+1) * @font_width + 1
		x2 = (@caret_x+1) * @font_width + 1
		y = @caret_y

		if x1 > w_w or x2 > w_w
			window.invalidate Gdk::Rectangle.new(0, y, 100000, @font_height), false
		else
			window.invalidate Gdk::Rectangle.new(x1-1, y, 2, @font_height), false
			window.invalidate Gdk::Rectangle.new(x2-1, y, 2, @font_height), false
		end

		@oldcaret_x = @caret_x
	end
end

class DbgWindow < MainWindow
	attr_accessor :dbg_widget
	def initialize(dbg = nil, title='metasm debugger')
		super(title)
		#set_default_size 200, 300
		display(dbg) if dbg
		Gtk::Settings.default.gtk_menu_bar_accel = nil	# disable F10 -> popup menubar
	end

	# show a new DbgWidget
	def display(dbg)
		@vbox.remove @dbg_widget if dbg_widget
		@dbg_widget = DbgWidget.new(dbg)
		@dbg_widget.win = self
		@vbox.add @dbg_widget
		show_all
		@dbg_widget
	end

	def build_menu
		@menu = Gtk::MenuBar.new
		@accel_group = Gtk::AccelGroup.new
		dbgmenu = Gtk::Menu.new
		i = addsubmenu(dbgmenu, 'continue') { @dbg_widget.keyboard_cb[Gdk::Keyval::GDK_F5][] }
		i.add_accelerator('activate', @accel_group, Gdk::Keyval::GDK_F5, 0, Gtk::ACCEL_VISIBLE)	# just to display the shortcut
		i = addsubmenu(dbgmenu, 'step over') { @dbg_widget.keyboard_cb[Gdk::Keyval::GDK_F10][] }
		i.add_accelerator('activate', @accel_group, Gdk::Keyval::GDK_F10, 0, Gtk::ACCEL_VISIBLE)
		i = addsubmenu(dbgmenu, 'step into') { @dbg_widget.keyboard_cb[Gdk::Keyval::GDK_F11][] }
		i.add_accelerator('activate', @accel_group, Gdk::Keyval::GDK_F11, 0, Gtk::ACCEL_VISIBLE)
		addsubmenu(dbgmenu, 'kill target') { @dbg_widget.dbg.kill }	# destroy ?
		addsubmenu(dbgmenu, 'detach target') { @dbg_widget.dbg.detach }	# destroy ?
		addsubmenu(dbgmenu)
		addsubmenu(dbgmenu, 'QUIT') { destroy }

		addsubmenu(@menu, dbgmenu, '_Actions')
	end
end

end
end
