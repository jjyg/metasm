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
			@code.focus_addr(0, :opcodes)
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
	end

	include Gdk::Keyval
	def keypress(ev)
		return if not @keyboard_cb[ev.keyval] or not @keyboard_cb[ev.keyval][ev]
		true
	end

	attr_accessor :keyboard_cb
	def setup_keyboard_cb
		@keyboard_cb = {
			GDK_F5 => lambda { @win.protect { dbg_continue } },
			GDK_F10 => lambda { @win.protect { dbg_stepover } },
			GDK_F11 => lambda { @win.protect { dbg_singlestep } },
		}
	end

	def pre_dbg_run
		@regs.pre_dbg_run
	end

	def post_dbg_run(update_status = true)
		gui_update
		Gtk.idle_add {
			next true if not @dbg.check_target
			@console.add_log "target #{@dbg.state} #{@dbg.info}" if update_status
			gui_update
			false
		}
	end

	def dbg_continue
		pre_dbg_run
		@dbg.continue
		post_dbg_run
	end

	def dbg_stepover
		pre_dbg_run
		@dbg.stepover
		post_dbg_run(false)
	end

	def dbg_singlestep
		pre_dbg_run
		@dbg.singlestep
		post_dbg_run(false)
	end

	def redraw
		window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false if window
	end

	def gui_update
		redraw
		@children.each { |c|
			c = c.dasm_widget if c.kind_of? Gtk::Window
			c.gui_update rescue next
			if wp = @watchpoint[c]
				c.focus_addr @dbg.resolve_expr(wp), nil, true
			end
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

		running = (@dbg.state == :running)
		xd = x_data*@font_width
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

		# draw caret
		gc.set_foreground @color[:caret]
		cx = (x_data + @caret_x)*@font_width+1
		cy = @caret_reg*@font_height
		w.draw_line(gc, cx, cy, cx, cy+@font_height-1)

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
			else return true
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
		window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false if window
	end

	def gui_update
		@reg_cache = @registers.inject({}) { |h, r| h.update r => @dbg.get_reg_value(r) }
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
		@layout_stat.text = @statusline
	       	y -= @layout_stat.pixel_size[1]
		w.draw_rectangle(gc, true, 0, y, w_w, @layout_stat.pixel_size[1])
		gc.set_foreground @color[:status]
		w.draw_layout(gc, 1+@font_width, y, @layout_stat)

		render[':' + @curline, :curline]
		@caret_y = y

		log.reverse.each { |l|
			render[l, :log]
			break if y < 0
		}

		# draw caret
		gc.set_foreground @color[:caret]
		cx = (@caret_x+1)*@font_width+1
		cy = @caret_y
		w.draw_line(gc, cx, cy, cx, cy+@font_height-1)

		@oldcaret_x = @caret_x
	end

	include Gdk::Keyval
	# keyboard binding
	# basic navigation (arrows, pgup etc)
	def keypress(ev)
		case ev.state & Gdk::Window::CONTROL_MASK
		when 0
			keypress_simple(ev)
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

	class IndExpression < Expression
		class << self
		def parse_value(lexer)
			sz = nil
			ptr = nil
			loop do
				nil while tok = lexer.readtok and tok.type == :space
				return if not tok
				case tok.raw
				when 'qword'; sz=8
				when 'dword'; sz=4
				when 'word'; sz=2
				when 'byte'; sz=1
				when 'ptr'
				when '['
					ptr = parse(lexer)
					nil while tok = lexer.readtok and tok.type == :space
					raise tok || lexer, '] expected' if tok.raw != ']'
					break
				else
					lexer.unreadtok tok
					break
				end
			end
			raise lexer, 'invalid indirection' if sz and not ptr
			if ptr
				sz ||= 4
				Indirection[ptr, sz]
			else super(lexer)
			end
		end

		def parse_intfloat(lexer, tok)
			case tok.raw
			when /^([0-9]+)$/; tok.value = $1.to_i
			when /^0x([0-9a-f]+)$/i, /^([0-9a-f]+)h?$/i; tok.value = $1.to_i(16)
			when /^0b([01]+)$/i; tok.value = $1.to_i(2)
			end
		end
		end
	end

	# parses the expression contained in arg, updates arg to point after the expr
	def parse_expr(arg)
		pp = Preprocessor.new(arg)
		return if not e = IndExpression.parse(pp)

		# update arg
		len = pp.pos
		pp.queue.each { |t| len -= t.raw.length }
		arg[0, len] = ''

		# resolve ambiguous symbol names/hex values
		bd = {}
		e.externals.each { |ex|
			if not v = @dbg.register_list.find { |r| ex.downcase == r.to_s.downcase } || @dbg.symbols.index(ex)
				lst = @dbg.symbols.values.find_all { |s| s.downcase.include? ex.downcase }
				case lst.length
				when 0
					if ex =~ /^[0-9a-f]+$/i
						v = ex.to_s(16)
					else
						add_log "unknown symbol name #{ex}"
						raise "unknown symbol name #{ex}"
					end
				when 1
					v = lst.first
					add_log "using #{v} for #{ex}"
				else
					add_log "ambiguous #{ex}: #{v.join(', ')} ?"
					raise "ambiguous symbol name #{ex}"
				end
			end
			bd[ex] = v
		}
		e = e.bind(bd)

		e
	end

	def solve_expr(arg)
		@dbg.resolve_expr(parse_expr(arg))
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
		new_command('continue', 'run', 'let the target run until something occurs') { p.dbg_continue(arg) }
		new_command('stepinto', 'singlestep', 'run a single instruction of the target') { p.dbg_singlestep }
		new_command('stepover', 'run a single instruction of the target, do not enter into subfunctions') { p.dbg_stepover }
		new_command('stepout', 'stepover until getting out of the current function') { p.dbg_stepout }
		new_command('bpx', 'set a breakpoint') { |arg| @dbg.bpx(solve_expr(arg)) }	# TODO conditions
		new_command('hwbp', 'set a hardware breakpoint') { |arg| @dbg.hwbp(solve_expr(arg)) }
		new_command('refresh', 'update the target memory/register cache') { @dbg.invalidate ; redraw }
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
		new_command('kill', 'kill the target') { |arg| @dbg.kill(arg) }
		new_command('g', 'wait until target reaches the specified address') { |arg|
			@dbg.bpx(solve_expr(arg), true)
			p.dbg_continue
		}
		new_command('r', 'read/write the content of a register') { |arg|
			reg, val = arg.split(/\s+/, 2)
			if reg == 'fl'
				@dbg.set_reg_value(val.to_sym, @dbg.get_reg_value(val.to_sym) == 0 ? 1 : 0)
			elsif not val
				add_log "#{r} = #{Expression[@dbg.get_reg_value(r.to_sym)]}"
			else
				val = solve_expr(val)
				@dbg.set_reg_value(reg.to_sym, val)
			end
		}
		new_command('exit', 'quit', 'quit the debugger interface') { Gtk.main_quit }	# TODO how do I close a window ?
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

		redraw
	end

	def add_log(l)
		@log << l
		@log.shift if log.length > @log_length
		redraw
	end

	# change the font of the listing
	# arg is a Gtk Fontdescription string (eg 'courier 10')
	def set_font(descr)
		@layout.font_description = Pango::FontDescription.new(descr)
		@layout_stat.font_description = Pango::FontDescription.new(descr)
		@layout_stat.font_description.weight = Pango::WEIGHT_BOLD
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
		window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false if window
	end

	def gui_update
		redraw
	end

	# hint that the caret moved
	def update_caret
		return if not window
		return if @oldcaret_x == @caret_x

		x = (@oldcaret_x+1) * @font_width + 1
		y = @caret_y
		window.invalidate Gdk::Rectangle.new(x-1, y, 2, @font_height), false

		x = (@caret_x+1) * @font_width + 1
		window.invalidate Gdk::Rectangle.new(x-1, y, 2, @font_height), false

		@oldcaret_x = @caret_x
	end
end

class DbgWindow < MainWindow
	attr_accessor :dbg_widget
	def initialize(dbg = nil, title='metasm debugger')
		super(title)
		#set_default_size 200, 300
		display(dbg) if dbg
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
		addsubmenu(dbgmenu, 'kill target') { @dbg.kill }	# destroy ?
		addsubmenu(dbgmenu, 'detach target') { @dbg.detach }	# destroy ?
		addsubmenu(dbgmenu)
		addsubmenu(dbgmenu, 'QUIT') { destroy }

		addsubmenu(@menu, dbgmenu, '_Actions')
	end
end

end
end
