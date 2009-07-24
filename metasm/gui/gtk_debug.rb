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
# TODO nonblocking @dbg ? (@dbg.continue -> still poke memory / run cmds)
# TODO customize child widgets (listing: persistent hilight of current instr, show/set breakpoints, ...)
# TODO mark changed register values after singlestep
# TODO handle debugee fork()
class DbgWidget < Gtk::VBox
	def initialize(dbg)
		super()

		@dbg = dbg

		setup_keyboard_cb

		@regs = DbgRegWidget.new(self, dbg)
		@code = DisasmWidget.new(dbg.disassembler)
		@mem = DisasmWidget.new(dbg.disassembler)
		@code.start_disassembling

		@code.keyboard_callback = @keyboard_cb
		@mem.keyboard_callback = @keyboard_cb

		self.spacing = 2
		add @regs, 'expand' => false
		add @mem
		add @code

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
		}

		set_size_request(640, 480)

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
			GDK_F5 => lambda {
				pre_dbg_run
				@dbg.continue
				post_dbg_run
			},
			GDK_F10 => lambda {
				pre_dbg_run
				@dbg.step_over
				post_dbg_run
			},
			GDK_F11 => lambda {
				pre_dbg_run
				@dbg.step_into
				post_dbg_run
			},
		}
	end

	def pre_dbg_run
		@regs.pre_dbg_run
	end

	def post_dbg_run
		gui_update
	end

	def gui_update
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

		running = @dbg.running?
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
		window.invalidate Gdk::Rectangle.new(x-1, y, x+1, y+@font_height), false

		x = (x_data + @caret_x) * @font_width + 1
		y = @caret_reg * @font_height
		window.invalidate Gdk::Rectangle.new(x-1, y, x+1, y+@font_height), false

		@oldcaret_x, @oldcaret_reg = @caret_x, @caret_reg
	end

end

class DbgWindow < MainWindow
	attr_accessor :dbg_widget
	def initialize(dbg = nil, title='metasm debugger')
		super(title)
		set_default_size 200, 300
		display(dbg) if dbg
	end

	# show a new DbgWidget
	def display(dbg)
		@vbox.remove @dbg_widget if dbg_widget
		@dbg_widget = DbgWidget.new(dbg)
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
