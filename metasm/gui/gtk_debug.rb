#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'gtk2'

module Metasm
module GtkGui
# a widget that displays values of registers of a Debugger
# also controls the Debugger and commands slave windows (showing listing & memory)
# TODO disassemble_simple @eip on unknown instr ? (would need invalidation for selfmodifying code)
# TODO statusline? ('break due to signal 11', ...)
# TODO cli ? (bpx, r fl z, ...)
# TODO nonblocking @dbg ? (@dbg.continue -> still poke memory / run cmds)
# TODO customize child widgets (listing: persistent hilight of current instr, show/set breakpoints, ...)
class DbgWidget < Gtk::DrawingArea
	attr_accessor :dbg, :registers

	def initialize(dbg)

		@dbg = dbg

		@caret_x = @caret_y = 0
		@oldcaret_x = @oldcaret_y = 42
		@layout = Pango::Layout.new Gdk::Pango.context
		@color = {}
		@data_size = @dbg.cpu.size/8
		@write_pending = {}	# addr -> newvalue (bytewise)
		@endianness = @dbg.cpu.endianness

		@registers = @dbg.register_list

		# slave windows (disassembly, memory hex..)
		@children = []
		# child => expression
		@watchpoint = {}

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
		setup_keyboard_cb
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

			set_color_association :label => :blue, :data => :black, :writepending => :darkred,
					:caret => :black, :bg => :white, :inactive => :palegrey
		}

		spawn_1stchild
		new_child(:opcodes, @dbg.pc_reg)
		new_child(:hex, @dbg.sp_reg)

		# setup the gui idle callback to disassemble pending entrypoints
		@children.first.dasm_widget.start_disassembling
	end

	def click(ev)
		@caret_x = (ev.x-1).to_i / @font_width - x_data
		@caret_x = [[@caret_x, 0].max, @data_size*2-1].min
		@caret_y = ev.y.to_i / @font_height
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

		a = allocation
		w_w = a.width
		w_h = a.height

		curaddr = 0
		x = 1
		y = 0

		render = lambda { |str, color|
			next if y >= w_h or x >= w_w
			@layout.text = str
			gc.set_foreground @color[color]
			w.draw_layout(gc, x, y, @layout)
			x += @layout.pixel_size[0]
		}
		nl = lambda {
			next if y >= w_h
			@num_lines += 1
			x = 1
			y += @font_height
		}

		xd = x_data*@font_width
		@registers.each { |reg|
			render[reg.to_s, :label]
			v = @write_pending[reg] || @dbg.get_reg_value(reg)
			x = xd
			col = @dbg.running? ? :inactive : @write_pending[reg] ? :write_pending : :data
			render["%0#{@data_size*2}x " % v, col]
			nl[]
		}

		# draw caret
		gc.set_foreground @color[:caret]
		cx = (x_data + @caret_x)*@font_width+1
		cy = @caret_y*@font_height
		w.draw_line(gc, cx, cy, cx, cy+@font_height-1)

		@oldcaret_x, @oldcaret_y = @caret_x, @caret_y
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
			if @caret_x < @data_size*2-1
				@caret_x += 1
				update_caret
			end
		when GDK_Up
			if @caret_y > 0
				@caret_y -= 1
				update_caret
			end
		when GDK_Down
			if @caret_y < @registers.length-1
				@caret_y += 1
				update_caret
			end
		when GDK_Home
			@caret_x = 0
			update_caret
		when GDK_End
			@caret_x = @data_size-1
			update_caret

		when 0x20..0x7e
			case v = ev.keyval
			when 0x20; v = nil	# keep current value
			when ?0..?9; v -= ?0
			when ?a..?f; v -= ?a-10
			when ?A..?F; v -= ?A-10
			else return true
			end

			if v
				# XXX if a reg overflows @data_size (eg xmm), the offset is wrong
				oo = 4*(@data_size*2-(@caret_x-x_data))
				reg = @registers[@caret_y]
				ov = @write_pending[reg] || @dbg.get_reg_value(reg)
				ov &= ~(0xf << oo)
				ov |= v << oo
				@write_pending[reg] = ov
			end
			
			if @caret_x < @data_size*2-1
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
			return if not @keyboard_cb[ev.keyval] or not @keyboard_cb[ev.keyval][ev]
		end
		true
	end

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

	# hint that the caret moved
	def update_caret
		return if not window
		return if @oldcaret_x == @caret_x and @oldcaret_y == @caret_y

		x = @oldcaret_x * @font_width
		y = @oldcaret_y * @font_height
		window.invalidate Gdk::Rectangle.new(x-1, y, x+1, y+@font_height), fals

		x = @caret_x * @font_width
		y = @caret_y * @font_height
		window.invalidate Gdk::Rectangle.new(x-1, y, x+1, y+@font_height), fals

		@oldcaret_x, @oldcaret_y = @caret_x, @caret_y
	end

	def gui_update
		@children.each { |c|
			c = c.dasm_widget
			c.gui_update rescue next
			if wp = @watchpoint[c]
				c.focus_addr @dbg.resolve_expr(wp), nil, true
			end
		}
		redraw
	end

	def spawn_1stchild
		child = MainWindow.new
		w = child.display(@dbg.dasm)
		register_child(child)
		w.focus_addr(@dbg.dasm.prog_binding.keys.first || 0)
		register_child(child)
	end

	# opens a new window with a DasmWidget on the same dasm, store it in @children
	def new_child(page=:hex, watchpoint=nil)
		child = @children.first.dasm_widget.clone_window
		register_child(child, watchpoint)
		addr = watchpoint ? @dbg.resolve_expr(watchpoint) : 'entrypoint'
		child.dasm_widget.focus_addr(addr, page, true)
		child
	end

	# stores child in @children, register its @keyboard_cb
	def register_child(child, watchpoint=nil)
		@children << child
		child.dasm_widget.keyboard_callback = @keyboard_cb
		@watchpoint[child] = watchpoint if watchpoint
	end
end

class DbgWindow < MainWindow
	attr_accessor :dbg_widget
	def initialize(dbg = nil, title='metasm debugger')
		super(title)
		set_default_size 300, 500
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
	end
end

end
end
