#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'gtk2'

module Metasm
module GtkGui
class AsmOpcodeWidget < Gtk::DrawingArea
	attr_accessor :hl_word

	# construction method
	def initialize(dasm, parent_widget)
		@dasm = dasm
		@parent_widget = parent_widget
		@hl_word = nil
		@caret_x = @caret_y = 0	# caret position in characters coordinates (column/line)
		@oldcaret_x = @oldcaret_y = 42
		@layout = Pango::Layout.new Gdk::Pango.context
		@color = {}
		@view_addr = @dasm.prog_binding['entrypoint'] || @dasm.sections.keys.min
		@line_text = {}
		@line_address = {}
		@view_min = @dasm.sections.keys.min rescue nil
		@view_max = @dasm.sections.map { |s, e| s + e.length }.max rescue nil

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
		signal_connect('size_allocate') { |w, alloc| # resize
			lines = alloc.height / @font_height
			cols = alloc.width / @font_width
			@caret_y = lines-1 if @caret_y >= lines
			@caret_x = cols-1 if @caret_x >= cols
		}
		signal_connect('key_press_event') { |w, ev| # keyboard
			keypress(ev)
		}
		signal_connect('scroll_event') { |w, ev| # mouse wheel
			mouse_wheel(ev)
		}
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
			# register colors
			@color.each_value { |c| window.colormap.alloc_color(c, true, true) }

			# map functionnality => color
			set_color_association :comment => :darkblue, :label => :darkgreen, :text => :black,
			  :instruction => :black, :address => :blue, :caret => :black,
			  :listing_bg => :white, :cursorline_bg => :paleyellow, :hl_word => :palered
		}
	end

	def click(ev)
		@caret_x = (ev.x-1).to_i / @font_width
		@caret_y = ev.y.to_i / @font_height
		update_caret
	end

	def rightclick(ev)
		click(ev)
		@parent_widget.clone_window(@hl_word, :opcodes)
	end

	def doubleclick(ev)
		@parent_widget.focus_addr(@hl_word)
	end

	def mouse_wheel(ev)
		case ev.direction
		when Gdk::EventScroll::Direction::UP
			(allocation.height/@font_height/2).times { scrollup }
			true
		when Gdk::EventScroll::Direction::DOWN
			(allocation.height/@font_height/2).times { scrolldown }
			true
		end
	end

	def di_at(addr)
		s = @dasm.get_section_at(addr) and s[0].ptr < s[0].length and update_di_args(@dasm.cpu.decode_instruction(s[0], addr))
	end

	def update_di_args(di)
		if di
			di.instruction.args.map! { |e|
				next e if not e.kind_of? Expression
				@dasm.get_label_at(e) || e
			}
		end
		di
	end

	def scrollup
		return if @view_min and @view_addr < @view_min
		# keep current instrs in sync
		16.times { |o|
			o += 1
			if di = di_at(@view_addr-o) and di.bin_length == o
				@view_addr -= o
				@line_address = {}
				redraw
				return
			end
		}
		@view_addr -= 1
		@line_address = {}
		redraw
	end

	def scrolldown
		return if @view_max and @view_addr >= @view_max
		if di = di_at(@view_addr)
			@view_addr += di.bin_length
		else
			@view_addr += 1
		end
		@line_address = {}
		redraw
	end

	def paint
		w = window
		gc = Gdk::GC.new(w)

		a = allocation
		w_w = a.width
		w_h = a.height

		# draw caret line background
		gc.set_foreground @color[:cursorline_bg]
		w.draw_rectangle(gc, true, 0, @caret_y*@font_height, w_w, @font_height)

		want_update_caret = true if @line_address == {}

		# map lineno => address shown
		@line_address = Hash.new(-1)
		# map lineno => raw text
		@line_text = Hash.new('')

		# current address drawing
		curaddr = @view_addr
		# current line text buffer
		fullstr = ''
		# current line number
		line = 0
		# current window position
		x = 1
		y = 0

		# renders a string at current cursor position with a color
		# must not include newline
		render = lambda { |str, color|
			# function ends when we write under the bottom of the listing
			next if y >= w_h or x >= w_w
			fullstr << str
			# TODO selection
			if @hl_word
				stmp = str
				pre_x = 0
				while stmp =~ /^(.*?)(\b#{Regexp.escape @hl_word}\b)/
					s1, s2 = $1, $2
					@layout.text = s1
					pre_x += @layout.pixel_size[0]
					@layout.text = s2
					hl_x = @layout.pixel_size[0]
					gc.set_foreground @color[:hl_word]
					w.draw_rectangle(gc, true, x+pre_x, y, hl_x, @font_height)
					pre_x += hl_x
					stmp = stmp[s1.length+s2.length..-1]
				end
			end
			@layout.text = str
			gc.set_foreground @color[color]
			w.draw_layout(gc, x, y, @layout)
			x += @layout.pixel_size[0]
		}
		# newline: current line is fully rendered, update @line_address/@line_text etc
		nl = lambda {
			next if y >= w_h
			@line_text[line] = fullstr
			@line_address[line] = curaddr
			fullstr = ''
			line += 1
			x = 1
			y += @font_height
		}

		invb = @dasm.prog_binding.invert

		# draw text until screen is full
		while y < w_h
			if label = invb[curaddr]
				nl[]
				@dasm.prog_binding.keys.sort.each { |name|
					next if not @dasm.prog_binding[name] == curaddr
					render["#{name}:", :label]
					nl[]
				}
			end
			render["#{Expression[curaddr]}    ", :address]

			if di = di_at(curaddr)
				render["#{di.instruction} ", :instruction]
			else
				if s = @dasm.get_section_at(curaddr) and s[0].ptr < s[0].length
					render["db #{Expression[s[0].read(1).unpack('C')]} ", :instruction]
				end
			end
			nl[]
			curaddr += di ? di.bin_length : 1
		end

		# draw caret
		# TODO selection
		gc.set_foreground @color[:caret]
		cx = @caret_x*@font_width+1
		cy = @caret_y*@font_height
		w.draw_line(gc, cx, cy, cx, cy+@font_height-1)

		update_caret if want_update_caret
	end

	include Gdk::Keyval
	# keyboard binding
	# basic navigation (arrows, pgup etc)
	def keypress(ev)
		return @parent_widget.keypress(ev) if ev.state & Gdk::Window::CONTROL_MASK == Gdk::Window::CONTROL_MASK

		case ev.keyval
		when GDK_Left
			if @caret_x >= 1
				@caret_x -= 1
				update_caret
			end
		when GDK_Up
			if @caret_y >= 1
				@caret_y -= 1
			else
				scrollup
			end
			update_caret
		when GDK_Right
			if @caret_x <= @line_text.values.map { |s| s.length }.max
				@caret_x += 1
				update_caret
			end
		when GDK_Down
			if @caret_y < @line_text.length-3
				@caret_y += 1
			else
				scrolldown
			end
			update_caret
		when GDK_Page_Up
			(allocation.height/@font_height/2).times { scrollup }
		when GDK_Page_Down
			@view_addr = @line_address.fetch(@line_address.length/2, @view_addr+15)
			redraw
		when GDK_Home
			@caret_x = 0
			update_caret
		when GDK_End
			@caret_x = @line_text[@caret_y].length
			update_caret

		else
			return @parent_widget.keypress(ev)
		end
		true
	end

	def get_cursor_pos
		[@view_addr, @caret_x, @caret_y]
	end

	def set_cursor_pos(p)
		@view_addr, @caret_x, @caret_y = p
		redraw
		update_caret
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
		modify_bg Gtk::STATE_NORMAL, @color[:listing_bg]
		redraw
	end

	# redraw the whole widget
	def redraw
		window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false if window
	end

	# hint that the caret moved
	# redraws the caret, change the hilighted word, redraw if needed
	def update_caret
		return if not l = @line_text[@caret_y]
		word = l[0...@caret_x].to_s[/\w*$/] << l[@caret_x..-1].to_s[/^\w*/]
		word = nil if word == ''
		if @hl_word != word or @oldcaret_y != @caret_y
			@hl_word = word
			redraw
		else
			return if @oldcaret_x == @caret_x and @oldcaret_y == @caret_y
			x = @oldcaret_x*@font_width+1
			y = @oldcaret_y*@font_height
			window.invalidate Gdk::Rectangle.new(x-1, y, 2, @font_height), false
			x = @caret_x*@font_width+1
			y = @caret_y*@font_height
			window.invalidate Gdk::Rectangle.new(x-1, y, 2, @font_height), false
		end

		@oldcaret_x = @caret_x
		@oldcaret_y = @caret_y
	end

	# focus on addr
	# returns true on success (address exists)
	def focus_addr(addr)
		return if not addr = @parent_widget.normalize(addr)
		if l = @line_address.index(addr) and l < @line_address.keys.max - 4
			@caret_y, @caret_x = @line_address.keys.find_all { |k| @line_address[k] == addr }.max, 0
		elsif @dasm.get_section_at(addr)
			@view_addr, @caret_x, @caret_y = addr, 0, 0
			redraw
		else
			return
		end
		update_caret
		true
	end

	# returns the address of the data under the cursor
	def current_address
		@line_address[@caret_y]
	end

	def gui_update
		@view_min = @dasm.sections.keys.min rescue nil
		@view_max = @dasm.sections.map { |s, e| s + e.length }.max rescue nil
		redraw
	end
end
end
end
