#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'gtk2'

module Metasm
module GtkGui
class HexWidget < Gtk::DrawingArea
	# data_size = size of data in bytes (1 => chars, 4 => dwords..)
	# line_size = nr of bytes shown per line
	attr_accessor :show_address, :show_data, :show_ascii,
		:data_sign, :data_size, :data_hex,
		:line_size, :viewaddr

	def initialize(dasm, parent_widget)
		@dasm = dasm
		@parent_widget = parent_widget
		@caret_x = @caret_y = 0	# caret position in characters coordinates (column/line)
		@oldcaret_x = @oldcaret_y = 42
		@focus_zone = :hex
		@layout = Pango::Layout.new Gdk::Pango.context
		@color = {}
		@viewaddr = @dasm.prog_binding['entrypoint'] || @dasm.section.keys.min
		@show_address = @show_data = @show_ascii = true
		@data_sign = false
		@data_size = 1
		@data_hex = true
		@line_size = 16
		@num_lines = 2	# size of widget in lines

		@write_pending = {}	# addr -> newvalue ?

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
		signal_connect('size_allocate') { |w, alloc| # resize
			@num_lines = alloc.height / @font_height
			cols = alloc.width / @font_width
			@caret_y = @num_lines-1 if @caret_y >= @num_lines
			@caret_x = cols-1 if @caret_x >= cols
			@line_size = 16	# TODO
		}
		# TODO disable windows' menu accelerators
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
			set_color_association :ascii => :black, :data => :black,
			  :address => :blue, :caret => :black, :bg => :white,
			  :write_pending => :darkred
		}
	end

	def click(ev)
		@caret_x = (ev.x-1).to_i / @font_width
		@caret_y = ev.y.to_i / @font_height
		update_caret
	end

	def rightclick(ev)
		@data_size = {1 => 2, 2 => 4, 4 => 1}[@data_size]
		redraw
	end

	def doubleclick(ev)
		rightclick(ev)	# TODO something else ?
	end

	def mouse_wheel(ev)
		case ev.direction
		when Gdk::EventScroll::Direction::UP
			@viewaddr -= allocation.height/@font_height/@line_size/2
			redraw
			true
		when Gdk::EventScroll::Direction::DOWN
			@viewaddr += allocation.height/@font_height/@line_size/2
			redraw
			true
		end
	end

	# returns 1 line of data
	def data_at(addr, len=@line_size)
		s = @dasm.get_section_at(addr) and s[0].ptr < s[0].length and s[0].read(len)
	end

	def paint
		w = window
		gc = Gdk::GC.new(w)

		a = allocation
		w_w = a.width
		w_h = a.height

		curaddr = @viewaddr
		# current window position
		x = 1
		y = 0
		@num_lines = 0

		# renders a string at current cursor position with a color
		# must not include newline
		render = lambda { |str, color|
			# function ends when we write under the bottom of the listing
			next if y >= w_h or x >= w_w
			# TODO selection
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

		# draw text until screen is full
		while y < w_h
			render["#{Expression[curaddr]} ".rjust(10, '0'), :address] if @show_address

			if d = data_at(curaddr)
				# TODO write_pending, data_hex, unsigned etc
				#case @data_size
				h = d.unpack('C*').map { |b| '%02x' % b }
				str = ''
				d.unpack('C*').each_with_index { |b, i|
					str << ' ' if i % 4 == 0
					str << ('%02x ' % b)
				} if @show_data
				str << '  ' << d.gsub(/[^\x20-\x7e]/, '.') if @show_ascii
				render[str, :data]
			end
			curaddr += @line_size
			nl[]
		end

		# draw caret
		# TODO selection
		gc.set_foreground @color[:caret]
		cx = @caret_x*@font_width+1
		cy = @caret_y*@font_height
		w.draw_line(gc, cx, cy, cx, cy+@font_height-1)
	end

	include Gdk::Keyval
	# keyboard binding
	# basic navigation (arrows, pgup etc)
	def keypress(ev)
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
				@viewaddr -= @line_size
				redraw
			end
			update_caret
		when GDK_Right
			@caret_x += 1
			update_caret
		when GDK_Down
			if @caret_y < @num_lines-2
				@caret_y += 1
			else
				@viewaddr += @line_size
				redraw
			end
			update_caret
		when GDK_Page_Up
			@viewaddr -= (@num_lines/2)*@line_size
			redraw
		when GDK_Page_Down
			@viewaddr += (@num_lines/2)*@line_size
			redraw
		when GDK_Home
			@caret_x = 0
			update_caret
		when GDK_End
			@caret_x = 5000
			update_caret

		# TODO
		#when Tab
		#	switch @focus_zone
		#when 0x20..0x7e
		#	write
		#when Enter
		#	commit

		else
			return @parent_widget.keypress(ev)
		end
		true
	end

	def get_cursor_pos
		[@viewaddr, @caret_x, @caret_y, @focus_zone]
	end

	def set_cursor_pos(p)
		@viewaddr, @caret_x, @caret_y, @focus_zone = p
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
		modify_bg Gtk::STATE_NORMAL, @color[:bg]
		redraw
	end

	# redraw the whole widget
	def redraw
		window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false if window
	end

	# hint that the caret moved
	# bind it to the current active area & redraw it
	def update_caret
		@caret_x = 10 if @caret_x < 10
		@caret_x = 10+16*3+4+18 if @caret_x > 10+16*3+4+18
		# TODO skip spaces between hex digits ?

		return if @oldcaret_x == @caret_x and @oldcaret_y == @caret_y
		x = @oldcaret_x*@font_width+1
		y = @oldcaret_y*@font_height
		window.invalidate Gdk::Rectangle.new(x-1, y, x+1, y+@font_height), false
		x = @caret_x*@font_width+1
		y = @caret_y*@font_height
		window.invalidate Gdk::Rectangle.new(x-1, y, x+1, y+@font_height), false

		@oldcaret_x = @caret_x
		@oldcaret_y = @caret_y
	end

	# focus on addr
	# returns true on success (address exists)
	def focus_addr(addr)
		if addr >= @viewaddr and addr < @viewaddr+(@num_lines-2)*@line_size
			# TODO
			@caret_x = 10 + 3*((addr-@viewaddr) % @line_size)
			@caret_y = (addr-@viewaddr) / @line_size
		else
			@viewaddr = addr&0xffff_fff0
			@caret_x = 10 + 3*((addr-@viewaddr) % @line_size)
			@caret_y = 0
			redraw
		end
		update_caret
		true
	end

	# returns the address of the data under the cursor
	def current_address
		@viewaddr + @caret_y*@line_size	# XXX @caret_x
	end

	def gui_update
		redraw
	end
end
end
end
