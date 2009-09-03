#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'gtk2'

module Metasm
module GtkGui
class HexWidget < Gtk::DrawingArea
	# data_size = size of data in bytes (1 => chars, 4 => dwords..)
	# line_size = nr of bytes shown per line
	# view_addr = addr of 1st byte to display
	attr_accessor :show_address, :show_data, :show_ascii,
		:data_size, :line_size, :endianness,
		#:data_sign, :data_hex,
		:caret_x, :caret_y, :caret_x_data, :focus_zone,
		:view_addr, :write_pending, :hl_word

	def initialize(dasm, parent_widget)
		@dasm = dasm
		@parent_widget = parent_widget
		# @caret_x = caret position in octets
		# in hex, round to nearest @data_size and add @caret_x_data (nibbles)
		@caret_x = @caret_y = @caret_x_data = 0
		@oldcaret_x = @oldcaret_y = @oldcaret_x_data = 42
		@focus_zone = @oldfocus_zone = :hex
		@layout = Pango::Layout.new Gdk::Pango.context
		@color = {}
		@view_min = @dasm.sections.keys.min rescue nil
		@view_max = @dasm.sections.map { |s, e| s + e.length }.max rescue nil
		@view_addr = @dasm.prog_binding['entrypoint'] || @dasm.sections.keys.min
		@show_address = @show_data = @show_ascii = true
		@data_size = 1
		@line_size = 16
		@num_lines = 2	# height of widget in lines
		@write_pending = {}	# addr -> newvalue (bytewise)
		@endianness = @dasm.cpu.endianness
		@raw_data_cache = {}	# addr -> raw @line_size data at addr
		#@data_sign = false
		#@data_hex = true

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
			autofit(alloc.width, alloc.height)
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
			set_color_association :ascii => :black, :data => :black,
			  :address => :blue, :caret => :black, :bg => :white,
			  :write_pending => :darkred, :caret_mirror => :palegrey
		}
	end

	def autofit(w, h)
		wc = w/@font_width
		hc = h/@font_height
		ca = current_address
		@num_lines = hc
		@caret_y = hc-1 if @caret_y >= hc
		ols = @line_size
		@line_size = 8
		@line_size *= 2 while x_ascii+(@show_ascii ? @line_size : 0) < wc	# booh..
		@line_size /= 2
		if @line_size != ols
			focus_addr ca
			gui_update
		end
	end

	# converts a screen x coord (in characters) to a [@caret_x, @caret_x_data, @focus_zone]
	def chroff_to_caretx(x)
		if x < x_data
			[0, 0, (@show_data ? :hex : :ascii)]
		elsif x < x_ascii
			x -= x_data
			x -= x/(4*(2*@data_size+1)+1)	# remove space after each 4*@data_size
			x -= x/(2*@data_size+1)		# remove space after each @data_size
			x = 2*@line_size-1 if x >= 2*@line_size	# between hex & ascii
			cx = x/(2*@data_size)*@data_size
			cxd = x-2*cx
			[cx, cxd, :hex]
		elsif x < x_ascii+@line_size
			x -= x_ascii
			[x, 0, :ascii]
		else
			[@line_size-1, 0, (@show_ascii ? :ascii : :hex)]
		end
	end

	def click(ev)
		@caret_x, @caret_x_data, @focus_zone = chroff_to_caretx((ev.x-1).to_i / @font_width)
		@caret_y = ev.y.to_i / @font_height
		update_caret
	end

	def rightclick(ev)
		doubleclick(ev)
	end

	def doubleclick(ev)
		@data_size = {1 => 2, 2 => 4, 4 => 1}[@data_size]
		redraw
	end

	def mouse_wheel(ev)
		off = allocation.height/@font_height/2*@line_size
		case ev.direction
		when Gdk::EventScroll::Direction::UP; @view_addr -= off
		when Gdk::EventScroll::Direction::DOWN; @view_addr += off
		else return
		end
		gui_update
		true
	end

	# returns 1 line of data
	def data_at(addr, len=@line_size)
		if len == @line_size and l = @raw_data_cache[addr]
			l
		elsif s = @dasm.get_section_at(addr).to_a[0] and s.ptr < s.length and (not s.data.respond_to? :page_invalid? or
				not (s.data.page_invalid?(s.ptr) and s.data.page_invalid?(s.ptr+len-1)))
			l = s.read(len)
			@raw_data_cache[addr] = l if len == @line_size
			l
		end
	end

	def paint
		w = window
		gc = Gdk::GC.new(w)

		a = allocation
		w_w = a.width
		w_h = a.height

		curaddr = @view_addr
		# current window position
		x = 1
		y = 0
		@num_lines = 0

		# renders a string at current cursor position with a color
		# must not include newline
		render = lambda { |str, color|
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

		xd = x_data*@font_width
		xa = x_ascii*@font_width
		hexfmt = "%0#{@data_size*2}x "
		wp_win = {} #@write_pending
		@write_pending.keys.grep(curaddr...curaddr+(w_h/@font_height+1)*@line_size).each { |k| wp_win[k] = @write_pending[k] } if not @write_pending.empty?
		# draw text until screen is full
		while y < w_h
			render["#{Expression[curaddr]}".rjust(9, '0'), :address] if @show_address

			d = data_at(curaddr)
			wp = {}
			d.length.times { |o|
				if c = wp_win[curaddr+o]
					wp[o] = true
					d = d.dup
					d[o, 1] = c.chr
				end
			} if d
			if @show_data and d
				x = xd
				# XXX non-hex display ? (signed int, float..)
				case @data_size
				when 1; pak = 'C*'
				when 2; pak = (@endianness == :little ? 'v*' : 'n*')
				when 4; pak = (@endianness == :little ? 'V*' : 'N*')
				end
				awp = {} ; wp.each_key { |k| awp[k/@data_size] = true }
				i = 0
				if awp.empty?
					s = ''
					d.unpack(pak).each { |b|
						s << (hexfmt % b)
						s << ' ' if i & 3 == 3
						i += 1
					}
					render[s, :data]
				else
					d.unpack(pak).each { |b|
						col = awp[i] ? :write_pending : :data
						render[hexfmt % b, col]
						render[' ', :data] if i & 3 == 3
						i+=1
					}
				end
			end
			if @show_ascii and d
				x = xa
				d = d.gsub(/[^\x20-\x7e]/, '.')
				if wp.empty?
					render[d, :ascii]
				else
					d.length.times { |o|
						col = wp[o] ? :write_pending : :ascii
						render[d[o, 1], col]
					}
				end
			end

			curaddr += @line_size
			nl[]
		end

		# draw caret
		# TODO selection
		if @show_data
			gc.set_foreground @color[focus? && @focus_zone == :hex ? :caret : :caret_mirror]
			cx = (x_data + x_data_cur)*@font_width+1
			cy = @caret_y*@font_height
			w.draw_line(gc, cx, cy, cx, cy+@font_height-1)
		end

		if @show_ascii
			gc.set_foreground @color[focus? && @focus_zone == :ascii ? :caret : :caret_mirror]
			cx = (x_ascii + @caret_x)*@font_width+1
			cy = @caret_y*@font_height
			w.draw_line(gc, cx, cy, cx, cy+@font_height-1)
		end

		@oldcaret_x, @oldcaret_y, @oldcaret_x_data, @oldfocus_zone = @caret_x, @caret_y, @caret_x_data, @focus_zone
	end

	# char x of start of data zone
	def x_data
		@show_address ? 11 : 0
	end

	# char x of start of ascii zone
	def x_ascii
		x_data + (@show_data ? @line_size*2 + @line_size/@data_size + @line_size/@data_size/4 : 0)
	end

	# current offset in data zone of caret
	def x_data_cur(cx = @caret_x, cxd = @caret_x_data)
		x = (cx/@data_size)*@data_size
		2*x + x/@data_size + x/@data_size/4 + cxd
	end

	include Gdk::Keyval
	# keyboard binding
	# basic navigation (arrows, pgup etc)
	def keypress(ev)
		return @parent_widget.keypress(ev) if ev.state & Gdk::Window::CONTROL_MASK == Gdk::Window::CONTROL_MASK

		case ev.keyval
		when GDK_Left
			key_left
			update_caret
		when GDK_Right
			key_right
			update_caret
		when GDK_Up
			key_up
			update_caret
		when GDK_Down
			key_down
			update_caret
		when GDK_Page_Up
			if not @view_min or @view_addr > @view_min
				@view_addr -= (@num_lines/2)*@line_size
				gui_update
			end
		when GDK_Page_Down
			if not @view_max or @view_addr < @view_max
				@view_addr += (@num_lines/2)*@line_size
				gui_update
			end
		when GDK_Home
			@caret_x = 0
			update_caret
		when GDK_End
			@caret_x = @line_size-1
			update_caret

		when 0x20..0x7e
			if @focus_zone == :hex
				case v = ev.keyval
				when ?0..?9; v -= ?0
				when ?a..?f; v -= ?a-10
				when ?A..?F; v -= ?A-10
				else return @parent_widget.keypress(ev)
				end
				oo = @caret_x_data/2
				oo = @data_size - oo - 1 if @endianness == :little
				baddr = current_address + oo
				return @parent_widget.keypress(ev) if not d = data_at(baddr, 1)
				o = 4*((@caret_x_data+1) % 2)
				@write_pending[baddr] ||= d[0]
				@write_pending[baddr] = (@write_pending[baddr] & ~(0xf << o) | (v << o))
			else
				@write_pending[current_address] = ev.keyval
			end
			key_right
			redraw
		when GDK_Tab
			switch_focus_zone
			update_caret
		when GDK_Return, GDK_KP_Enter
			commit_writes
			gui_update
		when GDK_Escape
			if not @write_pending.empty?
				@write_pending.clear
				redraw
			else
				return @parent_widget.keypress(ev)	# focus_back
			end

		else
			return @parent_widget.keypress(ev)
		end
		true
	end

	def key_left
		if @focus_zone == :hex
			if @caret_x_data > 0
				@caret_x_data -= 1
			else
				@caret_x_data = @data_size*2-1
				@caret_x -= @data_size
			end
		else
			@caret_x -= 1
		end
		if @caret_x < 0
			@caret_x += @line_size
			key_up
		end
	end

	def key_right
		if @focus_zone == :hex
			if @caret_x_data < @data_size*2-1
				@caret_x_data += 1
			else
				@caret_x_data = 0
				@caret_x += @data_size
			end
		else
			@caret_x += 1
		end
		if @caret_x >= @line_size
			@caret_x = 0
			key_down
		end
	end

	def key_up
		if @caret_y > 0
			@caret_y -= 1
		elsif not @view_min or @view_addr > @view_min
			@view_addr -= @line_size
			redraw
		else
			@caret_x = @caret_x_data = 0
		end
	end

	def key_down
		if @caret_y < @num_lines-2
			@caret_y += 1
		elsif not @view_max or @view_addr < @view_max
			@view_addr += @line_size
			redraw
		else
			@caret_x = @line_size-1		# XXX partial final line... (01 23 45         bla    )
			@caret_x_data = @data_size*2-1
		end
	end

	def switch_focus_zone(n=nil)
		n ||= { :hex => :ascii, :ascii => :hex }[@focus_zone]
		@caret_x = @caret_x / @data_size * @data_size if n == :hex
		@caret_x_data = 0
		@focus_zone = n
	end

	def commit_writes
		a = s = nil
		@write_pending.each { |k, v|
			if not s or k < a or k >= a + s.length
				s, a = @dasm.get_section_at(k)
			end
			next if not s
			s[k-a] = v
		}
		@write_pending.clear
	rescue
		@parent_widget.messagebox($!, $!.class.to_s)
	end

	def get_cursor_pos
		[@view_addr, @caret_x, @caret_y, @caret_x_data, @focus_zone]
	end

	def set_cursor_pos(p)
		@view_addr, @caret_x, @caret_y, @caret_x_data, @focus_zone = p
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
	def update_caret
		return if not window
		return if @oldcaret_x == @caret_x and @oldcaret_y == @caret_y and
				@oldcaret_x_data == @caret_x_data and @oldfocus_zone == @focus_zone
		a = []
		a << [x_data + x_data_cur, @caret_y] << [x_data + x_data_cur(@oldcaret_x, @oldcaret_x_data), @oldcaret_y] if @show_data
		a << [x_ascii + @caret_x, @caret_y] << [x_ascii + @oldcaret_x, @oldcaret_y] if @show_ascii
		a.each { |x, y|
			x *= @font_width
			y *= @font_height
			window.invalidate Gdk::Rectangle.new(x, y, 2, @font_height), false
		}
		@oldcaret_x, @oldcaret_y, @oldcaret_x_data, @oldfocus_zone = @caret_x, @caret_y, @caret_x_data, @focus_zone
	end

	# focus on addr
	# returns true on success (address exists)
	def focus_addr(addr)
		return if not addr = @parent_widget.normalize(addr)
		return if @view_min and (addr < @view_min or addr > @view_max)
		if addr < @view_addr or addr >= @view_addr+(@num_lines-2)*@line_size
			@view_addr = addr&0xffff_fff0
		end
		@caret_x = addr % @line_size
		@caret_x_data = 0
		@caret_y = (addr-@view_addr) / @line_size
		@focus_zone = :ascii
		redraw
		update_caret
		true
	end

	# returns the address of the data under the cursor
	def current_address
		@view_addr + @caret_y.to_i*@line_size + @caret_x.to_i
	end

	def gui_update
		@view_min = @dasm.sections.keys.min rescue nil
		@view_max = @dasm.sections.map { |s, e| s + e.length }.max rescue nil
		@raw_data_cache.clear
		redraw
	end
end
end
end
