#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'gtk2'

module Metasm
module GtkGui
class CoverageWidget < Gtk::DrawingArea
	# TODO wheel -> zoom, dblclick/rightclick -> clone clickaddr, :dasm, dragdrop -> scroll?(zoomed)
	def initialize(dasm, parent_widget)
		@dasm = dasm
		@parent_widget = parent_widget
		@color = {}
		@curaddr = 0
		@view_width = 0
		@view_height = 0
		@pixel_w = @pixel_h = 1	# use a font ?
		@sections = []

		super()

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
			set_color_association :caret => :yellow, :bg => :palegrey,
				:code => :red, :data => :blue
		}
	end

	def autofit(w, h)
		redraw
	end

	def click(ev)
		# TODO
		ev.x.to_i
		ev.y.to_i
	end

	def rightclick(ev)
		doubleclick(ev)
	end

	def doubleclick(ev)
		# TODO clonewindow(addr, :listing)
	end

	def mouse_wheel(ev)
		# TODO zoom ?
		case ev.direction
		when Gdk::EventScroll::Direction::UP
		when Gdk::EventScroll::Direction::DOWN
		end
	end

	def paint
		w = window
		gc = Gdk::GC.new(w)

		a = allocation
		@view_width = w_w = a.width
		@view_height = w_h = a.height

		@col_height = 32
		@spacing = 4	# TODO dynamic, wrap, stuff

		cols = @view_width/@pixel_w
		cols -= (@sections.length - 1) * @spacing
		cols = 64 if cols < 64

		# find how much bytes we must stuff per pixel so that it fits in the window
		# TODO cache the value
		byte_per_col = @col_height
		loop do
			has = cols
			@sections.each { |a, l, seq|
				has -= (l + byte_per_col - 1) / byte_per_col
			}
			break if has >= 0
			byte_per_col *= 2
		end


		x = 0
		y = ybase = 8

		# 1 5
		# 2 6
		# 3 ...
		# 4

		# draws a rectangle covering h1 to h2 in y, of width w
		# advances x as needed
		draw_rect = lambda { |h1, h2, w|
			h2 += 1
			w.draw_rectangle(gc, true, x, ybase+@pixel_h*h2-1, @pixel_w*w-1, @pixel_h*(h2-h1)-1)
			w -= 1 if h2 != @col_height
			x += w*@pixel_w
		}

		# draws rectangles to cover o1 to o2
		draw = lambda { |o1, o2|
			o1 /= byte_per_col / @col_height
			o2 /= byte_per_col / @col_height
			next if o1 <= o2

			o11 = o1 % @col_height
			o12 = o1 / @col_height
			o21 = o2 % @col_height
			o22 = o2 / @col_height

			if o11 > 0
				draw_rect[o11, (o12 == o22 ? o21 : @col_height-1), 1]
				next if o12 == o22
			end

			o22 += 1 if o21 == 0
			if o12 < o22
				draw_rect[0, @col_height-1, o22-o12]
			end

			if o21 > 0
				draw_rect[0, o21, 1]
			end
		}

		@sections.each { |a, l, seq|
			curoff = 0
			xstart = x
			seq += [[l, l]]	if not seq[-1] or seq[-1][1] < l	# to draw last data
			seq.each { |o, oe|
				gc.set_foreground @color[:data]
				draw[curoff, o-1]
				gc.set_foreground @color[:code]
				draw[o, oe]
				curoff = oe+1
			}
			x += @spacing*@pixel_w

			# caret
			co = @curaddr-a
			if co >= 0 and co < l
				gc.set_foreground @color[:caret]
				x = xstart
				draw[co, co+byte_per_col/@col_height]
			end

			# TODO save section offsets to click.ev -> addr
		}
	end

	include Gdk::Keyval
	def keypress(ev)
		return @parent_widget.keypress(ev)
	end

	def get_cursor_pos
		@curaddr
	end

	def set_cursor_pos(p)
		@curaddr = p
		redraw
	end

	def set_font(descr)
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

	# focus on addr
	# returns true on success (address exists)
	def focus_addr(addr)
		return if not addr = @parent_widget.normalize(addr)
		@curaddr = addr
		redraw
		true
	end

	# returns the address of the data under the cursor
	def current_address
		@curaddr
	end

	def gui_update
		# ary of section [addr, len, codespan]
		# codespan is an ary of [code_off_start, code_off_end] (sorted by off)
		@sections = @dasm.sections.map { |ed, a|
			a = Expression[a].reduce
			l = ed.length
			acc = []
			# stuff with addr-section_addr is to handle non-numeric section addrs (eg elf ET_REL)
			@dasm.decoded.keys.map { |da| da-a rescue nil }.grep(Integer).grep(0..l).sort.each { |o|
				da = @dasm.decoded[a+o]
				next if not da.kind_of? DecodedInstruction
				oe = o + da.length
				if acc[-1] and acc[-1][1] >= o
					# handle di overlapping
					acc[-1][1] = oe if acc[-1][1] < oe
				else
					acc << [o, oe]
				end
			}
			[a, l, acc]
		}
		redraw
	end
end
end
end
