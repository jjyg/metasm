#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'gtk2'

module Metasm
module GtkGui
class CdecompListingWidget < Gtk::DrawingArea
	attr_accessor :hl_word

	# construction method
	def initialize(dasm, parent_widget)
		@dasm = dasm
		@parent_widget = parent_widget
		@hl_word = nil
		@oldcaret_x = @oldcaret_y = @caret_x = @caret_y = 0	# caret position in characters coordinates (column/line)
		@layout = Pango::Layout.new Gdk::Pango.context
		@color = {}
		@line_text = []
		@curfunc = nil

		super()

		# receive mouse/kbd events
		set_events Gdk::Event::ALL_EVENTS_MASK
		set_can_focus true
		set_font 'courier 10'

		signal_connect('expose_event') { paint ; true }
		signal_connect('button_press_event') { |w, ev|
			case ev.event_type
			when Gdk::Event::Type::BUTTON_PRESS
				case ev.button
				when 1; click(ev)
				end
			when Gdk::Event::Type::BUTTON2_PRESS
				case ev.button
				when 1; doubleclick(ev)
				end
			end
		}
		signal_connect('key_press_event') { |w, ev| # keyboard
			keypress(ev)
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
			set_color_association :text => :black, :keyword => :blue, :caret => :black,
			  :bg => :white, :hl_word => :palered
		}
	end

	def click(ev)
		@caret_x = (ev.x-1).to_i / @font_width
		@caret_y = ev.y.to_i / @font_height
		update_caret
	end

	def doubleclick(ev)
		@parent_widget.focus_addr(@hl_word)
	end

	def paint
		w = window
		gc = Gdk::GC.new(w)

		a = allocation
		w_w, w_h = a.x + a.width, a.y + a.height

		# current line text buffer
		fullstr = ''
		# current line number
		line = 0
		# current cursor position
		x = 1
		y = 0

		# renders a string at current cursor position with a color
		# must not include newline
		render = lambda { |str, color|
			# function ends when we write under the bottom of the listing
			next if y >= w_h or x >= w_w
			fullstr << str
			@layout.text = str
			gc.set_foreground @color[color]
			w.draw_layout(gc, x, y, @layout)
			x += @layout.pixel_size[0]
		}

		# draw text until screen is full
		while y < w_h and l = @line_text[line]
			render[l, :text]
			y += @layout.pixel_size[1]
			x = 0
			line += 1
		end

		# draw caret
		gc.set_foreground @color[:caret]
		cx = @caret_x*@font_width+1
		cy = @caret_y*@font_height
		w.draw_line(gc, cx, cy, cx, cy+@font_height-1)
	end

	include Gdk::Keyval
	def keypress(ev)
		case ev.keyval
		when GDK_Left
			if @caret_x >= 1
				@caret_x -= 1
				update_caret
			end
		when GDK_Up
			if @caret_y > 0
				@caret_y -= 1
				update_caret
			end
		when GDK_Right
			@caret_x += 1
			update_caret
		when GDK_Down
			@caret_y += 1
			update_caret
		when GDK_Home
			@caret_x = 0
			update_caret
		when GDK_End
			@caret_x = 80
			update_caret
		when GDK_n
			@parent_widget.messagebox('real soon!')
		else
			return @parent_widget.keypress(ev)
		end
		true
	end

	def get_cursor_pos
		[@curfunc, @caret_x, @caret_y]
	end

	def set_cursor_pos(p)
		focus_addr p[0]
		@caret_x, @caret_y = p[1, 2]
		update_caret
	end

	def set_font(descr)
		@layout.font_description = Pango::FontDescription.new(descr)
		@layout.text = 'x'
		@font_width, @font_height = @layout.pixel_size
		redraw
	end

	def set_color_association(hash)
		hash.each { |k, v| @color[k] = @color[v] }
		modify_bg Gtk::STATE_NORMAL, @color[:bg]
		redraw
	end

	# hint that the caret moved
	# redraws the caret, change the hilighted word, redraw if needed
	def update_caret
		return if @oldcaret_x == @caret_x and @oldcaret_y == @caret_y
		x = @oldcaret_x*@font_width+1
		y = @oldcaret_y*@font_height
		window.invalidate Gdk::Rectangle.new(x-1, y, x+1, y+@font_height), false
		x = @caret_x*@font_width+1
		y = @caret_y*@font_height
		window.invalidate Gdk::Rectangle.new(x-1, y, x+1, y+@font_height), false
		@oldcaret_x = @caret_x
		@oldcaret_y = @caret_y

		return if not l = @line_text[@caret_y]
		word = l[0...@caret_x].to_s[/\w*$/] << l[@caret_x..-1].to_s[/^\w*/]
		word = nil if word == ''
		if @hl_word != word
			@hl_word = word
			#redraw
		end
	end

	# focus on addr
	# returns true on success (address exists & decompiled)
	def focus_addr(addr)
		addr = @dasm.normalize(addr)
		return if not @dasm.decoded[addr].kind_of? DecodedInstruction
		# scan up to func start/entrypoint
		todo = [addr]
		done = []
		ep = @dasm.entrypoints.inject({}) { |h, e| h.update @dasm.normalize(e) => true }
		while addr = todo.pop
			next if done.include?(addr) or not @dasm.decoded[addr].kind_of? DecodedInstruction
			addr = @dasm.decoded[addr].block.address
			done << addr
			break if @dasm.function[addr] or ep[addr]
			@dasm.decoded[addr].block.each_from_samefunc(@dasm) { |na| todo << na }
		end
		return true if @curfunc == addr
		return if not l = @dasm.prog_binding.index(addr)
		if not @dasm.c_parser or not f = @dasm.c_parser.toplevel.symbol[l]
			@dasm.decompile(addr)
			f = @dasm.c_parser.toplevel.symbol[l]
		end
		return if not f or not f.type.kind_of? C::Function
		@curfunc = l
		@caret_x = @caret_y = 0
		redraw
		true
	end

	def redraw
		return if not @dasm.c_parser or not f = @dasm.c_parser.toplevel.symbol[@curfunc]
		@line_text = f.dump_def(@dasm.c_parser.toplevel)[0].map { |l| l.gsub("\t", ' '*8) }
		window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false
	end

	# returns the address of the data under the cursor
	def current_address
		@curfunc
	end

	def gui_update
		redraw
	end
end
end
end
