#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'gtk2'

module Metasm
module GtkGui
class CdecompListingWidget < Gtk::DrawingArea
	attr_accessor :hl_word, :curaddr

	# OMGH4X returns a scrolledwindow/viewport/decompwidget
	def self.new(*a)
		n = super(*a)
		c = Gtk::ScrolledWindow.new.add_with_viewport(n)
		c.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC)
		class << c
			attr_accessor :proxy
			def method_missing(*a, &b) @proxy.send(*a, &b) end
		end
		c.proxy = n
		n.set_scroll c
		c
	end

	# construction method
	def initialize(dasm, parent_widget)
		@dasm = dasm
		@parent_widget = parent_widget
		@hl_word = nil
		@oldcaret_x = @oldcaret_y = @caret_x = @caret_y = 0	# caret position in characters coordinates (column/line)
		@layout = Pango::Layout.new Gdk::Pango.context
		@color = {}
		@line_text = []
		@curaddr = nil

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
				when 3; rightclick(ev)
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
			  :yellow => 'cc0', :darkyellow => '660', :paleyellow => 'ff0',
			}.each { |tag, val|
				@color[tag] = Gdk::Color.new(*val.unpack('CCC').map { |c| (c.chr*4).hex })
			}
			# register colors
			@color.each_value { |c| window.colormap.alloc_color(c, true, true) }

			# map functionnality => color
			set_color_association :text => :black, :keyword => :blue, :caret => :black,
			  :bg => :white, :hl_word => :palered, :localvar => :darkred, :globalvar => :darkgreen,
			  :intrinsic => :darkyellow
		}
	end

	def curfunc
		@dasm.c_parser and @dasm.c_parser.toplevel.symbol[@curaddr]
	end

	def click(ev)
		@caret_x = (ev.x-1).to_i / @font_width
		@caret_y = ev.y.to_i / @font_height
		update_caret
	end

	def rightclick(ev)
		click(ev)
		if @dasm.c_parser and @dasm.c_parser.toplevel.symbol[@hl_word]
			@parent_widget.clone_window(@hl_word, :decompile)
		elsif @hl_word
			@parent_widget.clone_window(@hl_word)
		end
	end

	def doubleclick(ev)
		@parent_widget.focus_addr(@hl_word)
	end

	def paint
		w = window
		gc = Gdk::GC.new(w)

		a = allocation
		w_w, w_h = a.x + a.width, a.y + a.height

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
			if @hl_word
				stmp = str
				pre_x = 0
				while stmp =~ /^(.*?)(\b#{Regexp.escape @hl_word}\b)/
					s1, s2 = $1, $2
					@layout.text = s1
					pre_x += @layout.pixel_size[0]
					@layout.text = s2
					hl_w = @layout.pixel_size[0]
					gc.set_foreground @color[:hl_word]
					w.draw_rectangle(gc, true, x+pre_x, y, hl_w, @font_height)
					pre_x += hl_w
					stmp = stmp[s1.length+s2.length..-1]
				end
			end
			@layout.text = str
			gc.set_foreground @color[color]
			w.draw_layout(gc, x, y, @layout)
			x += @layout.pixel_size[0]
		}

		if f = curfunc and f.kind_of? C::Variable and f.initializer.kind_of? C::Block
			keyword_re = /\b(#{C::Keyword.keys.join('|')})\b/
			intrinsic_re = /\b(intrinsic_\w+)\b/
			lv = f.initializer.symbol.keys
			lv << '00' if lv.empty?
			localvar_re = /\b(#{lv.join('|')})\b/
			globalvar_re = /\b(#{f.initializer.outer.symbol.keys.join('|')})\b/
		end

		# draw text until screen is full
		while y < w_h and l = @line_text[line]
			if f
				while l and l.length > 0
					if (i_k = (l =~ keyword_re)) == 0
						m = $1.length
						col = :keyword
					elsif (i_i = (l =~ intrinsic_re)) == 0
						m = $1.length
						col = :intrinsic
					elsif (i_l = (l =~ localvar_re)) == 0
						m = $1.length
						col = :localvar
					elsif (i_g = (l =~ globalvar_re)) == 0
						m = $1.length
						col = :globalvar
					else
						m = ([i_k, i_i, i_l, i_g, l.length] - [nil, false]).min
						col = :text
					end
					render[l[0, m], col]
					l = l[m..-1]
				end
			else
				render[l, :text]
			end

			y += @font_height
			x = 1
			line += 1
		end

		# draw caret
		gc.set_foreground @color[:caret]
		cx = @caret_x*@font_width+1
		cy = @caret_y*@font_height
		w.draw_line(gc, cx, cy, cx, cy+@font_height-1)

		@oldcaret_x, @oldcaret_y = @caret_x, @caret_y

		set_size_request((@line_text.map { |l| l.length }.max.to_i + 1) * @font_width, (@line_text.length + 1)* @font_height)
	end

	include Gdk::Keyval
	# n: rename variable
	# t: retype variable (persistent)
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
			if @caret_x < @line_text[@caret_y].to_s.length
				@caret_x += 1
				update_caret
			end
		when GDK_Down
			if @caret_y < @line_text.length
				@caret_y += 1
				update_caret
			end
		when GDK_Home
			@caret_x = @line_text[@caret_y].to_s[/^\s*/].length
			update_caret
		when GDK_End
			@caret_x = @line_text[@caret_y].to_s.length
			update_caret
		when GDK_n	# rename local/global variable
			f = curfunc.initializer if curfunc and curfunc.initializer.kind_of? C::Block
			n = @hl_word
			if (f and f.symbol[n]) or @dasm.c_parser.toplevel.symbol[n]
				@parent_widget.inputbox("new name for #{n}", :text => n) { |v|
					if v !~ /^[a-z_$][a-z_0-9$]*$/i
						@parent_widget.messagebox("invalid name #{v.inspect} !")
						next
					end
					if f and f.symbol[n]
						# TODO add/update comment to the asm instrs
						s = f.symbol[v] = f.symbol.delete(n)
						f.stackoff_name[s.stackoff] = v if s.stackoff
					elsif f.outer.symbol[n]
						@dasm.rename_label(n, v)
						s = f.outer.symbol[v] = f.outer.symbol.delete(n)
						@curaddr = v if @curaddr == n
					end
					s.name = v
					gui_update
				}
			end
		when GDK_t
			f = curfunc.initializer if curfunc and curfunc.initializer.kind_of? C::Block
			n = @hl_word
			if (f and s = f.symbol[n]) or s = @dasm.c_parser.toplevel.symbol[n]
				@parent_widget.inputbox("new type for #{n}", :text => s.type.to_s) { |t|
					# TODO persistence (store it in
					#  @dasm.function[@curaddr].stackoff_type[v.stackoff] or whatever
					#  patch #decompile to use it)
					# put t in a preprocessor and make @dasm.c_parser parse the type as a cast
					# update the var, redecompile (noauto for batch?)
					@parent_widget.messagebox("unimplemented - sorry")
				}
			end
		else
			return @parent_widget.keypress(ev)
		end
		true
	end

	def get_cursor_pos
		[@curaddr, @caret_x, @caret_y]
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
		@scroll.hadjustment.clamp_page(x-1, x+@font_width)
		@scroll.vadjustment.clamp_page(y, y+@font_height)
		@oldcaret_x = @caret_x
		@oldcaret_y = @caret_y

		return if not l = @line_text[@caret_y]
		word = l[0...@caret_x].to_s[/\w*$/] << l[@caret_x..-1].to_s[/^\w*/]
		word = nil if word == ''
		if @hl_word != word
			@hl_word = word
			redraw
		end
	end

	def set_scroll(sc)
		@scroll = sc
	end

	# focus on addr
	# returns true on success (address exists & decompiled)
	def focus_addr(addr)
		if @dasm.c_parser and @dasm.c_parser.toplevel.symbol[addr]
			@curaddr = addr
			@caret_x = @caret_y = 0
			gui_update
			return true
		end

		return if not addr = @parent_widget.normalize(addr)

		# scan up to func start/entrypoint
		todo = [addr]
		done = []
		ep = @dasm.entrypoints.to_a.inject({}) { |h, e| h.update @dasm.normalize(e) => true }
		while addr = todo.pop
			addr = @dasm.normalize(addr)
			next if not @dasm.decoded[addr].kind_of? DecodedInstruction
			addr = @dasm.decoded[addr].block.address
			next if done.include?(addr) or not @dasm.decoded[addr].kind_of? DecodedInstruction
			done << addr
			break if @dasm.function[addr] or ep[addr]
			empty = true
			@dasm.decoded[addr].block.each_from_samefunc(@dasm) { |na| empty = false ; todo << na }
			break if empty
		end
		return if not l = @dasm.prog_binding.index(addr)
		l = @dasm.auto_label_at(addr)	# if l has multiple names, auto_label_at will give the good one
		@curaddr = l
		@caret_x = @caret_y = 0
		gui_update
		true
	end

	def redraw
		window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false if window
	end

	# returns the address of the data under the cursor
	def current_address
		@curaddr
	end

	def gui_update
		if not curfunc and not @decompiling ||= false
			@line_text = ['please wait']
			redraw
			@decompiling = true
			@dasm.decompile(@curaddr)
			@decompiling = false
		end
		if curfunc
			@line_text = curfunc.dump_def(@dasm.c_parser.toplevel)[0].map { |l| l.gsub("\t", ' '*8) }
			@oldcaret_x = @caret_x + 1
			update_caret
		end
		redraw
	end
end
end
end
