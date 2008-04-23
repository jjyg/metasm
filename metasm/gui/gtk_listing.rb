#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'gtk2'

module Metasm
module GtkGui
class AsmListingWidget < Gtk::HBox
	# construction method
	def initialize(dasm, entrypoints)
		@dasm = dasm
		@entrypoints = entrypoints
		@view_history = []	# addrs we jumped from using focus_addr
		@arrows = []	# array of [linefrom, lineto] (may be :up or :down for offscreen)
		@line_address = {}
		@line_text = {}
		@hl_word = nil
		@caret_x = @caret_y = 0	# caret position in characters coordinates (column/line)
		@oldcaret_x = @oldcaret_y = 42
		@layout = Pango::Layout.new Gdk::Pango.context
		@color = {}

		super()

		@arrows_widget = Gtk::DrawingArea.new
		@listing_widget = Gtk::DrawingArea.new
		@vscroll = Gtk::VScrollbar.new
		pack_start @arrows_widget, false, false
		pack_start @listing_widget
		pack_end @vscroll, false, false
		# TODO listing hscroll (viewport?)

		@arrows_widget.set_size_request 40, 0	# TODO resizer
		@vscroll.adjustment.lower = @dasm.sections.keys.min
		@vscroll.adjustment.upper = @dasm.sections.keys.max + @dasm.sections[@dasm.sections.keys.max].length
		@vscroll.adjustment.step_increment = 1
		@vscroll.adjustment.page_increment = 10
		@vscroll.adjustment.value = @vscroll.adjustment.lower
		set_font 'courier 10'

		# receive mouse/kbd events
		@listing_widget.set_events Gdk::Event::ALL_EVENTS_MASK
		set_can_focus true

		# callbacks
		@arrows_widget.signal_connect('expose_event') { paint_arrows ; true }
		@listing_widget.signal_connect('expose_event') { paint_listing ; true }
		@listing_widget.signal_connect('button_press_event') { |w, ev|
			case ev.event_type
			when Gdk::Event::Type::BUTTON_PRESS
				case ev.button
				when 1: click(ev)
				end
			when Gdk::Event::Type::BUTTON2_PRESS
				case ev.button
				when 1: doubleclick(ev)
				end
			end
		}
		@listing_widget.signal_connect('size_allocate') { |w, alloc| # resize
			lines = alloc.height / @font_height
			cols = alloc.width / @font_width
			@caret_y = lines-1 if @caret_y >= lines
			@caret_x = cols-1 if @caret_x >= cols
			@vscroll.adjustment.page_increment = lines/2
		}
		@vscroll.adjustment.signal_connect('value_changed') { |adj|
			# align on @decoded boundary
			addr = adj.value.to_i
			if off = (0..16).find { |off| di = @dasm.decoded[addr-off] and di.respond_to? :bin_length and di.bin_length > off } and off != 0
				@vscroll.adjustment.value = addr-off
			else
				@line_address.clear	# make paint_listing call update_caret when done (hl_word etc)
				redraw
			end
		}
		signal_connect('key_press_event') { |w, ev| # keyboard
			keypress(ev)
		}
		signal_connect('scroll_event') { |w, ev| # mouse wheel
			case ev.direction
			when Gdk::EventScroll::Direction::UP
				# TODO scroll up exactly win_height/2 lines
				# at least cache page_down addresses
				@vscroll.adjustment.value -= @vscroll.adjustment.page_increment
				true
			when Gdk::EventScroll::Direction::DOWN
				pgdown = @line_address[@line_address.keys.max.to_i/2] || @vscroll.adjustment.value
				pgdown += @vscroll.adjustment.page_increment if pgdown == @vscroll.adjustment.value
				@vscroll.adjustment.value = pgdown
				true
			end
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
			  :listing_bg => :white, :cursorline_bg => :paleyellow, :hl_word => :palered,
			  :arrows_bg => :palegrey,
			  :arrow_up => :darkblue, :arrow_dn => :darkyellow, :arrow_hl => :red
		}
	end

	# 
	# methods used as Gtk callbacks
	#
	
	# TODO right click
	def click(ev)
		@caret_x = (ev.x-1).to_i / @font_width
		@caret_y = ev.y.to_i / @font_height
		update_caret
	end

	def doubleclick(ev)
		focus_addr(@hl_word)
	end

	# renders the disassembler in the @listing_widget using @vscroll.adjustment.value
	# creates the @arrows needed by #paint_arrows
	def paint_listing
		w = @listing_widget.window
		gc = Gdk::GC.new(w)

		a = @listing_widget.allocation
		w_w, w_h = a.x + a.width, a.y + a.height

		# draw caret line background
		gc.set_foreground @color[:cursorline_bg]
		w.draw_rectangle(gc, true, 0, @caret_y*@font_height, w_w, @font_height)

		# TODO scroll line-by-line when an addr is displayed on multiple lines (eg labels/comments)
		# TODO selection & current word hilight
		curaddr = @vscroll.adjustment.value.to_i

		want_update_caret = true if @line_address == {}

		# map lineno => adress shown
		@line_address = Hash.new(-1)
		# map lineno => raw text
		@line_text = Hash.new('')

		# current line text buffer
		fullstr = ''
		# current line number
		line = 0
		# current window position
		x = 1
		y = 0

		# list of arrows to draw ([addr_from, addr_to])
		arrows_addr = []

		# renders a string at current cursor position with a color
		# must not include newline
		render = proc { |str, color|
			# function ends when we write under the bottom of the listing
			next if y >= w_h or x >= w_w
			fullstr << str
			# TODO selection
			if @hl_word and str =~ /^(.*)(\b#{Regexp.escape @hl_word}\b)/
				s1, s2 = $1, $2
				@layout.text = s1
				pre_x = @layout.pixel_size[0]
				@layout.text = s2
				hl_x = @layout.pixel_size[0]
				gc.set_foreground @color[:hl_word]
				w.draw_rectangle(gc, true, x+pre_x, y, hl_x, @font_height)
			end
			@layout.text = str
			gc.set_foreground @color[color]
			w.draw_layout(gc, x, y, @layout)
			x += @layout.pixel_size[0]
		}
		# newline: current line is fully rendered, update @line_address/@line_text etc
		nl = proc {
			@line_text[line] = fullstr
			@line_address[line] = curaddr
			fullstr = ''
			line += 1
			x = 1
			y += @font_height
		}

		# draw text until screen is full
		# builds arrows_addr with addresses
		while y < w_h
			if di = @dasm.decoded[curaddr] and di.kind_of? Metasm::DecodedInstruction
				# a decoded instruction : check if it's a block start
				if di.block.list.first == di
					# render dump_block_header, add a few colors
					b_header = '' ; @dasm.dump_block_header(di.block) { |l| b_header << l ; b_header << ?\n if b_header[-1] != ?\n }
					b_header.each { |l| l.chomp!
						col = :comment
						col = :label if l[0, 2] != '//' and l[-1] == ?:
						render[l, col]
						nl[]
					}
					di.block.each_from_samefunc(@dasm) { |addr|
						addr = @dasm.normalize addr
						next if not addr.kind_of? ::Integer or (@dasm.decoded[addr].kind_of? Metasm::DecodedInstruction and addr + @dasm.decoded[addr].bin_length == curaddr)
						arrows_addr << [addr, curaddr]
					}
				end
				if di.block.list.last == di
					di.block.each_to_samefunc { |addr|
						addr = @dasm.normalize addr
						next if not addr.kind_of? ::Integer or addr == curaddr + di.bin_length
						arrows_addr << [curaddr, addr]
					}
				end
				render[Metasm::Expression[di.address].to_s + '    ', :address]
				render[di.instruction.to_s.ljust(24), :instruction]
				render[' ; ' + di.comment.join(' '), :comment] if di.comment
				nl[]

				# instr overlapping
				if off = (1...di.bin_length).find { |off| @dasm.decoded[curaddr + off] }
					nl[]
					curaddr += off
					render["// ------ overlap (#{di.bin_length - off}) ------", :comment]
					nl[]
				else
					curaddr += di.bin_length
				end
			elsif curaddr < @vscroll.adjustment.upper
				# TODO real data display (dwords, xrefs, strings..)
				if label = @dasm.prog_binding.index(curaddr) and @dasm.xrefs[curaddr]
					render[Metasm::Expression[curaddr].to_s + '    ', :address]
					render[label + ' ', :label]
				else
					if label
						render[label+':', :label]
						nl[]
					end
					render[Metasm::Expression[curaddr].to_s + '    ', :address]
				end
				s = @dasm.get_section_at(curaddr)
				render['db '+((s and s[0].rawsize > s[0].ptr) ? Metasm::Expression[s[0].read(1)[0]].to_s : '?'), :instruction]
				nl[]
				curaddr += 1
			else
				render['', :text]
				nl[]
			end
		end

		# draw caret
		# TODO selection
		gc.set_foreground @color[:caret]
		cx = @caret_x*@font_width+1
		cy = @caret_y*@font_height
		w.draw_line(gc, cx, cy, cx, cy+@font_height-1)

		# convert arrows_addr to @arrows (with line numbers)
		# updates @arrows_widget if @arrows changed
		prev_arrows = @arrows
		addr_line = @line_address.sort.inject({}) { |h, (l, a)| h.update a => l }	# addr => last line (di)
		@arrows = arrows_addr.uniq.sort.map { |from, to|
			[(addr_line[from] || (from < curaddr ? :up : :down)),
			 (addr_line[ to ] || ( to  < curaddr ? :up : :down))]
		}
		@arrows_widget.window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false if prev_arrows != @arrows

		update_caret if want_update_caret
	end

	# draws the @arrows defined in paint_listing
	def paint_arrows
		return if @arrows.empty? or @line_address[@caret_y] == -1
		w = @arrows_widget.window
		gc = Gdk::GC.new(w)
		w_w, w_h = @arrows_widget.allocation.width, @arrows_widget.allocation.height

		slot_alloc = {}	# [y1, y2] => x slot	-- y1 <= y2
		# find a free x slot for the vertical side of the arrow
		max = (w_w-6)/3
		find_free = proc { |y1, y2|
			y1, y2 = y2, y1 if y2 < y1
			slot_alloc[[y1, y2]] = (0...max).find { |off|
				not slot_alloc.find { |(oy1, oy2), oo|
					# return true if this slot cannot share with off
					next if oo != off	# not same slot => ok
					next if oy1 == y1 and y1 != 0		# same upbound & in window
					next if oy2 == y2 and y2 != w_h-1	# same lowbound & in window
					# check overlapping segment
					(y1 >= oy1 and y1 <= oy2) or
					(y2 >= oy1 and y2 <= oy2) or
					(oy1 >= y1 and oy1 <= y2) or
					(oy2 >= y1 and oy2 <= y2)
				}
			} || (max-1)
		}

		# alloc slots for arrows, starts by the smallest
		arrs = { :arrow_dn => [], :arrow_up => [], :arrow_hl => [] }
		@arrows.sort_by { |from, to|
			if from.kind_of? Numeric and to.kind_of? Numeric
				(from-to).abs
			else
				100000
			end
		}.each { |from, to|
			y1 = case from
			when :up: 0
			when :down: w_h-1
			else from * @font_height + @font_height/2 - 1
			end
			y2 = case to
			when :up: 0
			when :down: w_h-1
			else to * @font_height + @font_height/2 - 1
			end
			if y1 <= y2
				y1 += 2 if y1 != 0
			else
				y1 -= 2 if y1 != w_h-1
			end

			col = :arrow_dn
			col = :arrow_up if y1 > y2
			col = :arrow_hl if @line_address[from] == @line_address[@caret_y] or @line_address[to] == @line_address[@caret_y]
			arrs[col] << [y1, y2, find_free[y1, y2]]
		}

		slot_w = (w_w-4)/slot_alloc.values.uniq.length
		# draw arrows (hl last to overwrite)
		[:arrow_dn, :arrow_up, :arrow_hl].each { |col|
			gc.set_foreground @color[col]
			arrs[col].each { |y1, y2, slot|
				x1 = w_w-1
				x2 = w_w-4 - slot*slot_w - slot_w/2
				
				w.draw_line(gc, x1, y1, x2, y1) if y1 != 0 and y1 != w_h-1
				w.draw_line(gc, x2, y1, x2, y2)
				w.draw_line(gc, x2, y2, x1, y2) if y2 != 0 and y2 != w_h-1
				w.draw_line(gc, x1, y2, x1-3, y2-3) if y2 != 0 and y2 != w_h-1
				w.draw_line(gc, x1, y2, x1-3, y2+3) if y2 != 0 and y2 != w_h-1
			}
		}
	end

	include Gdk::Keyval
	# keyboard binding
	# basic navigation (arrows, pgup etc)
	# dasm navigation
	#  enter => go to label definition
	#  esc => jump back
	# dasm interaction
	#  c => start disassembling from here
	#  g => prompt for an address to jump to
	#  h => prompt for a C header file to read
	#  n => rename a label
	#  p => pause/play disassembler
	#  x => show xrefs
	#
	def keypress(ev)
		case ev.keyval
		when GDK_Left
			if @caret_x >= 1
				@caret_x -= 1
				update_caret
			end
		when GDK_Up
			if @caret_y > 1 or (@caret_y == 1 and @vscroll.adjustment.value == @vscroll.adjustment.lower)
				@caret_y -= 1
			else
				@vscroll.adjustment.value -= 1
			end
			update_caret
		when GDK_Right
			if @caret_x <= @line_text.values.map { |s| s.length }.max
				@caret_x += 1
				update_caret
			end
		when GDK_Down
			if @caret_y < @line_text.length-2 or (@caret_y < @line_text.length - 1 and @vscroll.adjustment.value == @vscroll.adjustment.upper)
				@caret_y += 1
			else
				off = 1
				if a = @line_address[0] and @dasm.decoded[a].kind_of? Metasm::DecodedInstruction
					off = @dasm.decoded[a].bin_length
				end
				@vscroll.adjustment.value += off
			end
			update_caret
		when GDK_Page_Up
			@vscroll.adjustment.value -= @vscroll.adjustment.page_increment
			update_caret
		when GDK_Page_Down
			pgdown = @line_address[@line_address.length/2] || @vscroll.adjustment.value
			pgdown = @vscroll.adjustment.value + @vscroll.adjustment.page_increment if pgdown == @vscroll.adjustment.value
			@vscroll.adjustment.value = pgdown
			update_caret
		when GDK_Home
			@caret_x = 0
			update_caret
		when GDK_End
			@caret_x = @line_text[@caret_y].length
			update_caret

		when GDK_Return, GDK_KP_Enter
			focus_addr @hl_word
		when GDK_Escape
			@vscroll.adjustment.value, @caret_x, @caret_y = @view_history.pop if not @view_history.empty?
			update_caret

		when GDK_c	# disassemble from this point
				# if points to a call, make it return
			#@entrypoints << @line_address[@caret_y]
			return if not addr = @line_address[@caret_y]
			if di = @dasm.decoded[addr] and di.kind_of? Metasm::DecodedInstruction and di.opcode.props[:saveip] and not @dasm.decoded[addr + di.bin_length]
				@dasm.addrs_todo << [addr + di.bin_length, addr, true]
			else
				@dasm.addrs_todo << [addr]
			end
		when GDK_g	# jump to address
			InputBox.new('address to go') { |v| focus_addr v }
		when GDK_h	# parses a C header
			OpenFile.new('open C header') { |f|
				@dasm.parse_c_file(f) rescue MessageBox.new("#{$!}\n#{$!.backtrace}")
			}
		when GDK_n	# name/rename a label
			if not @hl_word or not addr = @dasm.prog_binding[@hl_word]
				return if not addr = @line_address[@caret_y]
			end
			if old = @dasm.prog_binding.index(addr)
				InputBox.new("new name for #{old}") { |v| @dasm.rename_label(old, v) ; redraw }
			else
				InputBox.new("label name for #{Metasm::Expression[addr]}") { |v| @dasm.rename_label(@dasm.label_at(addr, v), v) ; redraw }
			end
		when GDK_p	# pause/play disassembler
			@dasm_pause ||= []
			if @dasm_pause.empty? and @dasm.addrs_todo.empty?
			elsif @dasm_pause.empty?
				@dasm_pause = @dasm.addrs_todo.dup
				@dasm.addrs_todo.clear
				puts "dasm paused (#{@dasm_pause.length})"
			else
				@dasm.addrs_todo.concat @dasm_pause
				@dasm_pause.clear
				puts "dasm restarted (#{@dasm.addrs_todo.length})"
			end
		when GDK_r	# reload this file
			load __FILE__
			redraw
			puts 'reloaded'
		when GDK_v	# toggle verbose flag
			$VERBOSE = ! $VERBOSE
			puts "verbose #$VERBOSE"
		when GDK_x	# show xrefs to the current address
			return if not addr = @line_address[@caret_y]
			lst = ["list of xrefs to #{Metasm::Expression[addr]}"]
			@dasm.each_xref(addr) { |xr|
				if @dasm.decoded[xr.origin].kind_of? Metasm::DecodedInstruction
					org = @dasm.decoded[xr.origin]
				else
					org = Metasm::Expression[xr.origin]
				end
				lst << "xref #{xr.type}#{xr.len} from #{org}"
			}
			MessageBox.new lst.join("\n ")
		when GDK_i	# misc debug
			#load 'metasm/ia32/render.rb'
			begin
			a = []
			@dasm.decoded[@line_address[@caret_y]].block.each_to { |to| a << "#{Metasm::Expression[to[0]]} #{to[1]}" }
			MessageBox.new a.inspect 
			rescue
				MessageBox.new $!
			end
		when 0x20..0x7e	# normal kbd (use ascii code)
		when GDK_Shift_L, GDK_Shift_R, GDK_Control_L, GDK_Control_R, GDK_Alt_L, GDK_Alt_R, GDK_Meta_L,
		     GDK_Meta_R, GDK_Super_L, GDK_Super_R, GDK_Menu
		else
			c = Gdk::Keyval.constants.find { |c| Gdk::Keyval.const_get(c) == ev.keyval }
			p [:unknown_keypress, ev.keyval, c, ev.state]
		end
		false
	end
	
	# 
	# Widget external API
	#
	
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
		@listing_widget.modify_bg Gtk::STATE_NORMAL, @color[:listing_bg]
		@arrows_widget.modify_bg Gtk::STATE_NORMAL, @color[:arrows_bg]
		redraw
	end

	# redraw the whole widget
	def redraw
		return if not @listing_widget.window
		@listing_widget.window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false
		@arrows_widget.window.invalidate  Gdk::Rectangle.new(0, 0, 100000, 100000), false
	end

	# hint that the caret moved
	# redraws the caret, change the hilighted word, redraw if needed
	def update_caret
		l = @line_text[@caret_y]
		word = l[0...@caret_x].to_s[/\w*$/] << l[@caret_x..-1].to_s[/^\w*/]
		word = nil if word == ''
		if @hl_word != word or @oldcaret_y != @caret_y
			@hl_word = word
			redraw
		else
			return if @oldcaret_x == @caret_x and @oldcaret_y == @caret_y
			x = @oldcaret_x*@font_width+1
			y = @oldcaret_y*@font_height
			@listing_widget.window.invalidate Gdk::Rectangle.new(x-1, y, x+1, y+@font_height), false
			x = @caret_x*@font_width+1
			y = @caret_y*@font_height
			@listing_widget.window.invalidate Gdk::Rectangle.new(x-1, y, x+1, y+@font_height), false
			if @arrows.find { |f, t| f == @caret_y or t == @caret_y or f == @oldcaret_y or t == @oldcaret_y }
				@arrows_widget.window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false
			end
		end

		@oldcaret_x = @caret_x
		@oldcaret_y = @caret_y
	end

	# focus on addr
	# addr may be a dasm label, dasm address, dasm address in string form (eg "0DEADBEEFh")
	# may scroll the window
	# updates @view_history
	# returns true on success (address exists)
	def focus_addr(addr)
		return if not addr or addr == ''
		if addr.kind_of? ::String
			if (?0..?9).include? addr[0]
				addr = '0x'+addr[0...-1] if addr[-1] == ?h
				begin
					addr = Integer(addr)
				rescue ::ArgumentError
					MessageBox.new "Invalid address #{addr}"
					return
				end
			elsif @dasm.prog_binding[addr]
				addr = @dasm.prog_binding[addr]
			else
				MessageBox.new "Unknown label #{addr}"
				return
			end
		end
		@view_history << [@vscroll.adjustment.value, @caret_x, @caret_y]
		if l = @line_address.index(addr) and l < @line_address.keys.max - 4
			@caret_y, @caret_x = @line_address.keys.find_all { |k| @line_address[k] == addr }.max, 0
		else
			@vscroll.adjustment.value, @caret_x, @caret_y = addr, 0, 0
		end
		update_caret
		true
	end

	# returns the address of the data under the cursor
	def current_address
		@line_address[@caret_y]
	end

	def gui_update
		redraw
	end
end
end
end
