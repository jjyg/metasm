#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'gtk2'

module Metasm
module GtkGui
class Graph
	# one box, has a text, an id, and a list of other boxes to/from
	class Box
		attr_accessor :id, :x, :y, :w, :h
		attr_accessor :to, :from # other boxes linked (arrays)
		attr_accessor :content
		def initialize(id, content=nil)
			@id = id
			@x = @y = @w = @h = 0
			@to, @from = [], []
			@content = content
		end
		def [](a) @content[a] end
		def inspect ; puts caller ; "#{Expression[@id] rescue @id.inspect}" end
	end

	# TODO
	class MergedBox
		attr_accessor :id, :text, :x, :y, :w, :h
		attr_accessor :to, :from
	end

	attr_accessor :id, :box, :root_addrs, :view_x, :view_y
	def initialize(id)
		@id = id
		clear
	end

	# empty @box, @view_x, @view_y
	def clear
		@view_x = @view_y = 0
		@box = []
	end

	# link the two boxes (by id)
	def link_boxes(id1, id2)
		raise "unknown index 1 #{id1}" if not b1 = @box.find { |b| b.id == id1 }
		raise "unknown index 2 #{id2}" if not b2 = @box.find { |b| b.id == id2 }
		b1.to   |= [b2]
		b2.from |= [b1]
	end

	# creates a new box, ensures id is not already taken
	def new_box(id, content=nil)
		raise "duplicate id #{id}" if @box.find { |b| b.id == id }
		b = Box.new(id, content)
		@box << b
		b
	end

	# checks if a box is reachable from another following a 'to' chain
	# TODO cache a cantreach b (all allowed)
	def can_reach(src, dst, allow=@box)
		src.to.each { |f|
			next if not allow.include? f
			return true if dst == f
			return true if can_reach(f, dst, allow-[src])
		}
		false
	end

	# place boxes in a good-looking layout
	def auto_arrange_boxes
		# groups is an array of box groups
		# all groups are centered on the origin
		groups = @box.map { |b|
			b.x = -b.w/2
			b.y = -b.h/2
			g = Box.new(nil, [b])
			g.x = b.x - 8
			g.y = b.y - 8
			g.w = b.w + 16
			g.h = b.h + 16
			g
		}

		# init group.to/from
		# must always point to something that is in the 'groups' array
		# no self references
		# a box is in one and only one group in 'groups'
		groups.each { |g|
			g.to   = g.content.first.to.map   { |t| groups[@box.index(t)] } - [g]
			g.from = g.content.first.from.map { |f| groups[@box.index(f)] } - [g]
		}

		# concat all ary boxes into its 1st element, remove trailing groups from 'groups'
		# updates from/to
		merge_groups = proc { |ary|
			bg = Box.new(nil, [])
			bg.x, bg.y = ary.map { |g| g.x }.min, ary.map { |g| g.y }.min
			bg.w, bg.h = ary.map { |g| g.x+g.w }.max - bg.x, ary.map { |g| g.y+g.h }.max - bg.y
			ary.each { |g|
				bg.content.concat g.content
				bg.to |= g.to
				bg.from |= g.from
			}
			bg.to -= ary
			bg.to.each { |t| t.from = t.from - ary + [bg] }
			bg.from -= ary
			bg.from.each { |f| f.to = f.to - ary + [bg] }
			idx = ary.map { |g| groups.index(g) }.min
			groups = groups - ary
			groups.insert(idx, bg)
			bg
		}

		# move all boxes within group of dx, dy
		move_group = proc { |g, dx, dy|
			g.content.each { |b| b.x += dx ; b.y += dy }
			g.x += dx ; g.y += dy
		}

		align_hz = proc { |ary|
			nx = ary.map { |g| g.w }.inject { |a, b| a+b } / -2
			ary.each { |g|
				move_group[g, nx-g.x, 0]
				nx += g.w
			}
		}
		align_vt = proc { |ary|
			ny = ary.map { |g| g.h }.inject { |a, b| a+b } / -2
			ary.each { |g|
				move_group[g, 0, ny-g.y]
				ny += g.h
			}
		}

		# scan groups for a column pattern (head has 1 'to' which from == [head]
		group_columns = proc {
			groups.find { |g|
				next if g.from.length == 1 and g.from.first.to.length == 1
				ary = [g]
				ary << (g = g.to.first) while g.to.length == 1 and g.to.first.from.length == 1
				next if ary.length == 1
				align_vt[ary]
				merge_groups[ary]
				true
			}
		}

		# scan groups for a line pattern (multiple groups with same to & same from)
		group_lines = proc {
			groups.find { |g|
				ary = groups.find_all { |gg|
					g.from.uniq.length == gg.from.uniq.length and (g.from - gg.from).empty? and
					g.to.uniq.length == gg.to.uniq.length and (g.to - gg.to).empty?
				}
				next if ary.length == 1
				dy = 16*(ary.length-2)	# many boxes => lower
				ary.each { |g| move_group[g, 0, dy] ; g.h += dy ; g.y -= dy }
				merge_groups[ary]
				align_hz[ary]
				true
			}
		}

		# scan groups for a if/then pattern (1 -> 2 -> 3 & 1 -> 3)
		group_ifthen = proc { |strict|
			groups.find { |g|
				next if not g2 = g.to.find { |g2| (g2.to.length == 1 and g.to.include?(g2.to.first)) or
					(not strict and g2.to.empty?)  }
				next if strict and g2.from != [g]
				align_vt[[g, g2]]
				move_group[g2, g2.w/2, 0]
				g2.x -= g2.w ; g2.w *= 2	# so that merge gives the correct x/w to head
				merge_groups[[g, g2]]
				true
			}
		}

		# unknown pattern, group as we can..
		group_other = proc {
			next if groups.length == 1
puts 'unknown configuration', groups.map { |g| "#{groups.index(g)} -> #{g.to.map { |t| groups.index(t) }.inspect}" }
			g1 = groups.find_all { |g| g.from.empty? }
			g1 << groups.first if g1.empty?
			g2 = g1.map { |g| g.to }.flatten.uniq - g1

			align_hz[g1]
			g1 = merge_groups[g1]
			move_group[g1, 0, -24]
			g1.h += 48
			align_hz[g2]
			g2 = merge_groups[g2]
			move_group[g2, 0, 24]
			g2.h += 48 ; g2.y -= 48

			align_vt[[g1, g2]]
			merge_groups[[g1, g2]]
			true
		}

		nil while group_columns[] or group_lines[] or group_ifthen[true] or group_ifthen[false] or group_other[]

		@view_x = groups.first.x-10
		@view_y = groups.first.y-10
	end
end





class GraphViewWidget < Gtk::HBox
	def initialize(dasm, entrypoints=[])
		@dasm = dasm
		@entrypoints = entrypoints
		@view_history = []
		@hl_word = nil
		@caret_x = @caret_y = @caret_box = nil
		@layout = Pango::Layout.new Gdk::Pango.context
		@color = {}
		@selected_boxes = []
		@shown_boxes = []
		@mousemove_origin = nil
		@curcontext = Graph.new(nil)
		@zoom = 1.0
		# @allgraphs = ?
		# scrollbars ?

		super()

		@drawarea = Gtk::DrawingArea.new
		pack_start @drawarea

		@drawarea.set_size_request 400, 400		# default control size
		@width = @height = 400

		set_font 'courier 10'
		
		@drawarea.set_events Gdk::Event::ALL_EVENTS_MASK	# receive click/keys
		set_can_focus true			# receive keys

		@drawarea.signal_connect('expose_event') { paint ; true }
		@drawarea.signal_connect('motion_notify_event') { |w, ev|
			mousemove(ev) if @mousemove_origin
		}
		@drawarea.signal_connect('size_allocate') { |w, ev| @width, @height = ev.width, ev.height }
		signal_connect('button_press_event') { |w, ev|
			case ev.event_type
			when Gdk::Event::BUTTON_PRESS
				case ev.button
				when 1: click(ev)
				when 3: rightclick(ev)
				end
			when Gdk::Event::BUTTON2_PRESS
				doubleclick(ev)
			end
		}
		signal_connect('button_release_event') { |w, ev|
			mouserelease(ev) if @mousemove_origin and ev.button == 1
		}
		signal_connect('scroll_event') { |w, ev|
			mousewheel(ev)
		}
		signal_connect('key_press_event') { |w, ev|
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
			set_color_association :bg => :paleblue, :hlbox_bg => :palegrey, :box_bg => :white,
				:text => :black, :arrow => :black, :arrow_hl => :red, :comment => :darkblue,
				:instruction => :black, :label => :darkgreen, :caret => :black, :hl_word => :palered,
				:cursorline_bg => :paleyellow
		}
	end

	def find_box_xy(x, y)
		x = @curcontext.view_x+x/@zoom
		y = @curcontext.view_y+y/@zoom
		@shown_boxes.to_a.reverse.find { |b| b.x <= x+@zoom and b.x+b.w >= x and b.y <= y+@zoom and b.y+b.h >= y }
	end

	def mousewheel(ev)
		case ev.direction
		when Gdk::EventScroll::Direction::UP
			if ev.state & Gdk::Window::CONTROL_MASK == Gdk::Window::CONTROL_MASK
				if @zoom < 100
					@curcontext.view_x += (ev.x / @zoom - ev.x / (@zoom*1.1))
					@curcontext.view_y += (ev.y / @zoom - ev.y / (@zoom*1.1))
					@zoom *= 1.1
				end
			else
				@curcontext.view_y -= @height/4 / @zoom
			end
			redraw
		when Gdk::EventScroll::Direction::DOWN
			if ev.state & Gdk::Window::CONTROL_MASK == Gdk::Window::CONTROL_MASK
				if @zoom > 1.0/100
					@curcontext.view_x += (ev.x / @zoom - ev.x / (@zoom/1.1))
					@curcontext.view_y += (ev.y / @zoom - ev.y / (@zoom/1.1))
					@zoom /= 1.1
				end
			else
				@curcontext.view_y += @height/4 / @zoom
			end
			redraw
		end
	end
	
	def mousemove(ev)
		dx = (ev.x - @mousemove_origin[0])/@zoom
		dy = (ev.y - @mousemove_origin[1])/@zoom
		@mousemove_origin = [ev.x, ev.y]
		if @selected_boxes.empty?
			@curcontext.view_x -= dx ; @curcontext.view_y -= dy
		else
			@selected_boxes.each { |b| b.x += dx ; b.y += dy }
		end
		redraw
	end

	def mouserelease(ev)
		mousemove(ev)
		@mousemove_origin = nil
	end

	def click(ev)
		@mousemove_origin = [ev.x, ev.y]
		b = find_box_xy(ev.x, ev.y)
		if ev.state & Gdk::Window::CONTROL_MASK == Gdk::Window::CONTROL_MASK
			if b
				if @selected_boxes.include? b
					@selected_boxes.delete b
				else
					@selected_boxes << b
				end
			end
		elsif b
			@selected_boxes = [b] if not @selected_boxes.include? b
			@caret_box = b
			@caret_x = (@curcontext.view_x+ev.x-b.x*@zoom - 1).to_i / @font_width
			@caret_y = (@curcontext.view_y+ev.y-b.y*@zoom - 1).to_i / @font_height
			update_caret
		else
			@selected_boxes = []
			@caret_box = nil
			@hl_word = nil
		end
		redraw
	end

	def rightclick(ev)
		b = find_box_xy(ev.x, ev.y)
		# TODO
	end

	def doubleclick(ev)
		if b = find_box_xy(ev.x, ev.y)
			if @hl_word and @zoom >= 0.90 and @zoom <= 1.1
				focus_addr(@hl_word)
			else
				focus_addr b[:addresses].first
			end
		elsif @zoom == 1.0
			@curcontext.view_x = @curcontext.box.map { |b| b.x }.min - 10
			@curcontext.view_y = @curcontext.box.map { |b| b.y }.min - 10
			maxx = @curcontext.box.map { |b| b.x + b.w }.max + 10
			maxy = @curcontext.box.map { |b| b.y + b.h }.max + 10
			@zoom = [@width.to_f/(maxx-@curcontext.view_x), @height.to_f/(maxy-@curcontext.view_y)].min
		else
			@curcontext.view_x += (ev.x / @zoom - ev.x)
			@curcontext.view_y += (ev.y / @zoom - ev.y)
			@zoom = 1.0
		end
		redraw
	end

	def paint
		w = @drawarea.window
		gc = Gdk::GC.new(w)
		w_w, w_h = @width, @height

		# TODO do this somewhere else
		#@curcontext.auto_arrange_boxes if not @curcontext.box.empty? and @curcontext.box.all? { |b| b.x == 0 and b.y == 0 }
		
		# TODO MergedBoxes

		# arrows
		# XXX precalc ?
		@curcontext.box.each { |b|
			b.to.each { |tb|
				paint_arrow(w, gc, b, tb)
			}
		}
		
		@shown_boxes = []
		@curcontext.box.each { |b|
			next if b.x >= @curcontext.view_x+w_w/@zoom or b.y >= @curcontext.view_y+w_h/@zoom or b.x+b.w <= @curcontext.view_x or b.y+b.h <= @curcontext.view_y
			@shown_boxes << b
			
			paint_box(w, gc, b)
		}
	end

	def paint_arrow(w, gc, b1, b2)
		x1, y1 = b1.x+b1.w/2-@curcontext.view_x, b1.y+b1.h-@curcontext.view_y
		x2, y2 = b2.x+b2.w/2-@curcontext.view_x, b2.y-1-@curcontext.view_y
		margin = 8
		return if (y1+margin < 0 and y2 < 0) or (y1 > @height/@zoom and y1-margin > @height/@zoom)	# just clip on y
		margin, x1, y1, x2, y2, b1w, b2w = [margin, x1, y1, x2, y2, b1.w, b2.w].map { |v| v*@zoom }
		if b1 == @caret_box or b2 == @caret_box
			gc.set_foreground @color[:arrow_hl]
		else
			gc.set_foreground @color[:arrow]
		end
		if margin > 2
			w.draw_line(gc, x1, y1, x1, y1+margin)
			w.draw_line(gc, x2, y2-margin, x2, y2)
			w.draw_line(gc, x2-margin/2, y2-margin/2, x2, y2)
			w.draw_line(gc, x2+margin/2, y2-margin/2, x2, y2)
			y1 += margin
			y2 -= margin-1
		end
		if y2+margin >= y1-margin-1
			w.draw_line(gc, x1, y1, x2, y2) if x1 != y1 or x2 != y2
		elsif x1-b1w/2-margin >= x2+b2w/2+margin	# z
			w.draw_line(gc, x1, y1, x1-b1w/2-margin, y1)
			w.draw_line(gc, x1-b1w/2-margin, y1, x2+b2w/2+margin, y2)
			w.draw_line(gc, x2+b2w/2+margin, y2, x2, y2)
		elsif x1+b1w/2+margin <= x2-b2w/2-margin	# invert z
			w.draw_line(gc, x1, y1, x1+b1w/2+margin, y1)
			w.draw_line(gc, x1+b1w/2+margin, y1, x2-b2w/2-margin, y2)
			w.draw_line(gc, x2-b2w/2-margin, y2, x2, y2)
		else						# turn around
			x = (x1 > x2 ? [x1-b1w/2-margin, x2-b2w/2-margin].min : [x1+b1w/2+margin, x2+b2w/2+margin].max)
			w.draw_line(gc, x1, y1, x, y1)
			w.draw_line(gc, x, y1, x, y2)
			w.draw_line(gc, x, y2, x2, y2)
		end
	end

	def paint_box(w, gc, b)
		if @selected_boxes.include? b
			gc.set_foreground @color[:hlbox_bg]
		else
			gc.set_foreground @color[:box_bg]
		end
		w.draw_rectangle(gc, true, (b.x-@curcontext.view_x)*@zoom, (b.y-@curcontext.view_y)*@zoom, b.w*@zoom, b.h*@zoom)

		return if @zoom < 0.99 or @zoom > 1.1

		# current text position
		x = (b.x - @curcontext.view_x + 1)*@zoom
		y = (b.y - @curcontext.view_y + 1)*@zoom
		w_w = (b.x - @curcontext.view_x)*@zoom + b.w - @font_width
		w_h = (b.y - @curcontext.view_y)*@zoom + b.h - @font_height

		if @caret_box == b
			gc.set_foreground @color[:cursorline_bg]
			w.draw_rectangle(gc, true, x-1, y+@caret_y*@font_height, b.w*@zoom-2, @font_height)
		end

		# renders a string at current cursor position with a color
		# must not include newline
		render = proc { |str, color|
			# function ends when we write under the bottom of the listing
			next if y >= w_h or x >= w_w
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
		# newline: current line is fully rendered, update line_address/line_text etc
		nl = proc {
			x = (b.x - @curcontext.view_x + 1)*@zoom
			y += @font_height
		}

		b[:addresses].each { |addr|
			curaddr = addr
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
				end
				render[di.instruction.to_s.ljust(24), :instruction]
				render[' ; ' + di.comment.join(' ')[0, 64], :comment] if di.comment
				nl[]
			else
				# TODO real data display (dwords, xrefs, strings..)
				if label = @dasm.prog_binding.index(curaddr) and @dasm.xrefs[curaddr]
					render[Metasm::Expression[curaddr].to_s + '    ', :black]
					render[label + ' ', :label]
				else
					if label
						render[label+':', :label]
						nl[]
					end
					render[Metasm::Expression[curaddr].to_s + '    ', :black]
				end
				s = @dasm.get_section_at(curaddr)
				render['db '+((s and s[0].rawsize > s[0].ptr) ? Metasm::Expression[s[0].read(1)[0]].to_s : '?'), :instruction]
				nl[]
			end
		}

		if b == @caret_box
			gc.set_foreground @color[:caret]
			cx = (b.x - @curcontext.view_x + 1)*@zoom + @caret_x*@font_width
			cy = (b.y - @curcontext.view_y + 1)*@zoom + @caret_y*@font_height
			w.draw_line(gc, cx, cy, cx, cy+@font_height-1)
		end
	end

	#
	# rebuild the code flow graph from @curcontext.roots
	# recalc the boxes w/h
	# TODO should autorearrange the boxes
	#
	def gui_update
		@curcontext.clear

		# graph : block -> following blocks in same function
		block_rel = {}

		todo = @curcontext.root_addrs.dup
		done = [:default, Expression::Unknown]
		while a = todo.shift
			a = @dasm.normalize a
			next if done.include? a
			done << a
			next if not di = @dasm.decoded[a] or not di.kind_of? DecodedInstruction
			block_rel[a] = []
			di.block.each_to_samefunc { |t|
				t = @dasm.normalize t
				next if not @dasm.decoded[t]
				todo << t
				block_rel[a] << t
			}
			block_rel[a].uniq!
		end

		# populate boxes
		addr2box = {}
		todo = @curcontext.root_addrs.dup
		done = []
		while a = todo.shift
			next if done.include? a
			done << a
			if from = block_rel.keys.find_all { |ba| block_rel[ba].include? a } and
					from.length == 1 and block_rel[from.first].length == 1 and
					addr2box[from.first] and @dasm.decoded[from.first].block.list.last.next_addr == a
				box = addr2box[from.first]
			else
				box = @curcontext.new_box a, :addresses => [], :line_text => {}, :line_address => {}
			end
			@dasm.decoded[a].block.list.each { |di|
				box[:addresses] << di.address
				addr2box[di.address] = box
			}
			todo.concat block_rel[a]
		end

		# link boxes
		@curcontext.box.each { |b|
			a = @dasm.decoded[b[:addresses].last].block.address
			next if not block_rel[a]
			block_rel[a].each { |t|
				@curcontext.link_boxes(b.id, t)
			}
		}

		# calc box dimensions
		@curcontext.box.each { |b|
			fullstr = ''
			curaddr = nil
			line = 0
			render = proc { |str| fullstr << str }
			nl = proc {
				b[:line_address][line] = curaddr
				b[:line_text][line] = fullstr
				fullstr = ''
				line += 1
			}
			b[:addresses].each { |addr|
				curaddr = addr
				if di = @dasm.decoded[curaddr] and di.kind_of? Metasm::DecodedInstruction
					if di.block.list.first == di
						b_header = '' ; @dasm.dump_block_header(di.block) { |l| b_header << l ; b_header << ?\n if b_header[-1] != ?\n }
						b_header.each { |l| render[l.chomp] ; nl[] }
					end
					render[di.instruction.to_s.ljust(24)]
					render[' ; ' + di.comment.join(' ')[0, 64]] if di.comment
					nl[]
				end
			}
			b.w = b[:line_text].values.map { |str| str.length }.max * @font_width + 2
			b.h = line * @font_height + 2
		}

		@curcontext.auto_arrange_boxes

		w_x = @curcontext.box.map { |b| b.x + b.w }.max - @curcontext.box.map { |b| b.x }.min + 20
		w_y = @curcontext.box.map { |b| b.y + b.h }.max - @curcontext.box.map { |b| b.y }.min + 20
		@drawarea.set_size_request([400, [w_x, @width].max].min, [400, [w_y, @height].max].min)


		redraw
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
	# TODO arrows => change caret_box
	# TODO non-navigation commands are global, get it out of the widget
	def keypress(ev)
		case ev.keyval
		when GDK_Left
			if @caret_box
				if @caret_x > 0
					@caret_x -= 1
					update_caret
				end
			else
				@curcontext.view_x -= 20/@zoom
				redraw
			end
		when GDK_Up
			if @caret_box
				if @caret_y > 0
					@caret_y -= 1
					update_caret
				end
			else
				@curcontext.view_y -= 20/@zoom
				redraw
			end
		when GDK_Right
			if @caret_box
				if @caret_x <= @caret_box[:line_text].values.map { |s| s.length }.max
					@caret_x += 1
					update_caret
				end
			else
				@curcontext.view_x += 20/@zoom
				redraw
			end
		when GDK_Down
			if @caret_box
				if @caret_y < @caret_box[:line_text].length-1
					@caret_y += 1
					update_caret
				end
			else
				@curcontext.view_y += 20/@zoom
				redraw
			end
		when GDK_Page_Up
			if @caret_box
				@caret_y = 0
				update_caret
			else
				@curcontext.view_y -= @height/4/@zoom
				redraw
			end
		when GDK_Page_Down
			if @caret_box
				@caret_y = @caret_box.line_length-1
				update_caret
			else
				@curcontext.view_y += @height/4/@zoom
				redraw
			end
		when GDK_Home
			if @caret_box
				@caret_x = 0
				update_caret
			else
				@curcontext.view_x = @curcontext.box.map { |b| b.x }.min-10
				@curcontext.view_y = @curcontext.box.map { |b| b.y }.min-10
				redraw
			end
		when GDK_End
			if @caret_box
				@caret_x = @caret_box[:line_text][@caret_y].length
				update_caret
			else
				@curcontext.view_x = [@curcontext.box.map { |b| b.x+b.w }.max-@width/@zoom+10, @curcontext.box.map { |b| b.x }.min-10].max
				@curcontext.view_y = [@curcontext.box.map { |b| b.y+b.h }.max-@height/@zoom+10, @curcontext.box.map { |b| b.y }.min-10].max
				redraw
			end

		when GDK_Return, GDK_KP_Enter
			focus_addr @hl_word if @hl_word
		when GDK_Escape
			if not @view_history.empty?
				addr, x = @view_history.pop
				@view_history.pop if focus_addr addr
				@caret_x = x
				update_caret
			end

		when GDK_Delete
			@selected_boxes.each { |b|
				@curcontext.box.delete b
				b.from.each { |bb| bb.to.delete b }
				b.to.each { |bb| bb.from.delete b }
			}
			redraw

		when GDK_a
			puts 'autoarrange'
			@curcontext.auto_arrange_boxes
			redraw
			puts 'autoarrange done'
		when GDK_u
			puts 'update'
			gui_update
			redraw
			puts 'update done'

		when GDK_c	# disassemble from this point
				# if points to a call, make it return
			return if not addr = @caret_box[:line_address][@caret_y]
			if di = @dasm.decoded[addr] and di.kind_of? DecodedInstruction and di.opcode.props[:saveip] and not @dasm.decoded[addr + di.bin_length]
				di.block.add_to_subfuncret(addr+di.bin_length)
				@dasm.addrs_todo << [addr + di.bin_length, addr, true]
			else
				@dasm.addrs_todo << [addr]
			end
		when GDK_g	# jump to address
			InputBox.new('address to go') { |v| focus_addr v }
		when GDK_h	# parses a C header
			OpenFile.new('open C header') { |f|
				@dasm.parse_c_file(f) rescue MessageBox.new($!)
			}
		when GDK_n	# name/rename a label
			if not @hl_word or not addr = @dasm.prog_binding[@hl_word]
				return if not addr = @caret_box[:line_address][@caret_y]
			end
			if old = @dasm.prog_binding.index(addr)
				InputBox.new("new name for #{old}") { |v| @dasm.rename_label(old, v) ; redraw }
			else
				InputBox.new("label name for #{Expression[addr]}") { |v| @dasm.rename_label(@dasm.label_at(addr, v), v) ; redraw }
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
			return if not addr = @caret_box[:line_address][@caret_y]
			lst = ["list of xrefs to #{Expression[addr]}"]
			@dasm.each_xref(addr) { |xr|
				if @dasm.decoded[xr.origin].kind_of? DecodedInstruction
					org = @dasm.decoded[xr.origin]
				else
					org = Expression[xr.origin]
				end
				lst << "xref #{xr.type}#{xr.len} from #{org}"
			}
			MessageBox.new lst.join("\n ")
		when GDK_i	# misc debug
			begin
				p @curcontext.box.map { |b| b[:line_address].sort.map { |a1, a2| "#{a1} #{Expression[a2]}" } }
				if @caret_box
					puts @caret_box[:line_text].sort.transpose.last
				else
					puts 'nobox'
				end
				p [@caret_x, @caret_y]
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
	
	# find a suitable array of graph roots, walking up from a block (function start/entrypoint)
	def dasm_find_roots(addr)
		todo = [addr]
		done = []
		roots = []
		while a = todo.shift
			a = @dasm.normalize(a)
			next if done.include? a
			next if not b = @dasm.decoded[a] or not b.kind_of? DecodedInstruction or not b = b.block
			done << a
			newf = []
			b.each_from_samefunc(@dasm) { |f| newf << f }
			if newf.empty?
				roots << a
			else
				todo.concat newf
			end
		end

		roots
	end

	# queue redraw of the whole GUI visible area
	def redraw
		return if not @drawarea.window
		@drawarea.window.invalidate Gdk::Rectangle.new(0, 0, 100000, 100000), false
	end

	# change the color association
	# arg is a hash function symbol => color symbol
	# color must be allocated
	# check #initialize/sig('realize') for initial function/color list
	def set_color_association(hash)
		hash.each { |k, v| @color[k] = @color[v] }
		@drawarea.modify_bg Gtk::STATE_NORMAL, @color[:bg]
		gui_update
	end
	
	# change the font of the listing
	# arg is a Gtk Fontdescription string (eg 'courier 10')
	def set_font(descr)
		@layout.font_description = Pango::FontDescription.new(descr)
		@layout.text = 'x'
		@font_width, @font_height = @layout.pixel_size
		redraw
	end

	# focus on addr
	# addr may be a dasm label, dasm address, dasm address in string form (eg "0DEADBEEFh")
	# addr must point to a decodedinstruction
	# if the addr is not found in curcontext, the code flow is walked up until a function
	# start or an entrypoint is found, then the graph is created from there
	# will call gui_update then
	def focus_addr(addr, can_update_context=true)
		return if not addr or addr == ''

		@zoom = 1.0

		# find real address from addr
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

		if not @dasm.decoded[addr].kind_of? DecodedInstruction
			# TODO switch to Listing
			MessageBox.new "Not an instruction"
			return
		end

		# move window / change curcontext
		@view_history << [current_address, @caret_x] if can_update_context
		if b = @curcontext.box.find { |b| b[:line_address].index(addr) }
			@caret_box, @caret_x, @caret_y = b, 0, b[:line_address].index(addr)
			focus_xy(b.x, b.y + @caret_y*@font_height)
			update_caret
		elsif can_update_context
			@curcontext = Graph.new 'testic'
			@curcontext.root_addrs = dasm_find_roots(addr)
			gui_update
			return focus_addr(addr, false)
		else
			MessageBox.new "Bad control graph, cannot find graph root :("
			if @caret_box
				@curcontext = Graph.new 'testic'
				@curcontext.root_addrs = dasm_find_roots(@caret_box[:line_address][0])
				gui_update
				return focus_addr(@caret_box[:line_address][0], false)
			end
		end
		true
	end

	def focus_xy(x, y)
		if @curcontext.view_x*@zoom + @width < x or @curcontext.view_x*@zoom > x
			@curcontext.view_x = (x - @width/5)/@zoom
			redraw
		end
		if @curcontext.view_y*@zoom + @height < y or @curcontext.view_y*@zoom > y
			@curcontext.view_y = (y - @height/5)/@zoom
			redraw
		end
	end

	# hint that the caret moved
	# redraw, change the hilighted word
	def update_caret
		return if not @caret_box or not @caret_x or not l = @caret_box[:line_text][@caret_y]
		word = l[0...@caret_x].to_s[/\w*$/] << l[@caret_x..-1].to_s[/^\w*/]
		word = nil if word == ''
		@hl_word = word
		redraw
	end

	def current_address
		@caret_box[:line_address][@caret_y] if @caret_box
	end
end
end
end
