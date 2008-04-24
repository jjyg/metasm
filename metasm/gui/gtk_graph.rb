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
		attr_accessor :line_address, :line_text
		attr_accessor :addresses	# list of addresses to display
		def initialize(id)
			@id = id
			@x = @y = @w = @h = 0
			@to, @from = [], []
			@line_address = {}
			@line_text = {}
			@addresses = []
		end
		def inspect ; "<box #{@id.inspect} #{@text[0..10].inspect} #@x:#@y #@w:#@h>" end
	end

	# TODO
	class MergedBox
		attr_accessor :id, :text, :x, :y, :w, :h
		attr_accessor :to, :from
	end

	# hierarchical box grouping
	class BoxGroup
		attr_accessor :list	# list of inner box/boxgroup
		def initialize(list=[])
			@list = []
			list.each { |b| self << b }
		end
		def <<(b)
			@list << b if b
			self
		end
		def boxes(g=self)
			return [g] if not g.kind_of? BoxGroup
			g.list.map { |gg| boxes(gg) }.flatten
		end
		def x ; list.map { |b| b.x }.min end
		def y ; list.map { |b| b.y }.min end
		def w ; list.map { |b| b.x+b.w }.max - x end
		def h ; list.map { |b| b.y+b.h }.max - y end
		def x=(nx) dx = nx-x ; list.each { |b| b.x += dx } end
		def y=(ny) dy = ny-y ; list.each { |b| b.y += dy } end
	end
	class VtBoxGroup < BoxGroup
		def <<(b)
			return super if not b.kind_of? VtBoxGroup
			@list.concat b.list
			self
		end
		def inspect ; "<vt #{@list.inspect}>" end
	end
	class HzBoxGroup < BoxGroup
		attr_accessor :direct	# leave passage for a direct arrow from vt_prev to vt_next (eg. if then end)
		def <<(b)
			return super if not b.kind_of? HzBoxGroup
			@direct = true if b.direct
			@list.concat b.list
			self
		end
		def inspect ; "<hz #{'d ' if direct}#{@list.inspect}>" end
	end

	attr_accessor :id, :box, :w, :h, :roots, :view_x, :view_y
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
	def new_box(id)
		raise "duplicate id #{id}" if @box.find { |b| b.id == id }
		b = Box.new(id)
		@box << b
		b
	end

	# checks if a box is reachable from another following a 'to' chain
	def can_reach(src, dst, allow=@box)
		src.to.each { |f|
			next if not allow.include? f
			return true if dst == f
			return true if can_reach(f, dst, allow-[src])
		}
		false
	end

	# define box width&height from their text content
	# place them for kawaii
	def auto_arrange_boxes
#puts Metasm::Expression[@id]
ptt = Time.now
pt = proc { |i| nt = Time.now ; puts "aa #{'%0.3f' % (nt-ptt)} #{i}" if $VERBOSE ; ptt = nt }
		# calc box sizes
		@box.each { |b|
			b.x = b.y = 0
		}
pt['initbox']

		# find graph roots
		roots = [@box.first]
		@box.reverse_each { |b|		# reverse -> in case of an ep loop, prefer @box order
			if not roots.find { |bb| can_reach(bb, b) }
				roots.delete_if { |bb| can_reach(b, bb) }
				roots << b
			end
		}
pt['roots']

		# calc ranks
		rank = {}	# a->b->c + a->c  => rk(a) < rk(b) < rk(c)
		roots.each { |b| rank[b] = 0 }
		until (@box - rank.keys).empty?
			nextgen = rank.keys.map { |b| b.to }.flatten.uniq - rank.keys
			while b = nextgen.find { |b| (nextgen-[b]).find { |bb| can_reach(bb, b, @box-rank.keys) } }
				nextgen.delete b
			end
			nrank = rank.values.max + 1
			nextgen.each { |b| rank[b] = nrank }
		end
pt['rank']

		simplify_split = nil
		simplify_merge = proc { |ary, b|
			# common suffix
			down = nil
			# walk blocks, if find b => update down, remove from block
			# returns true if found b in the middle of a vblock
			walk = proc { |g|
				ret = false
				case g
				when HzBoxGroup
					g.list.each { |gg| ret ||= walk[gg] }
					g.direct = true if ret and g.list.grep(BoxGroup).find { |gg| gg.list.empty? }
					g.list.delete_if { |gg| gg.kind_of? BoxGroup and gg.list.empty? }
				when VtBoxGroup
					if g.list.include? b
						down = VtBoxGroup.new g.list[g.list.index(b)..-1]
						g.list[g.list.index(b)..-1] = []
						ret = true if not g.list.empty?
					end
					g.list.each { |gg| ret = true if walk[gg] and gg != g.list.first }	# XXX g.list.first.list.empty?
					g.list.delete_if { |gg| gg.kind_of? BoxGroup and gg.list.empty? }
				end
				ret
			}
			g = HzBoxGroup.new(ary)
			walk[g]
			VtBoxGroup.new << simplify_split[g] << down
		}

		# take an hbox, find common boxes, simplify_merge groups containing them ( =>  h[v[h[prefix], common suffix], nothing in common])
		simplify_split = proc { |g|
			case g.list.length
			when 0: nil
			when 1: g.direct ? g : g.list.first
			else
				# search common box
				boxes = g.list.inject({}) { |h, gg| h.update gg => g.boxes(gg) }
				# for all couple of groups, find the lowest-ranked common box, then return the lowest-ranked of them
				if b = (0...g.list.length).map { |i| 
					(i+1...g.list.length).map { |ii| boxes[g.list[i]] & boxes[g.list[ii]] }.flatten.uniq.sort_by { |b| rank[b] }.first
				}.compact.sort_by { |b| rank[b] }.first
					v = g.list.find_all { |gg| boxes[gg].include?(b) }
					g.list -= v
					g.list << simplify_merge[v, b]
					simplify_split[g]
				else
					g
				end
			end
		}

		# create a vbox with 2 elems: the root, and an hbox containing all to with higher rank, simplified
		make_group = proc { |root|
			g = HzBoxGroup.new
			root.to.each { |t| g << make_group[t] if rank[t] > rank[root] }
			VtBoxGroup.new << root << simplify_split[g]
		}

		rootbox = HzBoxGroup.new
		roots.each { |r| rootbox << make_group[r] }
pt['makegroups']
		rootbox = simplify_split[rootbox]
pt['simp_split final']

		arrange = proc { |g|
			next if not g.kind_of? BoxGroup
			g.list.each { |gg| arrange[gg] }
			case g
			when VtBoxGroup
				dy = 0
				gw = g.w
				g.list.each { |gg|
					gg.x += (gw-gg.w)/2
					if gg.kind_of? HzBoxGroup
						if gg.direct
							gg.x += gg.w/2+8
						else
							dy += 17
						end
					end
					gg.y += dy
					dy += gg.h+17
				}
			when HzBoxGroup
				dx = 0
				g.list.each { |gg| gg.x += dx ; dx += gg.w + 17 }
			end
		}

		# fails, a box may be now in two non-imbricated groups => bad layout
		arrange[rootbox]
pt['arrange']
		# shrink the graph
0.times {
		@box.sort_by { |b| rank[b] }.each { |b|
			pv = @box.map { |bb| bb.y + bb.h if bb.x+bb.w+16 < b.x or b.x+b.w+16 < bb.x }.compact.delete_if { |pv| pv >= b.y }.sort.last
			b.y = pv+24 if pv and b.y > pv+24
		}
		@box.sort_by { |b| rank[b] }.each { |b|
			pv = @box.map { |bb| bb.x + bb.w if bb.y+bb.h+12 < b.y or b.y+b.h+12 < bb.y }.compact.delete_if { |pv| pv >= b.x }.sort.last
			b.x = pv+24 if pv and b.x > pv+24
		}
}
pt['shrink']

		@view_x = rootbox.x-16	# need window width to center..
		@view_y = rootbox.y-16
	end
end





class GraphViewWidget < Gtk::HBox
	def initialize(dasm, entrypoints=[])
		@dasm = dasm
		@entrypoints = entrypoints
		@view_history = []
		@line_address = {}	# box => {line => addr}
		@line_text = {}
		@hl_word = nil
		@caret_x = @caret_y = @caret_box = nil
		@layout = Pango::Layout.new Gdk::Pango.context
		@color = {}
		@selected_boxes = []
		@shown_boxes = []
		@mousemove_origin = nil
		@curcontext = Graph.new(nil)
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
			case ev.direction
			when Gdk::EventScroll::Direction::UP
				@curcontext.view_y -= allocation.height/4
				redraw
			when Gdk::EventScroll::Direction::DOWN
				@curcontext.view_y += allocation.height/4
				redraw
			end
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
		@shown_boxes.to_a.reverse.find { |b| b.x <= x and b.x+b.w >= x and b.y <= y and b.y+b.h >= y }
	end

	def mousemove(ev)
		dx = ev.x - @mousemove_origin[0]
		dy = ev.y - @mousemove_origin[1]
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
		b = find_box_xy(@curcontext.view_x+ev.x, @curcontext.view_y+ev.y)
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
			@caret_x = (@curcontext.view_x+ev.x-b.x - 1).to_i / @font_width
			@caret_y = (@curcontext.view_y+ev.y-b.y - 1).to_i / @font_height
			update_caret
		else
			@selected_boxes = []
		end
		redraw
	end

	def rightclick(ev)
		b = find_box_xy(@curcontext.view_x+ev.x, @curcontext.view_y+ev.y)
		# TODO
	end

	def doubleclick(ev)
		if @shown_boxes.empty?
			if b = @curcontext.box[0]
				@curcontext.view_x, @curcontext.view_y = b.x-10, b.y-10
				redraw
			end
		else
			focus_addr(@hl_word)
		end
	end

	def paint
		w = @drawarea.window
		gc = Gdk::GC.new(w)
		w_w, w_h = allocation.width, allocation.height

		# TODO do this somewhere else
		#@curcontext.auto_arrange_boxes if not @curcontext.box.empty? and @curcontext.box.all? { |b| b.x == 0 and b.y == 0 }
		
		# TODO MergedBoxes

		# arrows
		# XXX precalc ?
		@curcontext.box.each { |b|
			b.to.each { |tb|
				srcx, srcy =  b.x+ b.w/2-@curcontext.view_x, b.y+b.h-@curcontext.view_y
				dstx, dsty = tb.x+tb.w/2-@curcontext.view_x, tb.y-1-@curcontext.view_y
				margin = 8
				next if (srcy+margin < 0 and dsty < 0) or (srcy > w_h and dsty-margin > w_h)	# just clip on y
				paint_arrow(w, gc, srcx, srcy, dstx, dsty, b, tb)
			}
		}
		
		@shown_boxes = []
		@curcontext.box.each { |b|
			next if b.x >= @curcontext.view_x+w_w or b.y >= @curcontext.view_y+w_h or b.x+b.w <= @curcontext.view_x or b.y+b.h <= @curcontext.view_y
			@shown_boxes << b
			
			paint_box(w, gc, b)
		}
	end

	def paint_arrow(w, gc, x1, y1, x2, y2, b1, b2)
		margin = 8
		if b1 == @caret_box or b2 == @caret_box
			gc.set_foreground @color[:arrow_hl]
		else
			gc.set_foreground @color[:arrow]
		end
		w.draw_line(gc, x1, y1, x1, y1+margin)
		w.draw_line(gc, x2, y2-margin, x2, y2)
		w.draw_line(gc, x2-margin/2, y2-margin/2, x2, y2)
		w.draw_line(gc, x2+margin/2, y2-margin/2, x2, y2)
		y1 += margin
		y2 -= margin
		if y2+margin >= y1-margin
			w.draw_line(gc, x1, y1, x2, y2) if x1 != y1 or x2 != y2
		elsif x1-b1.w/2-margin >= x2+b2.w/2+margin	# z
			w.draw_line(gc, x1, y1, x1-b1.w/2-margin, y1)
			w.draw_line(gc, x1-b1.w/2-margin, y1, x2+b2.w/2+margin, y2)
			w.draw_line(gc, x2+b2.w/2+margin, y2, x2, y2)
		elsif x1+b1.w/2+margin <= x2-b2.w/2-margin	# invert z
			w.draw_line(gc, x1, y1, x1+b1.w/2+margin, y1)
			w.draw_line(gc, x1+b1.w/2+margin, y1, x2-b2.w/2-margin, y2)
			w.draw_line(gc, x2-b2.w/2-margin, y2, x2, y2)
		else						# turn around
			x = (x1 > x2 ? [x1-b1.w/2-margin, x2-b2.w/2-margin].min : [x1+b1.w/2+margin, x2+b2.w/2+margin].max)
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
		w.draw_rectangle(gc, true, b.x-@curcontext.view_x, b.y-@curcontext.view_y, b.w, b.h)

		# current text position
		x = b.x - @curcontext.view_x + 1
		y = b.y - @curcontext.view_y + 1
		w_w = b.x + b.w - @curcontext.view_x - @font_width
		w_h = b.y + b.h - @curcontext.view_y - @font_height

		if @caretbox == b
			gc.set_foreground @color[:cursorline_bg]
			w.draw_rectangle(gc, true, x, y+@caret_y*@fontheight, b.w-2, @fontheight)
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
		# newline: current line is fully rendered, update @line_address/@line_text etc
		nl = proc {
			x = b.x - @curcontext.view_x + 1
			y += @font_height
		}

		b.addresses.each { |addr|
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
			cx = b.x - @curcontext.view_x + @caret_x*@font_width + 1
			cy = b.y - @curcontext.view_y + @caret_y*@font_height
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

		todo = @curcontext.roots.dup
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
		todo = @curcontext.roots.dup
		done = []
		while a = todo.shift
			next if done.include? a
			done << a
			if from = block_rel.keys.find_all { |ba| block_rel[ba].include? a } and
					from.length == 1 and block_rel[from.first].length == 1 and
					addr2box[from.first] and @dasm.decoded[from.first].block.list.last.next_addr == a
				box = addr2box[from.first]
			else
				box = @curcontext.new_box(a)
			end
			@dasm.decoded[a].block.list.each { |di|
				box.addresses << di.address
				addr2box[di.address] = box
			}
			todo.concat block_rel[a]
		end

		# link boxes
		@curcontext.box.each { |b|
			a = @dasm.decoded[b.addresses.last].block.address
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
				b.line_address[line] = curaddr
				b.line_text[line] = fullstr
				fullstr = ''
				line += 1
			}
			b.addresses.each { |addr|
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
			b.w = b.line_text.values.map { |str| str.length }.max * @font_width + 2
			b.h = b.line_text.length * @font_height + 2
		}

		if @curcontext.box.length < 15
			@curcontext.auto_arrange_boxes
			@curcontext.view_x = @curcontext.box.map { |b| b.x }.min.to_i - 10
		end

		w_x = @curcontext.box.map { |b| b.x + b.w }.max - @curcontext.box.map { |b| b.x }.min + 20
		w_y = @curcontext.box.map { |b| b.y + b.h }.max - @curcontext.box.map { |b| b.y }.min + 20
		@drawarea.set_size_request([w_x, @width].max, [w_y, @height].max)


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
			if @caret_x > 0
				@caret_x -= 1
				update_caret
			end
		when GDK_Up
			if @caret_y > 0
				@caret_y -= 1
				update_caret
			end
		when GDK_Right
			if @caret_x <= @caret_box.line_text.values.map { |s| s.length }.max
				@caret_x += 1
				update_caret
			end
		when GDK_Down
			if @caret_y < @caret_box.line_text.length-1
				@caret_y += 1
				update_caret
			end
		when GDK_Page_Up
			@caret_y = 0
			update_caret
		when GDK_Page_Down
			@caret_y = @caret_box.line_length-1
			update_caret
		when GDK_Home
			@caret_x = 0
			update_caret
		when GDK_End
			@caret_x = @caret_box.line_text[@caret_y].length
			update_caret

		when GDK_Return, GDK_KP_Enter
			focus_addr @hl_word
		when GDK_Escape
			if not @view_history.empty?
				addr, x = @view_history.pop
				@view_history.pop if focus_addr addr
				@caret_x = x
				update_caret
			end

		when GDK_a
			puts 'autoarrange'
			@curcontext.auto_arrange_boxes
			redraw
			puts 'autoarrange done'

		when GDK_c	# disassemble from this point
				# if points to a call, make it return
			#@entrypoints << @line_address[@caret_y]
			return if not addr = @caret_box.line_address[@caret_y]
			if di = @dasm.decoded[addr] and di.kind_of? DecodedInstruction and di.opcode.props[:saveip] and not @dasm.decoded[addr + di.bin_length]
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
				return if not addr = @caret_box.line_address[@caret_y]
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
			return if not addr = @caret_box.line_address[@caret_y]
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
				p @curcontext.box.map { |b| b.line_address.sort.map { |a1, a2| "#{a1} #{Expression[a2]}" } }
				if @caret_box
					puts @caret_box.line_text.sort.transpose.last
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
#puts "focus #{Expression[addr]}"
#puts "ctx #{@curcontext.box.map { |b| b.line_address.sort.map { |a1, a2| "#{Expression[a1]} => #{Expression[a2]}" }.join(', ') } }"
		if b = @curcontext.box.find { |b| b.line_address.index(addr) }
			@caret_box, @caret_x, @caret_y = b, 0, b.line_address.index(addr)
			focus_xy(b.x, b.y + @caret_y*@font_height)
			update_caret
		elsif can_update_context
			@curcontext = Graph.new 'testic'
			@curcontext.roots = dasm_find_roots(addr)
			gui_update
			return focus_addr(addr, false)
		else
			MessageBox.new "Bad control graph, cannot find graph root :("
			if @caret_box
				@curcontext = Graph.new 'testic'
				@curcontext.roots = dasm_find_roots(@caret_box.line_address[0])
				gui_update
				return focus_addr(@caret_box.line_address[0], false)
			end
		end
		true
	end

	def focus_xy(x, y)
		if @curcontext.view_x + @width < x or @curcontext.view_x > x
			@curcontext.view_x = x - @width/2
			redraw
		end
		if @curcontext.view_y + @height < y or @curcontext.view_y > y
			@curcontext.view_y = y - @height/2
			redraw
		end
	end

	# hint that the caret moved
	# redraw, change the hilighted word
	def update_caret
		return if not @caret_box
		l = @caret_box.line_text[@caret_y]
		word = l[0...@caret_x].to_s[/\w*$/] << l[@caret_x..-1].to_s[/^\w*/]
		word = nil if word == ''
		@hl_word = word
		redraw
	end

	def current_address
		@caret_box.line_address[@caret_y] if @caret_box
	end
end
end
end
