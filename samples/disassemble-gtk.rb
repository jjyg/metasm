#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# 
# this script disassembles an executable (elf/pe) with a lovely gtk2 graphic interface
# ruby disassemble-gtk.rb <exe file> [<c header file>] [<entrypoints>]
#

class GraphViewContext
	# one graphic item
	class Box
		attr_accessor :id, :text, :x, :y, :w, :h
		attr_accessor :to, :from # other boxes linked (arrays)
		def initialize(id, text, x=0, y=0)
			@id, @text, @x, @y = id, text, x, y
			@to, @from = [], []
		end
	end

	attr_accessor :id, :view_x, :view_y, :box
	def initialize(gui, id)
		@gui = gui
		@id = id
		clear
	end

	# empty @box, @view_x, @view_y
	def clear
		@box = []
		@view_x = @view_y = 0
	end

	# link the two boxes (by id)
	def link_boxes(id1, id2)
		raise "unknown index #{id1}" if not b1 = @box.find { |b| b.id == id1 }
		raise "unknown index #{id2}" if not b2 = @box.find { |b| b.id == id2 }
		b1.to   |= [b2]
		b2.from |= [b1]
	end

	# creates a new box, ensures id is not already taken
	def new_box(id, text)
		raise "duplicate id #{id}" if @box.find { |b| b.id == id }
		@box << Box.new(id, text)
	end

	# checks if a box is reachable from another following a 'to' chain
	def arrange_can_reach(src, dst, allow=@box)
		src.to.each { |f|
			next if not allow.include? f
			return true if dst == f
			return true if arrange_can_reach(f, dst, allow-[src])
		}
		false
	end

	# define box width&height from their text content
	# place them for kawaii
	def auto_arrange_boxes
		# calc box sizes
		@box.each { |b|
			text_w, text_h = @gui.get_text_wh(b.text)
			b.w = [100, text_w + 2].max
			b.h = text_h + 2
		}

		# organize boxes
		# TODO groups
		rank = {}	# a->b->c + a->c  => rk(a) < rk(b) < rk(c)
		@box.each { |b| rank[b] = 0 if b.from.empty? }
		until (@box - rank.keys).empty?
			nextgen = rank.keys.map { |b| b.to }.flatten
			nextgen -= rank.keys
			nextgen.uniq!
			while b = nextgen.find { |b| nextgen.find { |bb|
				b != bb and arrange_can_reach(bb, b, @box-rank.keys)
			} }
				nextgen.delete b
			end
			nrank = rank.values.max + 1
			nextgen.each { |b| rank[b] = nrank }
		end

		# TODO imbricated groups
		ary = Array.new(rank.values.max+1) { [] }
		rank.each { |b, r| ary[r] << b }
		y = 0
		ary.each { |ar|
			x = -ar.inject(0) { |s, b| s + b.w + 16 } / 2
			x += ar.first.w + 16 if ar.length == 1 and ff = ar.first.from.find { |ff| rank[ff] == rank[ar.first]-1 } and ff.to.find { |tt| rank[tt] > rank[ar.first] }
			ar.each { |b|
				b.x = x
				b.y = y
				x += b.w + 16
			}
			y += ar.map { |b| b.h }.max + 32
		}
		@view_x = ary.first.first.x - 16
		@view_y = -16
	end
end

# GTK part
require 'gtk2'
class GtkGraphView < Gtk::DrawingArea
	attr_accessor :keyboard_callback, :doubleclick_callback, :rightclick_callback
	attr_accessor :context, :curcontext
	attr_accessor :shown_boxes, :selected_boxes, :color, :mousemove_origin	# internal vars
	def initialize
		@context = {}
		@shown_boxes = []
		@selected_boxes = []
		@color = {}
		@color[:bg] = Gdk::Color.new(45000, 45000, 65000)
		@color[:selected_box_bg] = Gdk::Color.new(45000, 45000, 45000)
		@color[:box_bg] = Gdk::Color.new(55000, 55000, 55000)
		@color[:box_fg] = Gdk::Color.new(    0,     0,     0)
		@color[:arrow] = Gdk::Color.new(    0,     0,     0)
		@mousemove_origin = nil
		@text_layout = Pango::Layout.new(Gdk::Pango.context)
		@text_layout.font_description = Pango::FontDescription.new('courier 10')
		super()
		set_size_request 400, 400		# default control size
		set_events Gdk::Event::ALL_EVENTS_MASK	# receive click/keys
		set_can_focus true			# receive keys
		
		# one-time initialization
		signal_connect('realize') {
			# alloc colors
			@color.each_value { |c| window.colormap.alloc_color(c, true, true) }
		}

		# draw
		signal_connect('expose_event') {
			gc = Gdk::GC.new(window)
			w_w, w_h = allocation.width, allocation.height

			# background
			gc.set_foreground color[:bg]
			window.draw_rectangle(gc, true, 0, 0, w_w, w_h)

			# TODO syntax coloration

			# arrows
			# TODO avoid running into/behind boxes (a -> b -> c & a -> c)
			gc.set_foreground color[:arrow]
			@curcontext.box.each { |b|
				b.to.each { |tb|
					srcx, srcy =  b.x+ b.w/2-@curcontext.view_x, b.y+b.h-@curcontext.view_y
					dstx, dsty = tb.x+tb.w/2-@curcontext.view_x, tb.y-1-@curcontext.view_y
					margin = 8
					next if (srcy+margin < 0 and dsty < 0) or (srcy > w_h and dsty-margin > w_h)	# just clip on y
					window.draw_line(gc, srcx, srcy, srcx, srcy+margin)
					window.draw_line(gc, dstx, dsty-margin, dstx, dsty)
					window.draw_line(gc, dstx-margin/2, dsty-margin/2, dstx, dsty)
					window.draw_line(gc, dstx+margin/2, dsty-margin/2, dstx, dsty)
					srcy += margin
					dsty -= margin
					if dsty+margin >= srcy-margin
						window.draw_line(gc, srcx, srcy, dstx, dsty) if srcx != srcy or dstx != dsty
					elsif srcx-b.w/2-margin >= dstx+tb.w/2+margin	# z
						window.draw_line(gc, srcx, srcy, srcx-b.w/2-margin, srcy)
						window.draw_line(gc, srcx-b.w/2-margin, srcy, dstx+tb.w/2+margin, dsty)
						window.draw_line(gc, dstx+tb.w/2+margin, dsty, dstx, dsty)
					elsif srcx+b.w/2+margin <= dstx-tb.w/2-margin	# invert z
						window.draw_line(gc, srcx, srcy, srcx+b.w/2+margin, srcy)
						window.draw_line(gc, srcx+b.w/2+margin, srcy, dstx-tb.w/2-margin, dsty)
						window.draw_line(gc, dstx-tb.w/2-margin, dsty, dstx, dsty)
					else						# turn around
						x = (srcx > dstx ? [srcx-b.w/2-margin, dstx-tb.w/2-margin].min : [srcx+b.w/2+margin, dstx+tb.w/2+margin].max)
						window.draw_line(gc, srcx, srcy, x, srcy)
						window.draw_line(gc, x, srcy, x, dsty)
						window.draw_line(gc, x, dsty, dstx, dsty)
					end
				}
			}

			# restrict click test to shown boxes
			@shown_boxes = []
			@curcontext.box.each { |b|
				next if b.x >= @curcontext.view_x+w_w or b.y >= @curcontext.view_y+w_h or b.x+b.w <= @curcontext.view_x or b.y+b.h <= @curcontext.view_y
				@shown_boxes << b

				gc.set_foreground color[@selected_boxes.include?(b) ? :selected_box_bg : :box_bg]
				window.draw_rectangle(gc, true, b.x-@curcontext.view_x, b.y-@curcontext.view_y, b.w, b.h)
				@text_layout.text = b.text
				gc.set_foreground color[:box_fg]
				window.draw_layout(gc, b.x-@curcontext.view_x+1, b.y-@curcontext.view_y+1, @text_layout)
			}
		}

		# mouse move
		signal_connect('motion_notify_event') { |own, ev|
			if @mousemove_origin
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
		}

		# mouse click
		signal_connect('button_press_event') { |own, ev|
			case ev.event_type
			when Gdk::Event::BUTTON_PRESS
				case ev.button
				when 1
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
					else
						@selected_boxes = []
					end
					redraw
				when 3
					b = find_box_xy(@curcontext.view_x+ev.x, @curcontext.view_y+ev.y)
					rightclick_callback[b] # TODO text offset clicked
					# multiple selection contextual menu ?
				end
			when Gdk::Event::BUTTON2_PRESS
				if ev.button == 1
					if @shown_boxes.empty?
						@curcontext.view_x, @curcontext.view_y = @curcontext.box[0].x-10, @curcontext.box[0].y-10 if @curcontext.box[0]
						redraw
					else
						b = find_box_xy(@curcontext.view_x+ev.x, @curcontext.view_y+ev.y)
						doubleclick_callback[b] # TODO text offset
					end
				end
			end
		}

		# mouse release
		signal_connect('button_release_event') { |own, ev|
			case ev.event_type
			when Gdk::Event::BUTTON_RELEASE
				if ev.button == 1
					@mousemove_origin = nil
					if ev.state & Gdk::Window::CONTROL_MASK != Gdk::Window::CONTROL_MASK
						@selected_boxes = []
					end
				end
			end
		}

		# mouse wheel
		signal_connect('scroll_event') { |own, ev|
			case ev.direction
			when Gdk::EventScroll::Direction::UP
				@curcontext.view_y -= allocation.height/4
				redraw
			when Gdk::EventScroll::Direction::DOWN
				@curcontext.view_y += allocation.height/4
				redraw
			end
		}

		# keyboard
		signal_connect('key_press_event') { |own, ev|
			key = case ev.keyval
			when 65307: :esc
			else ev.keyval
			end
			keyboard_callback[key]
		}
	end

	def find_box_xy(x, y)
		@shown_boxes.to_a.find { |b| b.x <= x and b.x+b.w >= x and b.y <= y and b.y+b.h >= y }
	end


	###################################
	# public standalone GUI interface #
	###################################
	
	# don't return while GUI exists
	# calls repeatedly the block parameter when idle while it returns true
	def main_loop(&b)
		w = Gtk::Window.new
		w.signal_connect('destroy') { Gtk.main_quit }
		w.add self
		w.show_all
		Gtk.idle_add(&b) if b
		Gtk.main
	end

	# end the main_loop
	def quit
		Gtk.main_quit
	end

	# queue redraw of the whole GUI visible area
	def redraw
		window.invalidate Gdk::Rectangle.new(0, 0, 10000, 10000), false
	end

	# retrieve a graph context
	def get_context(id)
		@context[id] ||= GraphViewContext.new(self, id)
	end

	# set the displayed graph
	def set_context(id)
		raise "unknown context #{id}" if not c = @context[id]
		@selected_boxes, @mousemove_origin = [], nil
		@curcontext = c
		redraw
	end

	# returns [width, height] of the rendering of text
	def get_text_wh(text)
		@text_layout.text = text
		@text_layout.pixel_size
	end
end

# metasm part
require 'metasm'

# raise, my minion !
module Metasm
class Disassembler
	# rebuild the code flow graph (function graph + each function block graph), and update the GUI accordingly
	def gui_update
		# build the transition graphs: (arrays of normalized addresses)
		#  function -> subfunctions
		func_rel = {}
		#  block -> following blocks in same function
		block_rel = {}

		todo_f = @entrypoints.dup
		done_f = []
		while f = todo_f.shift
			f = normalize f
			next if done_f.include? f
			done_f << f
			func_rel[f] = []

			todo_b = [f]
			done_b = []
			while b = todo_b.shift
				b = normalize b
				next if done_b.include? b
				done_b << b
				block_rel[b] = []
				next if not di = @decoded[b] or not di.kind_of? DecodedInstruction
				if di.block.to_subfuncret
					di.block.each_to_normal { |t|
						t = normalize t
						todo_f << t
						func_rel[f] << t
					}
					di.block.each_to_subfuncret { |t|
						t = normalize t
						next if not @decoded[t]
						todo_b << t
						block_rel[b] << t
					}
				else
					di.block.each_to_normal { |t|
						t = normalize t
						next if not @decoded[t]
						todo_b << t
						block_rel[b] << t
					}
				end
				di.block.each_to_indirect { |t|
					t = normalize t
					todo_f << t
					func_rel[f] << t
				}
				block_rel[b].uniq!
			end
			func_rel[f].uniq!
		end

		ctx = @gui.get_context(:functions)
		ctx.clear
		func_rel.each { |func, subfunc|
			ctx.new_box func, label_at(func) || "unk #{func}"
		}
		func_rel.each { |func, subfunc|
			subfunc.each { |sf| ctx.link_boxes func, sf }
		}
		ctx.auto_arrange_boxes
		func_rel.each_key { |func|
			ctx = @gui.get_context(func)
			ctx.clear
			todo = [func]
			done = []
			while b = todo.shift
				next  if done.include? b
				done << b
				if di = @decoded[b] and di.kind_of? DecodedInstruction
					src = gui_dump_block(di.block)
				else
					src = b.to_s
				end
				ctx.new_box b, src
				todo.concat block_rel[b]
			end
			done.each { |b| block_rel[b].each { |tb| ctx.link_boxes b, tb } }	# XXX
			ctx.auto_arrange_boxes
		}

		@gui.redraw
	end

	# disassembles the program with an interactive gui (well, almost interactive ;) )
	def gui_disassemble(gui, *entrypoints)
		entrypoints = @program.get_default_entrypoints if entrypoints.empty?
		@gui = gui
		@gui.keyboard_callback = proc { |key|
			case key
			when :esc: @gui.quit
			when ?f: @gui.set_context(:functions)
			else puts "unknown key #{key.inspect}"
			end
		}
		# function => function body only
		@gui.doubleclick_callback = proc { |box|
			if box and @gui.context[box.id]
				@gui.set_context(box.id)
			end
		}

		counter = 0
		@gui.curcontext = @gui.get_context(:functions)
		@gui.main_loop {
			if @addrs_todo.empty?
				if not ep = entrypoints.shift
					post_disassemble
					gui_update
					puts 'disassembly finished'
					false
				else
					@entrypoints ||= []
					@entrypoints << label_at(normalize(ep), 'entrypoint')
					@addrs_todo << ep
					true
				end
			else
				counter += 1
				if counter > 100
					counter = 0
					gui_update
				end
				disassemble_step
				true
			end
		}
	end

	# returns a string to be used as block content in graphic view
	def gui_dump_block(b)
		return 'x'
		src = ''
		dump_block(b) { |l|
			l = l.sub(/\s+;/, ' ;').sub(/;\s+@\S+\s+\S+/, ';').sub(/\s*;\s*$/, '')	# remove instr addr, instr binary encoding & empty asm comment
			src << l << "\n" if not l.strip.empty?
		}
		src
	end
end
end

if __FILE__ == $0
	# roll
	exename = ARGV.shift
	cheader = ARGV.shift
	exe = Metasm::AutoExe.decode_file exename
	d = exe.init_disassembler
	d.parse_c_file cheader if cheader
	ep = ARGV.map { |e| e =~ /^[0-9]/ ? Integer(e) : e }
	d.gui_disassemble(GtkGraphView.new, *ep)
end
