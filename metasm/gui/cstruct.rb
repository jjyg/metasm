#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

module Metasm
module Gui
class CStructWidget < DrawableWidget
	attr_accessor :dasm, :view_x, :view_y

	def initialize_widget(dasm, parent_widget)
		@dasm = dasm
		@parent_widget = parent_widget

		@line_text_col = []	# each line is [[:col, 'text'], [:col, 'text']]
		@line_text = []
		@curaddr = nil
		@curstruct = nil
		@tabwidth = 8
		@view_x = @view_y = 0
		@caret_x = @caret_y = 0
		@cwidth = @cheight = 1	# widget size in chars

		@default_color_association = { :text => :black, :keyword => :blue, :caret => :black,
			  :background => :white, :hl_word => :palered }
	end

	def click(x, y)
		@caret_x = (x-1).to_i / @font_width + @view_x
		@caret_y = y.to_i / @font_height + @view_y
		update_caret
	end

	def rightclick(x, y)
		click(x, y)
		@parent_widget.clone_window(@hl_word) if @hl_word
	end

	def doubleclick(x, y)
		click(x, y)
		@parent_widget.focus_addr(@hl_word)
	end

	def mouse_wheel(dir, x, y)
		case dir
		when :up
			if @caret_y > 0
				@view_y -= 4
				@caret_y -= 4
				@caret_y = 0 if @caret_y < 0
			end
		when :down
			if @caret_y < @line_text.length - 1
				@view_y += 4
				@caret_y += 4
				redraw
			end
		end
		redraw
	end

	def paint
		@cwidth = width/@font_width
		@cheight = height/@font_height

		# adjust viewport to cursor
		sz_x = @line_text.map { |l| l.length }.max.to_i + 1
		sz_y = @line_text.length.to_i + 1
		@view_x = @caret_x - @cwidth + 1 if @caret_x > @view_x + @cwidth - 1
		@view_x = @caret_x if @caret_x < @view_x
		@view_x = sz_x - @cwidth - 1 if @view_x >= sz_x - @cwidth
		@view_x = 0 if @view_x < 0

		@view_y = @caret_y - @cheight + 1 if @caret_y > @view_y + @cheight - 1
		@view_y = @caret_y if @caret_y < @view_y
		@view_y = sz_y - @cheight - 1 if @view_y >= sz_y - @cheight
		@view_y = 0 if @view_y < 0

		# current cursor position
		x = 1
		y = 0

		# renders a string at current cursor position with a color
		# must not include newline
		render = lambda { |str, color|
			# function ends when we write under the bottom of the listing
			if @hl_word
				stmp = str
				pre_x = 0
				while stmp =~ /^(.*?)(\b#{Regexp.escape @hl_word}\b)/
					s1, s2 = $1, $2
					pre_x += s1.length*@font_width
					hl_w = s2.length*@font_width
					draw_rectangle_color(:hl_word, x+pre_x, y, hl_w, @font_height)
					pre_x += hl_w
					stmp = stmp[s1.length+s2.length..-1]
				end
			end
			draw_string_color(color, x, y, str)
			x += str.length * @font_width
		}

		@line_text_col[@view_y, @cheight + 1].each { |l|
			cx = 0
			l.each { |c, t|
				cx += t.length
				if cx-t.length > @view_x + @cwidth + 1
				elsif cx < @view_x
				else
					t = t[(@view_x - cx + t.length)..-1] if cx-t.length < @view_x
					render[t, c]
				end
			}
			x = 1
			y += @font_height
		}

		if focus?
			# draw caret
			cx = (@caret_x-@view_x)*@font_width+1
			cy = (@caret_y-@view_y)*@font_height
			draw_line_color(:caret, cx, cy, cx, cy+@font_height-1)
		end
	
		@oldcaret_x, @oldcaret_y = @caret_x, @caret_y
	end

	def keypress(key)
		case key
		when :left
			if @caret_x >= 1
				@caret_x -= 1
				update_caret
			end
		when :up
			if @caret_y > 0
				@caret_y -= 1
				update_caret
			end
		when :right
			if @caret_x < @line_text[@caret_y].to_s.length
				@caret_x += 1
				update_caret
			end
		when :down
			if @caret_y < @line_text.length
				@caret_y += 1
				update_caret
			end
		when :home
			@caret_x = @line_text[@caret_y].to_s[/^\s*/].length
			update_caret
		when :end
			@caret_x = @line_text[@caret_y].to_s.length
			update_caret
		when ?t	# change current struct type
			f = curfunc.initializer if curfunc.kind_of? C::Variable and curfunc.initializer.kind_of? C::Block
			n = @hl_word
			cp = @dasm.c_parser
			if (f and s = f.symbol[n]) or s = cp.toplevel.symbol[n] or s = cp.toplevel.symbol[@curaddr]
				s_ = s.dup
				s_.initializer = nil if s.kind_of? C::Variable	# for static var, avoid dumping the initializer in the textbox
				s_.attributes &= C::Attributes::DECLSPECS if s_.attributes
				@parent_widget.inputbox("new type for #{s.name}", :text => s_.dump_def(cp.toplevel)[0].join(' ')) { |t|
					if t == ''
						if s.type.kind_of? C::Function and s.initializer and s.initializer.decompdata
							s.initializer.decompdata[:stackoff_type].clear
							s.initializer.decompdata.delete :return_type
						elsif s.kind_of? C::Variable and s.stackoff
							f.decompdata[:stackoff_type].delete s.stackoff
						end
						next
					end
					begin
						cp.lexer.feed(t)
						raise 'bad type' if not v = C::Variable.parse_type(cp, cp.toplevel, true)
						v.parse_declarator(cp, cp.toplevel)
						if s.type.kind_of? C::Function and s.initializer and s.initializer.decompdata
							# updated type of a decompiled func: update stack
							vt = v.type.untypedef
							vt = vt.type.untypedef if vt.kind_of? C::Pointer
							raise 'function forever !' if not vt.kind_of? C::Function
							# TODO _declspec
							ao = 1
							vt.args.to_a.each { |a|
								next if a.has_attribute_var('register')
								ao = (ao + [cp.sizeof(a), cp.typesize[:ptr]].max - 1) / cp.typesize[:ptr] * cp.typesize[:ptr]
								s.initializer.decompdata[:stackoff_name][ao] = a.name if a.name
								s.initializer.decompdata[:stackoff_type][ao] = a.type
								ao += cp.sizeof(a)
							}
							s.initializer.decompdata[:return_type] = vt.type
							s.type = v.type
						else
							f.decompdata[:stackoff_type][s.stackoff] = v.type if f and s.kind_of? C::Variable and s.stackoff
							s.type = v.type
						end
						gui_update
					rescue Object
						@parent_widget.messagebox([$!.message, $!.backtrace].join("\n"), "error")
					end
					cp.readtok until cp.eos?
				}
			end
		when ?T
			list = [['name']]
			list += @dasm.c_parser.toplevel.struct.keys.grep(String).sort.map { |stn| [stn] }
			listwindow('structs', list) { |stn|
				focus_addr(@curaddr, @dasm.c_parser.toplevel.struct[stn[0]] || @curstruct)
			}
		else return false
		end
		true
	end

	def get_cursor_pos
		[@curaddr, @curstruct, @caret_x, @caret_y]
	end

	def set_cursor_pos(p)
		focus_addr p[0], p[1]
		@caret_x, @caret_y = p[2, 2]
		update_caret
	end

	# hint that the caret moved
	# redraws the caret, change the hilighted word, redraw if needed
	def update_caret
		redraw if @caret_x < @view_x or @caret_x >= @view_x + @cwidth or @caret_y < @view_y or @caret_y >= @view_y + @cheight

		invalidate_caret(@oldcaret_x-@view_x, @oldcaret_y-@view_y)
		invalidate_caret(@caret_x-@view_x, @caret_y-@view_y)
		@oldcaret_x, @oldcaret_y = @caret_x, @caret_y

		redraw if update_hl_word(@line_text[@caret_y], @caret_x)
	end

	# focus on addr
	# returns true on success (address exists & decompiled)
	def focus_addr(addr, struct=@curstruct)
		return if not addr = @parent_widget.normalize(addr)
		@curaddr = addr
		@curstruct = struct
		@caret_x = @caret_y = 0
		gui_update
		true
	end

	# returns the address of the data under the cursor
	def current_address
		@curaddr
	end

	def render_struct
		@line_text_col = [[]]
		render = lambda { |str, col| @line_text_col.last << [col, str] }
		nl = lambda { @line_text_col << [] }

		render["#{@curstruct.kind_of?(C::Struct) ? 'struct' : 'union' } #{@curstruct.name || ''} {", :text]
		nl[]
		sect = @dasm.get_section_at(@curaddr)
		sect = sect[0] if sect
		@curstruct.members.each { |m|
			render[' '*@tabwidth + m.type.to_s[1..-2].to_s + ' ' + (m.name || '') + ';', :text]
			raw = sect.read(@dasm.c_parser.sizeof(m))
			render['   // ' + Expression[@dasm.c_parser.decode_value(m.type, raw, :text)]] if sect and m.type.kind_of? C::BaseType
			sect.ptr -= raw.size if not @curstruct.kind_of?(C::Struct)
			nl[]
		}
		render['};', :text]
	end

	def gui_update
		if @curstruct
			render_struct
		else
			@line_text_col = [[[:text, 'no struct selected']]]
		end
		
		@line_text = @line_text_col.map { |l| l.map { |c, s| s }.join }
		update_caret
		redraw
	end
end
end
end
