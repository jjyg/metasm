#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

module ::Metasm
module Gui
class GraphHeapWidget < GraphViewWidget
	attr_accessor :heap, :addr_struct, :snapped
	# addrstruct = 0x234 => AllocCStruct

	def set_color_arrow(b1, b2)
		if b1 == @caret_box or b2 == @caret_box
			draw_color :arrow_hl
		else
			draw_color :arrow_cond
		end
	end

	def keypress(k)
		case k
		when ?u
			@parent_widget.parent_widget.console.commands['refresh'][]
			gui_update
		when ?t
			if b = @caret_box
				as = @addr_struct[b.id]
				st = as.struct
				if m = st.fldoffset.index(b[:line_address][@caret_y].to_i - b.id) and m = st.fldlist[m]
					inputbox("new type for #{m.name}") { |nn|
						as.cp.lexer.feed!(nn)
						raise 'bad type' if not v = C::Variable.parse_type(as.cp, as.cp.toplevel, true)
						v.parse_declarator(as.cp, as.cp.toplevel)
						nt = v.type
						nsz = as.cp.sizeof(nt)
						osz = as.cp.sizeof(m)
						if nsz > osz
							idx = st.members.index(m)
							# eat next members
							while nsz > osz
								break if idx+1 >= st.members.length
								sz = as.cp.sizeof(st.members.delete_at(idx+1))
								osz += sz
							end
						end
						if nsz < osz
							idx = st.members.index(m)
							# fill gap with bytes
							rnd = [*'a'..'z'][rand(26)] # try this hard to avoid m name collisions
							idx += 1
							while nsz < osz
								st.members[idx, 0] = [C::Variable.new("fil#{rnd}#{idx}", C::BaseType.new(:__int8, :unsigned))]
								idx += 1
								nsz += 1
							end
						end
						m.type = nt
						st.update_member_cache(as.cp)
						gui_update
					}
				end
			end
		when ?n
			if b = @caret_box
				as = @addr_struct[b.id]
				st = as.struct
				if @caret_y == 0
					inputbox("new name for #{st.name}") { |nn|
						as.cp.toplevel.struct[nn] = as.cp.toplevel.struct.delete(st.name)
						st.name = nn
						gui_update
					}
				elsif (st.fldoffset or st.update_member_cache(as.cp) or true) and m = st.fldoffset.index(b[:line_address][@caret_y].to_i - b.id) and m = st.fldlist[m]
					inputbox("new name for #{m.name}") { |nn|
						m.name = nn
						st.update_member_cache(as.cp)
						gui_update
					}
				end
			end
		when ?e
			if b = @caret_box
				as = @addr_struct[b.id]
				st = as.struct
				if m = st.findmember_atoffset(as.cp, b[:line_address][@caret_y].to_i - b.id)
					if m.type.kind_of?(C::Array) and m.type.type.kind_of?(C::BaseType) and m.type.type.name == :char
						defval = as[m].to_array.pack('C*').gsub(/\0*$/, '').gsub(/[^\x20-\x7e]/, '.')
						string = true
					else
						defval = as[m]
						string = false
					end
					inputbox("new value for #{m.name}", :text => defval.to_s) { |nn|
						if string
							am = as[m]
							(nn.unpack('C*') + [0]).each_with_index { |b, i| am[i] = b }
						else
							as[m] = Expression.parse_string(nn).reduce
						end
						gui_update
					}
				end
			end
		when ?x
			if b = @caret_box
				list = [['address']]
				@heap.xrchunksfrom[b.id].to_a.each { |a|
					list << [Expression[a]]
				}
				if list.length == 1
					messagebox "no xref to #{Expression[b.id]}"
				else
					listwindow("heap xrefs to #{Expression[b.id]}", list) { |*i| @parent_widget.focus_addr(i[0], nil, true) }
				end
			end
		else return super(k)
		end
		true
	end

	# create the graph objects in ctx
	def build_ctx(ctx)
		# create boxes
		todo = ctx.root_addrs.dup & @addr_struct.keys
		todo << @addr_struct.keys.first if todo.empty?
		done = []
		while a = todo.shift
			next if done.include? a
			done << a
			box = ctx.new_box a, :line_text_col => [], :line_address => []
			todo.concat @heap.xrchunksto[a].to_a & @addr_struct.keys
		end

		# link boxes
		if (@heap.xrchunksto[ctx.box.first.id].to_a & @addr_struct.keys).length == ctx.box.length - 1
			ot = ctx.box[0].id
			ctx.box[1..-1].each { |b|
				ctx.link_boxes(ot, b.id)
			}
		else
		    ctx.box.each { |b|
			@heap.xrchunksto[b.id].to_a.each { |t|
				ctx.link_boxes(b.id, t) if @addr_struct[t]
			}
		    }
		end

		if snapped
			@datadiff = {}
		end

		# calc box dimensions/text
		ctx.box.each { |b|
			colstr = []
			curaddr = b.id
			if snapped
				ghost = snapped[curaddr]
			end
			line = 0
			render = lambda { |str, col| colstr << [str, col] }
			nl = lambda {
				b[:line_address][line] = curaddr
				b[:line_text_col][line] = colstr
				colstr = []
				line += 1
			}
			render_val = lambda { |v|
				if not v
					render['NULL', :text]
				elsif v > 0x100
					render['0x%X' % v, :text]
				elsif v < -0x100
					render['-0x%X' % -v, :text]
				else
					render[v.to_s, :text]
				end
			}
			ast = @addr_struct[curaddr]
			render["struct #{ast.struct.name} *#{'0x%X' % curaddr} = {", :text]
			nl[]
			ast.struct.members.each { |m|
				if m.type.kind_of?(C::Array)
					if m.type.type.kind_of?(C::BaseType) and m.type.type.name == :char
						render["    #{m.type.type.to_s[1...-1]} #{m.name}[#{m.type.length}] = #{ast[m].to_array.pack('C*').gsub(/\0*$/, '').inspect}", :text]
						nl[]
						curaddr += ast.cp.sizeof(m)
					else
						t = m.type.type.to_s[1...-1]
						tsz = ast.cp.sizeof(m.type.type)
						ast[m].to_array.each_with_index { |v, i|
							render["    #{t} #{m.name}[#{i}] = ", :text]
							render_val[v]
							@datadiff[curaddr] = true if ghost and ghost[m][i] != v
							render[';', :text]
							nl[]
							curaddr += tsz
						}
					end
				else
					render["    ", :text]
					render["#{m.type.to_s[1...-1]} ", :text]
					render["#{m.name} = ", :text]
					render_val[ast[m]]
					@datadiff[curaddr] = true if ghost and ghost[m] != ast[m]
					render[';', :text]

					if m.type.kind_of?(C::Pointer) and m.type.type.kind_of?(C::BaseType) and m.type.type.name == :char
						if s = @dasm.decode_strz(ast[m], 32)
							render["    // #{s.inspect}", :comment]
						end
					end
					nl[]
					curaddr += ast.cp.sizeof(m)
				end
			}
			render['};', :text]
			nl[]

			b.w = b[:line_text_col].map { |strc| strc.map { |s, c| s }.join.length }.max.to_i * @font_width + 2
			b.w += 1 if b.w % 2 == 0
			b.h = line * @font_height
		}
	end

	def struct_find_roots(addr)
		todo = [addr]
		done = []
		roots = []
		default_root = nil
		while a = todo.shift
			if done.include?(a) # cycle
				default_root ||= a
				next
			end
			done << a
			newf = @heap.xrchunksfrom[addr].to_a & @addr_struct.keys
			if newf.empty?
				roots << a
			else
				todo.concat newf
			end
		end
		roots << default_root if roots.empty? and default_root

		roots
	end

	# will call gui_update then
	def focus_addr(addr, fu=nil)
		return if @parent_widget and not addr = @parent_widget.normalize(addr)

		# move window / change curcontext
		if b = @curcontext.box.find { |b_| b_[:line_address].index(addr) }
			@caret_box, @caret_x, @caret_y = b, 0, b[:line_address].rindex(addr)
			@curcontext.view_x += (width/2 / @zoom - width/2)
			@curcontext.view_y += (height/2 / @zoom - height/2)
			@zoom = 1.0

			focus_xy(b.x, b.y + @caret_y*@font_height)
			update_caret
		elsif addr_struct and @addr_struct[addr]
			@curcontext = Graph.new 'testic'
			@curcontext.root_addrs = struct_find_roots(addr)
			@want_focus_addr = addr
			gui_update
		elsif @heap.chunks[addr]
			do_focus_addr(addr)
		else
			return
		end
		true
	end

	def do_focus_addr(addr)
		if not st = @heap.chunk_struct[addr]
			st = C::Struct.new
			st.name = "chunk_#{'%x' % addr}"
			st.members = []
			li = 0
			(@heap.chunks[addr] / 4).times { |i|
				n = "u#{i}"
				v = @dasm.decode_dword(addr+4*i)
				if @heap.chunks[v]
					t = C::Pointer.new(C::BaseType.new(:void))
				else
					t = C::BaseType.new(:int)
				end
				st.members << C::Variable.new(n, t)
				li = i
			}
			(@heap.chunks[addr] % 4).times { |i|
				n = "u#{li+i}"
				v = @dasm.decode_byte(addr+4*li+i)
				t = C::BaseType.new(:char)
				st.members << C::Variable.new(n, t)
			}
			@heap.cp.toplevel.struct[st.name] = st
			@heap.chunk_struct[addr] = st
		end

		ed, l = @dasm.get_section_at(addr)
		@addr_struct = { addr => @heap.cp.decode_c_struct(st.name, ed.data, ed.ptr) }
		gui_update
	end

	def snap
		@snapped = {}
		@addr_struct.each { |a, ast|
			@snapped[a] = ast.cp.decode_c_struct(ast.struct, ast.str[ast.stroff, ast.sizeof].to_str)
		}
		@datadiff = {}
		ocb = @parent_widget.bg_color_callback
		@parent_widget.bg_color_callback = lambda { |a|
			if @datadiff[a]
				'f88'
			elsif ocb
				ocb[a]
			end
		}
	end

	def get_cursor_pos
		[super, addr_struct]
	end

	def set_cursor_pos(p)
		s, @addr_struct = p
		super(s)
	end
end
end
end
