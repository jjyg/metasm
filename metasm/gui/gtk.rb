#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'gtk2'

module Metasm
module GtkGui
class DisasmWidget < Gtk::VBox
	attr_accessor :dasm, :entrypoints, :views, :gui_update_counter_max, :notebook
	# hash key_val => lambda { |keyb_ev| true if handled }
	attr_accessor :keyboard_callback
	attr_accessor :clones, :gtk_idle_handle
	attr_accessor :pos_history, :pos_history_redo

	def initialize(dasm, ep=[])
		super()

		@dasm = dasm
		@entrypoints = ep
		@pos_history = []
		@pos_history_redo = []
		@keyboard_callback = {}
		@clones = [self]

		@notebook = Gtk::Notebook.new
		@notebook.show_border = false
		@notebook.show_tabs = false

		@views = []
		@view_index = {}
		addview = lambda { |widget, name|
			@view_index[name] = @views.length
			@views << widget.new(@dasm, self)
			@notebook.append_page(@views.last, Gtk::Label.new(name.to_s))
		}

		addview[AsmListingWidget, :listing]
		addview[GraphViewWidget, :graph]
		addview[CdecompListingWidget, :decompile]
		addview[AsmOpcodeWidget, :opcodes]
		addview[HexWidget, :hex]
		addview[CoverageWidget, :coverage]

		@notebook.focus_child = curview

		pack_start @notebook
	end

	def start_disassembling
		@gui_update_counter_max = 100
		gui_update_counter = 0
		dasm_working = false
		@gtk_idle_handle = Gtk.idle_add {
			# metasm disassembler loop
			# update gui once in a while
			dasm_working = true if not @entrypoints.empty? or not @dasm.addrs_todo.empty?
			if dasm_working
				begin
					if not @dasm.disassemble_mainiter(@entrypoints)
						dasm_working = false
						gui_update_counter = @gui_update_counter_max
					end
				rescue Object
					messagebox [$!, $!.backtrace].join("\n")
				end
				gui_update_counter += 1
				if gui_update_counter > @gui_update_counter_max
					gui_update_counter = 0
					gui_update
				end
			end
			true
		}

		@dasm.callback_prebacktrace ||= lambda { Gtk.main_iteration_do(false) }
	end

	def terminate
		@clones.delete self
		if @clones.empty? and @gtk_idle_handle
			Gtk.idle_remove @gtk_idle_handle
			@gtk_idle_handle = nil
		end
	end

	def widget(idx)
		@views[@view_index[idx] || idx]
	end

	def curview
		@views[@notebook.page]
	end

	# returns the address of the item under the cursor in current view
	def curaddr
		curview.current_address
	end

	# returns the object under the cursor in current view (@dasm.decoded[curaddr])
	def curobj
		@dasm.decoded[curaddr]
	end

	# returns the address of the label under the cursor or the address of the line of the cursor
	def pointed_addr
		@dasm.prog_binding[curview.hl_word] || curview.current_address
	end


	def normalize(addr)
		case addr
		when ::String
			if @dasm.prog_binding[addr]
				addr = @dasm.prog_binding[addr]
			elsif (?0..?9).include? addr[0] or (?a..?f).include? addr.downcase[0]
				case addr
				when /^0x/i
				when /h$/i; addr = '0x' + addr[0...-1]
				when /[a-f]/i; addr = '0x' + addr
				when /^[0-9]+$/
					addr = '0x' + addr if not @dasm.get_section_at(addr.to_i) and
								  @dasm.get_section_at(addr.to_i(16))
				end
				begin
					addr = Integer(addr)
				rescue ::ArgumentError
					return
				end
			else
				return
			end
		end
		addr
	end

	def focus_addr(addr, page=nil, quiet=false)
		page ||= @notebook.page
		page = 0 if page == -1
		page = @view_index[page] || page
		return if not addr
		return if page == @notebook.page and addr == curview.current_address
		oldpos = [@notebook.page, curview.get_cursor_pos]
		@notebook.page = page
		if curview.focus_addr(addr) or [oldpos[0], *0...@views.length].find { |v|
			o_p = @views[v].get_cursor_pos
			if @views[v].focus_addr(addr)
				@notebook.page = v
				true
			else
				@views[v].set_cursor_pos o_p
				false
			end
		}
			@pos_history << oldpos unless oldpos[0] == -1	# ignore start focus_addr
			@pos_history_redo.clear
			true
		else
			messagebox "Invalid address #{addr}" if not quiet
			@notebook.page = oldpos[0]
			curview.set_cursor_pos oldpos[1]
			false
		end
	end

	def focus_addr_back(val = @pos_history.pop)
		return if not val
		@pos_history_redo << [@notebook.page, curview.get_cursor_pos]
		@notebook.page = val[0]
		curview.set_cursor_pos val[1]
		true
	end

	def focus_addr_redo
		# undo focus_addr_back
		if val = @pos_history_redo.pop
			@pos_history << [@notebook.page, curview.get_cursor_pos]
			@notebook.page = val[0]
			curview.set_cursor_pos val[1]
		end
	end

	def gui_update
		@clones.each { |c| c.do_gui_update }
	end

	def do_gui_update
		@views.each { |v| v.gui_update }
	end

	def redraw
		curview.redraw
	end

	def keep_focus_while
		curaddr = curaddr
		yield
		focus_addr curaddr if curaddr
	end
	
	# add/change a comment @addr
	def add_comment(addr)
		cmt = @dasm.comment[addr].to_a.join(' ')
		if @dasm.decoded[addr].kind_of? DecodedInstruction
			cmt += @dasm.decoded[addr].comment.to_a.join(' ')
		end
		inputbox("new comment for #{Expression[addr]}", :text => cmt) { |c|
			c = c.split("\n")
			c = nil if c == []
			if @dasm.decoded[addr].kind_of? DecodedInstruction
				@dasm.decoded[addr].comment = c
			else
				@dasm.comment[addr] = c
			end
			gui_update
		}
	end

	# disassemble from this point
	# if points to a call, make it return
	def disassemble(addr)
		if di = @dasm.decoded[addr] and di.kind_of? DecodedInstruction and di.opcode.props[:saveip]
			di.block.each_to_normal { |t|
				t = @dasm.normalize t
				next if not @dasm.decoded[t]
				@dasm.function[t] ||= @dasm.function[:default] ? @dasm.function[:default].dup : DecodedFunction.new
			}
			di.block.add_to_subfuncret(di.next_addr)
			@dasm.addrs_todo << [di.next_addr, addr, true]
		elsif addr
			@dasm.addrs_todo << [addr]
		end
	end

	# disassemble fast from this point (don't dasm subfunctions, don't backtrace)
	def disassemble_fast(addr)
		@dasm.disassemble_fast(addr)
		gui_update
	end

	# disassemble fast & deep from this point (don't backtrace, but still dasm subfuncs)
	def disassemble_fast_deep(addr)
		@dasm.disassemble_fast_deep(addr)
		gui_update
	end

	# (re)decompile
	def decompile(addr)
		if @dasm.c_parser and var = @dasm.c_parser.toplevel.symbol[addr] and (var.type.kind_of? C::Function or @dasm.decoded[@dasm.normalize(addr)].kind_of? DecodedInstruction)
			@dasm.c_parser.toplevel.statements.delete_if { |st| st.kind_of? C::Declaration and st.var == var }
			@dasm.c_parser.toplevel.symbol.delete addr
			widget(:decompile).curaddr = nil
		end
		focus_addr(addr, :decompile)
	end

	def toggle_data(addr)
		return if @dasm.decoded[addr] or not @dasm.get_section_at(addr)
		@dasm.add_xref(addr, Xref.new(nil, nil, 1)) if not @dasm.xrefs[addr]
		@dasm.each_xref(addr) { |x|
			x.len = {1 => 2, 2 => 4, 4 => 8, 8 => 1}[x.len]
			break
		}
		gui_update
	end

	def list_functions
		list = [['name', 'addr']]
		@dasm.function.keys.each { |f|
			addr = @dasm.normalize(f)
			next if not @dasm.decoded[addr]
			list << [@dasm.get_label_at(addr), Expression[addr]]
		}
		title = "list of functions"
		listwindow(title, list) { |i| focus_addr i[1] }
	end

	def list_labels
		list = [['name', 'addr']]
		@dasm.prog_binding.each { |k, v|
			list << [k, Expression[@dasm.normalize(v)]]
		}
		listwindow("list of labels", list) { |i| focus_addr i[1] }
	end

	def list_sections
		list = [['addr', 'length', 'name', 'info']]
		@dasm.section_info.each { |n,a,l,i|
			list << [Expression[a], Expression[l], n, i]
		}
		listwindow("list of sections", list) { |i| focus_addr i[0] if i[0] != '0' or @dasm.get_section_at(0) }
	end

	def list_xrefs(addr)
		list = [['address', 'type', 'instr']]
		@dasm.each_xref(addr) { |xr|
			list << [Expression[xr.origin], "#{xr.type}#{xr.len}"]
			if di = @dasm.decoded[xr.origin] and di.kind_of? DecodedInstruction
				list.last << di.instruction
			end
		}
		if list.length == 1
			messagebox "no xref to #{Expression[addr]}" if addr
		else
			listwindow("list of xrefs to #{Expression[addr]}", list) { |i| focus_addr(i[0], nil, true) }
		end
	end

	# jump to address
	def prompt_goto
		inputbox('address to go', :text => Expression[curaddr]) { |v|
			if not focus_addr(v, nil, true)
				labels = @dasm.prog_binding.map { |k, vv|
 					[k, Expression[@dasm.normalize(vv)]] if k.downcase.include? v.downcase
				}.compact
				case labels.length
				when 0; focus_addr(v)
				when 1; focus_addr(labels[0][0])
				else
					labels.unshift ['name', 'addr']
					listwindow("list of labels", labels) { |i| focus_addr i[1] }
				end
			end
		}
	end

	def prompt_parse_c_file
		# parses a C header
		openfile('open C header') { |f|
			@dasm.parse_c_file(f) rescue messagebox("#{$!}\n#{$!.backtrace}")
		}
	end

	# run arbitrary ruby
	def prompt_run_ruby
		inputbox('ruby code to eval()') { |c|
			begin
				ret = eval c
				messagebox ret.inspect[0, 512], 'eval'
			rescue Object
				messagebox "#$! #{$!.message}\n#{$!.backtrace.join("\n")}", 'eval error'
			end
		}
	end

	# prompts for a new name for addr
	def rename_label(addr)
		old = addr
		if @dasm.prog_binding[old] or old = @dasm.get_label_at(addr)
			inputbox("new name for #{old}", :text => old) { |v| @dasm.rename_label(old, v) ; gui_update }
		else
			inputbox("label name for #{Expression[addr]}", :text => Expression[addr]) { |v|
				@dasm.set_label_at(addr, v)
				if di = @dasm.decoded[addr]
					@dasm.split_block(di.block, di.address)
				end
				gui_update
			}
		end
	end

	# pause/play disassembler
	# returns true if playing
	# this empties @dasm.addrs_todo, the dasm may still continue to work if this msg is
	#  handled during an instr decoding/backtrace (the backtrace may generate new addrs_todo)
	# addresses in addrs_todo pointing to existing decoded instructions are left to create a prettier graph
	def playpause_dasm
		@dasm_pause ||= []
		if @dasm_pause.empty? and @dasm.addrs_todo.empty?
			true
		elsif @dasm_pause.empty?
			@dasm_pause = @dasm.addrs_todo.dup
			@dasm.addrs_todo.clear
			@dasm.addrs_todo.concat @dasm_pause.find_all { |a, *b| @dasm.decoded[@dasm.normalize(a)] }
			@dasm_pause -= @dasm.addrs_todo
			puts "dasm paused (#{@dasm_pause.length})"
		else
			@dasm.addrs_todo.concat @dasm_pause
			@dasm_pause.clear
			puts "dasm restarted (#{@dasm.addrs_todo.length})"
			true
		end
	end

	def toggle_expr_char(o)
		@dasm.toggle_expr_char(o)
		gui_update
	end

	def toggle_view(idx)
		idx = @view_index[idx] || idx
		default = (idx == 0 ? 1 : 0)
		focus_addr(curview.current_address, ((@notebook.page == idx) ? default : idx))
	end

	# undefines the whole function body
	def undefine_function(addr, incl_subfuncs = false)
		list = []
		@dasm.each_function_block(addr, incl_subfuncs) { |b| list << b }
		list.each { |b| @dasm.undefine_from(b) }
		gui_update
	end

	include Gdk::Keyval
	def keypress(ev)
		return true if @keyboard_callback[ev.keyval] and @keyboard_callback[ev.keyval].call(ev)
		case ev.state & Gdk::Window::CONTROL_MASK
		when Gdk::Window::CONTROL_MASK
			case ev.keyval
			when GDK_Return, GDK_KP_Enter; focus_addr_redo
			when GDK_r; prompt_run_ruby
			when GDK_C; disassemble_fast_deep(curview.current_address)
			else return false
			end
		when 0
			case ev.keyval
			when GDK_Return, GDK_KP_Enter; focus_addr curview.hl_word
			when GDK_Escape; focus_addr_back
			when GDK_slash; inputbox('search word') { |w|
				next unless curview.respond_to? :hl_word
				curview.hl_word = w 
				curview.redraw
			} if curview.respond_to? :hl_word
			when GDK_c; disassemble(curview.current_address)
			when GDK_C; disassemble_fast(curview.current_address)
			when GDK_d; toggle_data(curview.current_address)
			when GDK_f; list_functions
			when GDK_g; prompt_goto
			when GDK_l; list_labels
			when GDK_n; rename_label(pointed_addr)
			when GDK_p; playpause_dasm
			when GDK_r; toggle_expr_char(curobj)
			when GDK_v; $VERBOSE = ! $VERBOSE ; puts "#{'not ' if not $VERBOSE}verbose"	# toggle verbose flag
			when GDK_x; list_xrefs(pointed_addr)
			when GDK_semicolon; add_comment(curview.current_address)

			when GDK_space; toggle_view(:graph)
			when GDK_Tab;   toggle_view(:decompile)

			when 0x20..0x7e; return false	# quiet
			when GDK_Shift_L, GDK_Shift_R, GDK_Control_L, GDK_Control_R,
				GDK_Alt_L, GDK_Alt_R, GDK_Meta_L, GDK_Meta_R,
				GDK_Super_L, GDK_Super_R, GDK_Menu
				return false	# quiet
			else
				c = Gdk::Keyval.constants.find { |c_| Gdk::Keyval.const_get(c_) == ev.keyval }
				p [:unknown_keypress, ev.keyval, c, ev.state] if $VERBOSE	# dev helper
				return false
			end
		end		# ctrl/alt
		true
	rescue Object
		messagebox [$!.message, $!.backtrace].join("\n"), $!.class.name
	end

	# creates a new dasm window with the same disassembler object, focus it on addr#win
	def clone_window(*focus)
		popup = MainWindow.new
		popup.display(@dasm, @entrypoints, :dont_dasm => true)
		w = popup.dasm_widget
		w.clones = @clones.concat w.clones
		w.gtk_idle_handle = @gtk_idle_handle
		w.focus_addr(*focus)
		popup
	end

	def messagebox(*a)
		MessageBox.new(toplevel, *a)
	end

	def inputbox(*a, &b)
		InputBox.new(toplevel, *a, &b)
	end

	def openfile(*a, &b)
		OpenFile.new(toplevel, *a, &b)
	end

	def listwindow(*a, &b)
		ListWindow.new(toplevel, *a, &b)
	end
end

module GtkProtect
	@@lasterror = Time.now
	def protect
		yield
	rescue Object
		puts $!.message, $!.backtrace	# also dump on stdout, for c/c
		delay = Time.now-@@lasterror
		sleep 1-delay if delay < 1	# msgbox flood protection
		@@lasterror = Time.now
		MessageBox.new(self, [$!.message, $!.backtrace].join("\n"), $!.class.name)
	end
end

class MessageBox < Gtk::MessageDialog
	# shows a message box (non-modal)
	def initialize(owner, str, opts={})
		owner = nil if owner and owner.destroyed?
		owner ||= Gtk::Window.toplevels.first
		opts = {:title => opts} if opts.kind_of? String
		super(owner, Gtk::Dialog::DESTROY_WITH_PARENT, INFO, BUTTONS_CLOSE, str)
		self.title = opts[:title] if opts[:title]
		signal_connect('response') { destroy }
		show_all
		present		# bring the window to the foreground & set focus
	end
end

class InputBox < Gtk::Dialog
	include GtkProtect

	# shows a simplitic input box (eg window with a 1-line textbox + OK button), yields the text
	# TODO history, dropdown, autocomplete, contexts, 3D stereo surround, etc
	def initialize(owner, str, opts={})
		owner ||= Gtk::Window.toplevels.first
		super(nil, owner, Gtk::Dialog::DESTROY_WITH_PARENT,
			[Gtk::Stock::OK, Gtk::Dialog::RESPONSE_ACCEPT], [Gtk::Stock::CANCEL, Gtk::Dialog::RESPONSE_REJECT])
		self.title = opts[:title] if opts[:title]

		label = Gtk::Label.new(str)
		text  = Gtk::TextView.new
		if opts[:text]
			text.buffer.text = opts[:text].to_s
			text.buffer.move_mark('selection_bound', text.buffer.start_iter)
			text.buffer.move_mark('insert', text.buffer.end_iter)
		end

		text.signal_connect('key_press_event') { |w, ev|
			case ev.keyval
			when Gdk::Keyval::GDK_Escape; response(RESPONSE_REJECT) ; true
			when Gdk::Keyval::GDK_Return, Gdk::Keyval::GDK_KP_Enter; response(RESPONSE_ACCEPT) ; true
			end
		}

		signal_connect('response') { |win, id|
			if id == RESPONSE_ACCEPT
				resp = text.buffer.text
				destroy
				protect { yield resp }
			else
				destroy
			end
			true
		}

		vbox.pack_start label, false, false, 8
		vbox.pack_start text, false, false, 8

		show_all
		present
	end
end

class OpenFile < Gtk::FileChooserDialog
	include GtkProtect

	@@currentfolder = nil
	# shows an asynchronous FileChooser window, yields the chosen filename
	# TODO save last path
	def initialize(owner, title, opts={})
		owner ||= Gtk::Window.toplevels.first
		super(title, owner, Gtk::FileChooser::ACTION_OPEN, nil,
		[Gtk::Stock::CANCEL, Gtk::Dialog::RESPONSE_CANCEL], [Gtk::Stock::OPEN, Gtk::Dialog::RESPONSE_ACCEPT])
		f = opts[:path] || @@currentfolder
		self.current_folder = f if f
		signal_connect('response') { |win, id|
			if id == Gtk::Dialog::RESPONSE_ACCEPT
				file = filename
				@@currentfolder = File.dirname(file)
			end
			destroy
			protect { yield file } if file
			true
		}

		show_all
		present
	end
end

class SaveFile < Gtk::FileChooserDialog
	include GtkProtect

	@@currentfolder = nil

	# shows an asynchronous FileChooser window, yields the chosen filename
	# TODO save last path
	def initialize(owner, title, opts={})
		owner ||= Gtk::Window.toplevels.first
		super(title, owner, Gtk::FileChooser::ACTION_SAVE, nil,
		[Gtk::Stock::CANCEL, Gtk::Dialog::RESPONSE_CANCEL], [Gtk::Stock::SAVE, Gtk::Dialog::RESPONSE_ACCEPT])
		f = opts[:path] || @@currentfolder
		self.current_folder = f if f
		signal_connect('response') { |win, id|
			if id == Gtk::Dialog::RESPONSE_ACCEPT
				file = filename
				@@currentfolder = File.dirname(file)
			end
			destroy
			protect { yield file } if file
			true
		}

		show_all
		present
	end
end

class ListWindow < Gtk::Dialog
	include GtkProtect

	# shows a window with a list of items
	# the list is an array of arrays, displayed as String
	# the first array is the column names
	# each item double-clicked yields the block with the selected iterator
	def initialize(owner, title, list)
		owner ||= Gtk::Window.toplevels.first
		super(title, owner, Gtk::Dialog::DESTROY_WITH_PARENT)

		cols = list.shift

		treeview = Gtk::TreeView.new
		treeview.model = Gtk::ListStore.new(*[String]*cols.length)
		treeview.selection.mode = Gtk::SELECTION_NONE

		cols.each_with_index { |col, i|
			crt = Gtk::CellRendererText.new
			tvc = Gtk::TreeViewColumn.new(col, crt)
			tvc.sort_column_id = i
			tvc.set_cell_data_func(crt) { |_tvc, _crt, model, iter| _crt.text = iter[i] }
			treeview.append_column tvc
		}

		list.each { |e|
			iter = treeview.model.append
			e.each_with_index { |v, i| iter[i] = v.to_s }
		}

		treeview.model.set_sort_column_id(0)

		treeview.signal_connect('cursor_changed') { |x|
			if iter = treeview.selection.selected
				protect { yield iter }
			end
		}

		remove vbox
		add Gtk::ScrolledWindow.new.add(treeview)
		toplevel.set_default_size cols.length*120, 400

		show_all
		present

		# so that the 1st line is not selected by default
		treeview.selection.mode = Gtk::SELECTION_SINGLE
	end
end

class MainWindow < Gtk::Window
	include GtkProtect

	attr_accessor :dasm_widget, :menu
	def initialize(title = 'metasm disassembler')
		super()

		(@@mainwindow_list ||= []) << self
		signal_connect('destroy') {
			@dasm_widget.terminate if @dasm_widget
			@@mainwindow_list.delete self
			Gtk.main_quit if @@mainwindow_list.empty?
		}

		self.title = title
		@dasm_widget = nil
		build_menu
		@vbox = Gtk::VBox.new
		add @vbox
		@vbox.add @menu, 'expand' => false
		s = Gdk::Screen.default
		set_default_size s.width*3/4, s.height*3/4
	end

	# sets up a DisasmWidget as main widget of the window, replaces the current if it exists
	# returns the widget
	def display(dasm, ep=[], opts={})
		if @dasm_widget
			@dasm_widget.terminate
			@vbox.remove @dasm_widget
		end
		@dasm_widget = DisasmWidget.new(dasm, ep)
		@vbox.add @dasm_widget
		@dasm_widget.start_disassembling unless opts[:dont_dasm]
		show_all
		@dasm_widget
	end

	# returns the specified widget from the @dasm_widget (idx in :hex, :listing, :graph etc)
	def widget(idx=nil)
		idx && @dasm_widget ? @dasm_widget.widget(idx) : @dasm_widget
	end

	def loadfile(path)
		exe = Metasm::AutoExe.orshellcode(Metasm::Ia32.new).decode_file(path) { |type, str|
			# Disassembler save file will use this callback with unhandled sections / invalid binary file path
			case type
			when 'binarypath'
				ret = nil
				OpenFile.new(self, "please locate #{str}") { |f| ret = f }.signal_connect('destroy') {  Gtk.main_quit }
				Gtk.main
				break if not ret		# what will this do ?
				ret
			end
		}
		(@dasm_widget ? MainWindow.new : self).display(exe.init_disassembler)
		exe
	end

	def build_menu
		# TODO dynamic checkboxes (check $VERBOSE when opening the options menu to (un)set the mark)

		@menu = Gtk::MenuBar.new
		@accel_group = Gtk::AccelGroup.new
		add_accel_group(@accel_group)

		filemenu = Gtk::Menu.new

		addsubmenu(filemenu, 'OPEN', '^o') {
			OpenFile.new(self, 'chose target binary') { |exename|
				loadfile(exename)
			}
		}
		addsubmenu(filemenu, '_Debug') {
			# TODO list existing targets (inputbox + listbox, reuseable for _goto..)
			# TODO gdbserver
			InputBox.new(self, 'chose target') { |target|
				if not target = Metasm::OS.current.find_process(target)
					MessageBox.new(self, 'no such target')
				else
					DbgWindow.new(target.debugger)
				end
			}
		}

		addsubmenu(filemenu, 'SAVE', '^s') {
			OpenFile.new(self, 'chose save file') { |file|
				@dasm_widget.dasm.save_file(file)
			} if @dasm_widget
		}

		addsubmenu(filemenu, 'CLOSE') {
			if @dasm_widget
				@dasm_widget.terminate
				@vbox.remove @dasm_widget
				@dasm_widget = nil
			end
		}
		addsubmenu(filemenu)

		iomenu = Gtk::Menu.new
		addsubmenu(iomenu, 'Load _map') {
			OpenFile.new(self, 'chose map file') { |file|
				@dasm_widget.dasm.load_map(File.read(file)) if @dasm_widget
			} if @dasm_widget
		}
		addsubmenu(iomenu, 'S_ave map') {
			SaveFile.new(self, 'chose map file') { |file|
				File.open(file, 'w') { |fd|
					fd.puts @dasm_widget.dasm.save_map
				} if @dasm_widget
			} if @dasm_widget
		}
		addsubmenu(iomenu, 'Save _C') {
			SaveFile.new(self, 'chose C file') { |file|
				File.open(file, 'w') { |fd|
					fd.puts @dasm_widget.dasm.c_parser
				} if @dasm_widget
			} if @dasm_widget
		}
		addsubmenu(filemenu, 'Load _C') {
			OpenFile.new(self, 'chose C file') { |file|
				@dasm_widget.dasm.parse_c(File.read(file)) if @dasm_widget
			} if @dasm_widget
		}
		addsubmenu(filemenu, '_i/o', iomenu)
		addsubmenu(filemenu)
		addsubmenu(filemenu, 'QUIT') { destroy } # post_quit_message ?
		# TODO fullsave (map + comments + cur focus_addr + binary? ...)

		addsubmenu(@menu, filemenu, '_File')

		# a fake unreferenced accel group, so that the shortcut keys appear in the menu, but the widget keypress is responsible
		# of handling them (otherwise this would take precedence and :hex couldn't get 'c' etc)
		# but ^o still works (must work even without DasmWidget loaded)
		@accel_group = Gtk::AccelGroup.new

		actions = Gtk::Menu.new
		dasm = Gtk::Menu.new
		addsubmenu(dasm, '_Disassemble from here', 'c') { @dasm_widget.disassemble(@dasm_widget.curview.current_address) }
		@accel_group = Gtk::AccelGroup.new	# ok, so an old gtk segfaults with an accelerator containing both c and C..
		addsubmenu(dasm, 'Disassemble _fast from here', 'C') { @dasm_widget.disassemble_fast(@dasm_widget.curview.current_address) }
		addsubmenu(dasm, 'Disassemble fast & dee_p from here') { @dasm_widget.disassemble_fast_deep(@dasm_widget.curview.current_address) }
		addsubmenu(actions, dasm, '_Disassemble')
		i = addsubmenu(actions, 'Follow') { @dasm_widget.focus_addr @dasm_widget.curview.hl_word }
		i.add_accelerator('activate', @accel_group, Gdk::Keyval::GDK_Return, 0, Gtk::ACCEL_VISIBLE)
		i = addsubmenu(actions, 'Jmp back') { @dasm_widget.focus_addr_back }
		i.add_accelerator('activate', @accel_group, Gdk::Keyval::GDK_Escape, 0, Gtk::ACCEL_VISIBLE)
		i = addsubmenu(actions, 'Undo jmp back') { @dasm_widget.focus_addr_redo }
		i.add_accelerator('activate', @accel_group, Gdk::Keyval::GDK_Return, Gdk::Window::CONTROL_MASK, Gtk::ACCEL_VISIBLE)
		addsubmenu(actions, 'Goto', 'g') { @dasm_widget.prompt_goto }
		addsubmenu(actions, 'List functions', 'f') { @dasm_widget.list_functions }
		addsubmenu(actions, 'List labels', 'l') { @dasm_widget.list_labels }
		addsubmenu(actions, 'List xrefs', 'x') { @dasm_widget.list_xrefs(@dasm_widget.pointed_addr) }
		addsubmenu(actions, 'Rename label', 'n') { @dasm_widget.rename_label(@dasm_widget.pointed_addr) }
		addsubmenu(actions, 'Decompile', 'r') { @dasm_widget.decompile(@dasm_widget.curview.current_address) }
		addsubmenu(actions, 'Decompile finali_ze') { @dasm_widget.dasm.decompiler.finalize ; @dasm_widget.gui_update }
		addsubmenu(actions, 'Comment', ';') { @dasm_widget.decompile(@dasm_widget.curview.current_address) }
		addsubmenu(actions, '_Undefine') { @dasm_widget.dasm.undefine_from(@dasm_widget.curview.current_address) ; @dasm_widget.gui_update }
		addsubmenu(actions, 'Unde_fine function') { @dasm_widget.undefine_function(@dasm_widget.curview.current_address) }
		addsubmenu(actions, 'Undefine function & _subfuncs') { @dasm_widget.undefine_function(@dasm_widget.curview.current_address, true) }
		addsubmenu(actions, 'Data', 'd') { @dasm_widget.toggle_data(@dasm_widget.curview.current_address) }
		addsubmenu(actions, 'Pause dasm', 'p', :check) { |ck| ck.active = !@dasm_widget.playpause_dasm }
		addsubmenu(actions, 'Run ruby snippet', '^r') { @dasm_widget.prompt_run_ruby }
		addsubmenu(actions, 'Run _ruby plugin') {
			OpenFile.new(self, 'ruby plugin') { |f|
				@dasm_widget.instance_eval(File.read(f))
			}
		}

		addsubmenu(@menu, actions, '_Actions')

		options = Gtk::Menu.new
		addsubmenu(options, '_Verbose', :check, $VERBOSE, 'v') { |ck| $VERBOSE = ck.active? ; puts "#{'not ' if not $VERBOSE}verbose" }
		addsubmenu(options, 'Debu_g', :check, $DEBUG) { |ck| $DEBUG = ck.active? }
		addsubmenu(options, 'Debug _backtrace', :check) { |ck| @dasm_widget.dasm.debug_backtrace = ck.active? if @dasm_widget }
		addsubmenu(options, 'Backtrace li_mit') {
			InputBox.new(self, 'max blocks to backtrace', :text => @dasm_widget.dasm.backtrace_maxblocks ) { |target|
				@dasm_widget.dasm.backtrace_maxblocks = Integer(target) if not target.empty?
			}
		}
		addsubmenu(options, 'Backtrace _limit (data)') {
			InputBox.new(self, 'max blocks to backtrace data (-1 to never start)',
					:text => @dasm_widget.dasm.backtrace_maxblocks_data ) { |target|
				@dasm_widget.dasm.backtrace_maxblocks_data = Integer(target) if not target.empty?
			}
		}
		addsubmenu(options)
		addsubmenu(options, 'Forbid decompile _types', :check) { |ck| @dasm_widget.dasm.decompiler.forbid_decompile_types = ck.active? }
		addsubmenu(options, 'Forbid decompile _if/while', :check) { |ck| @dasm_widget.dasm.decompiler.forbid_decompile_ifwhile = ck.active? }
		addsubmenu(options, 'Forbid decomp _optimize', :check) { |ck| @dasm_widget.dasm.decompiler.forbid_optimize_code = ck.active? }
		addsubmenu(options, 'Forbid decomp optim_data', :check) { |ck| @dasm_widget.dasm.decompiler.forbid_optimize_dataflow = ck.active? }
		addsubmenu(options, 'Forbid decomp optimlab_els', :check) { |ck| @dasm_widget.dasm.decompiler.forbid_optimize_labels = ck.active? }
		addsubmenu(options, 'Decompiler _recurse', :check, true) { |ck| @dasm_widget.dasm.decompiler.recurse = (ck.active? ? 1/0.0 : 1) }	# XXX race if changed while decompiling
		# TODO CPU type, size, endian...
		# factorize headers

		addsubmenu(@menu, options, '_Options')

		views = Gtk::Menu.new
		addsubmenu(views, 'Dis_assembly') { @dasm_widget.focus_addr(@dasm_widget.curaddr, :listing) }
		addsubmenu(views, '_Graph') { @dasm_widget.focus_addr(@dasm_widget.curaddr, :graph) }
		addsubmenu(views, 'De_compiled') { @dasm_widget.focus_addr(@dasm_widget.curaddr, :decompile) }
		addsubmenu(views, 'Raw _opcodes') { @dasm_widget.focus_addr(@dasm_widget.curaddr, :opcodes) }
		addsubmenu(views, '_Hex') { @dasm_widget.focus_addr(@dasm_widget.curaddr, :hex) }
		addsubmenu(views, 'Co_verage') { @dasm_widget.focus_addr(@dasm_widget.curaddr, :coverage) }
		addsubmenu(views, '_Sections') { @dasm_widget.list_sections }

		addsubmenu(@menu, views, '_Views')
	end

	def addsubmenu(menu, *args, &action)
		stock = (Gtk::Stock.constants.map { |c| c.to_s } & args).first
		args.delete stock if stock
		accel = args.grep(/^\^?\w$/).first
		args.delete accel if accel
		check = args.delete :check
		submenu = args.grep(Gtk::Menu).first
		args.delete submenu if submenu
		label = args.shift

		if stock
			item = Gtk::ImageMenuItem.new(Gtk::Stock.const_get(stock))
			begin
				item.label = label if label
			rescue
				# in some version of gtk, no #label=
				item = Gtk::MenuItem.new(label) if label
			end
		elsif check
			item = Gtk::CheckMenuItem.new(label)
			item.active = args.shift
		elsif label
			item = Gtk::MenuItem.new(label)
		else
			item = Gtk::MenuItem.new
		end
		item.set_submenu(submenu) if submenu
		item.add_accelerator('activate', @accel_group, accel[-1], (accel[0] == ?^ ? Gdk::Window::CONTROL_MASK : 0), Gtk::ACCEL_VISIBLE) if accel	# XXX 1.9 ?
		item.signal_connect('activate') { protect { action.call(item) } } if action
		menu.append item
		item
	end
end

end
end

require 'metasm/gui/gtk_hex'
require 'metasm/gui/gtk_listing'
require 'metasm/gui/gtk_opcodes'
require 'metasm/gui/gtk_coverage'
require 'metasm/gui/gtk_graph'
require 'metasm/gui/gtk_decomp'
require 'metasm/gui/gtk_debug'

