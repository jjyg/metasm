#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm GUI plugin: 
# pops a list of bookmarked functions
# also allows the custom coloration of blocks/functions

if gui
=begin
	# TODO generic ToolWindow
	class ColorWidget < Metasm::Gui::DrawableWidget
		def initialize_widget(&b)
			@action = b
		end

		def paint
			0xff.times { |x|
				0xf.times { |y|
					draw_rectangle_color('%02x%x' % [x, y], x*16, y*16, 16, 16)
				}
			}
		end

		def click(x, y)
			@action.call('%02x%x' % [x, y])
			destroy
		end
	end
=end

	# list of user-specified addrs
	@bookmarklist = []
	# every single addr => color
	@bookmarkcolor = {}

	obg = gui.bg_color_callback	# chain old callback
	gui.bg_color_callback = lambda { |a|
		if obg and col = obg[a]
			col
		else
			# least priority
			@bookmarkcolor[a]
		end
	}

	popbookmarks = lambda {
		list = [['address', 'color']] + @bookmarklist.map { |bm| [Expression[bm].to_s, @bookmarkcolor[bm].to_s] }
		listcolcb = lambda { |e| [nil, @bookmarkcolor[Expression.parse_string(e[0]).reduce]] }
		gui.listwindow('bookmarks', list, :color_callback => listcolcb) { |e| gui.focus_addr(e[0]) }
	}

	w = gui.toplevel
	w.addsubmenu(w.find_menu('Views'), '_Bookmarks', popbookmarks)
	w.update_menu
	gui.keyboard_callback[?B] = popbookmarks

	gui.keyboard_callback[?C] = lambda { |a|
		if s = gui.curview.instance_variable_get('@selected_boxes') and not s.empty?
			al = s.map { |b| b[:line_address] }
		elsif fa = find_function_start(gui.curaddr)
			al = function_blocks(fa).map { |k, v| block_at(k).list.map { |di| di.address } }
		else
			next
		end
		al = al.flatten.uniq
		# XXX also prompt for comment/bookmark name ?
		#ColorWindow.new.prompt { |col|
		gui.inputbox('color to use (RGB)', :text => 'f88') { |col|
			@bookmarklist << al.min
			al.each { |a| @bookmarkcolor[a] = col }
			gui.gui_update
		}
	}
end
