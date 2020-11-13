#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm GUI plugin: hide 'nop' instructions from the graph view
if gui
	gui.keyboard_callback[?H] = lambda { |*_|
		next if not gui.curview.respond_to?(:curcontext)
		addr = gui.curaddr
		gui.curview.curcontext.box.each { |b|
			b[:addresses].delete_if { |a| di_at(a) and di_at(a).opcode.name == 'nop' }
		}
		gui.curview.build_ctx_boxes(gui.curview.curcontext)
		gui.curview.curcontext.auto_arrange_boxes
		gui.focus_addr(addr)
	}
end
