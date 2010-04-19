#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/dynldr'

module Metasm
module Gui
class XGui < DynLdr
	new_api_c '#include <X11/Xlib.h>', 'libX11.so'

def self.test
p 1
	d = xopendisplay(nil)
p 2
	s = xdefaultscreen(d)
p 3
	w = xcreatesimplewindow(d, xdefaultrootwindow(d), 0, 0, 28, 28, 0, xblackpixel(d, s), xwhitepixel(d, s))
p 4
	xselectinput(d, w, EXPOSUREMASK|KEYPRESSMASK|BUTTONPRESSMASK)
p 5
	xmapwindow(d, w)
p 6
	map = xdefaultcolormap(d, s)
p 7
	gc = xcreategc(d, w, 0, 0)
	#xalloccolor
	#xflush(d)
p 8
	msg = alloc_c_struct('XEvent')
str = 'lolz'
x = 12
y = 20
w = 50
h = 30
	loop {
p d, msg
p 9
		xnextevent(d, msg)
		case msg['type']
		when EXPOSE
p 10
			#xsetforeground(d, gc, col)
			xdrawrectangle(d, w, gc, x, y, w, h)
p 11
			xfillrectangle(d, w, gc, x, y, w, h)
p 12
			#xdrawline(d, w, gc, todo)
p 13
			xdrawstring(d, w, gc, x, y, str, str.length)
		when KEYPRESS
p 14
			k = xlookupkeysym(msg['key'], 0)
		end
	}
p 15
	xdestroywindow(d, w)
p 16
	xclosedisplay(d)
p 17
end

test

end
end
end

#require 'metasm/gui/dasm_main'
#require 'metasm/gui/debug'

