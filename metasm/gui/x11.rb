#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/dynldr'

module Metasm
module Gui
class XGui < DynLdr
	new_api_c <<EOS, 'libX11.so'
#pragma prepare_gcc
#include <X11/Xlib.h>
EOS

def self.test
	d = xopendisplay(nil)
	s = xdefaultscreen(d)
	cmap = xdefaultcolormap(d, s)
	w = xcreatesimplewindow(d, xdefaultrootwindow(d), 0, 0, 28, 28, 0, xblackpixel(d, s), xwhitepixel(d, s))
	xstorename(d, w, "lol")
	gc = xcreategc(d, w, 0, 0)
	xsetforeground(d, gc, xwhitepixel(d, s))
	xselectinput(d, w, EXPOSUREMASK|KEYPRESSMASK|BUTTONPRESSMASK)
	xmapwindow(d, w)
	msg = alloc_c_struct('XEvent')
str = 'lolz'
x = 12
y = 20
w = 50
h = 30
	loop {
p :loop
		xnextevent(d, msg)
		case msg['type']
		when EXPOSE
p :expose
			#xsetforeground(d, gc, col)
			#xdrawrectangle(d, w, gc, x, y, w, h)
			#xfillrectangle(d, w, gc, x, y, w, h)
			#xdrawline(d, w, gc, todo)
			xdrawstring(d, w, gc, x, y, str, str.length)
		when KEYPRESS
p :keypress
			k = xlookupkeysym(msg['key'], 0)
			p k
		when BUTTONPRESS
p :buttonpress
			break
		end
	}
	xdestroywindow(d, w)
	xclosedisplay(d)
end

test

end
end
end

#require 'metasm/gui/dasm_main'
#require 'metasm/gui/debug'

