#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm plugin: scan for xrefs to the target address, incl. relative offsets (eg near call/jmp)
def scanxrefs(target)
	ans = []
	csz = cpu.size
	msk = (1 << csz) - 1
	upq = (csz == 64 ? 'q' : 'V')
	sections.sort.each { |s_addr, edata|
		raw = edata.data.to_str
		(0..raw.length-csz/8).each { |off|
			r = raw[off, csz/8].unpack(upq).first
			ans << (s_addr + off) if (r + off+csz/8 + s_addr) & msk == target or r == target
		}
	}
	ans
end

gui.keyboard_callback[?X] = lambda { |*a|
	target = gui.curaddr
	ans = scanxrefs(target)
	list = [['addr']] + ans.map { |off| [Expression[off].to_s] }
	gui.listwindow("scanned xrefs to #{Expression[target]}", list) { |i| gui.focus_addr i[0] }
	true
} if gui
