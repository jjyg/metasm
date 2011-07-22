#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm plugin: try to demangle all labels as c++ names, add them as
# comment if successful

def demangle_all_cppnames
	cnt = 0
	prog_binding.each { |name, addr|
		if dname = demangle_cppname(name)
			cnt += 1
			add_comment(addr, dname)
		end
	}
	cnt
end

demangle_all_cppnames if gui
