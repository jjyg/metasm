#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm plugin: retrieve a section section, and disassemble everything it can, skipping existing code and nops
# usage: load the plugin, then call (ruby snipped): dasm.dasm_all_section '.text'
def dasm_all(addrstart, length, method=:disassemble_fast_deep)
	s = get_section_at(addrstart)
	return if not s
	s = s[0]
	boff = s.ptr
	off = 0
	while off < length
		if di = @decoded[addrstart + off]
			if di.kind_of? DecodedInstruction
				off += di.bin_length
			else
				off += 1
			end
		else
			s.ptr = boff+off
			maydi = cpu.decode_instruction(s, 0)
			if not maydi
				off += 1
			elsif maydi.instruction.to_s =~ /nop|lea (.*), \[\1(?:\+0)?\]|mov (.*), \2|int 3/
				off += maydi.bin_length
			else
				puts "dasm_all: found #{Expression[addrstart+off]}" if $VERBOSE
				send(method, addrstart+off)
			end
		end
	end

	count = 0
	off = 0
	while off < length
		addr = addrstart+off
		if di = @decoded[addr] and di.kind_of? DecodedInstruction
			if di.block_head?
				b = di.block
				if not @function[addr] and b.from_subfuncret.to_a.empty? and b.from_normal.to_a.empty?
					l = auto_label_at(addr, 'sub_orph')
					puts "dasm_all: found orphan function #{l}"
					@function[addrstart+off] = DecodedFunction.new
					@function[addrstart+off].finalized = true
					detect_function_thunk(addr)
					count += 1
				end
			end
			off += di.bin_length
		else
			off += 1
		end
	end

	puts "found #{count} orphan functions" if $VERBOSE

	gui.gui_update if gui
end

def dasm_all_section(name, method=:disassemble_fast_deep)
	section_info.each { |n, a, l, i|
		if name == n
			dasm_all(Expression[a].reduce, l, method)
		end
	}
	true
end
