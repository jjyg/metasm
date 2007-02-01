#!/usr/bin/ruby

require 'metasm/ia32'

include Metasm

m = Metassembler.new(ia32_opcode_list_pentium_sse3, Ia32_Instruction)

def hex2bytes(h)
	h = h.hex
	'' << (h & 0xff) << ((h >> 8)  & 0xff) << ((h >> 16) & 0xff) << ((h >> 24) & 0xff)
end

ARGF.each_line { |l|
	if (l =~ /^(trace \d+:\d+ - ([a-fA-F0-9]+) = )([a-fA-F0-9]+) ([a-fA-F0-9]+) ([a-fA-F0-9]+)/)
		pre = $1
		off = $2.hex
		raw = hex2bytes($3) + hex2bytes($4) + hex2bytes($5)
		begin
			i = m.decode(raw)
			if o.codeoffset
				co = o.args.find { |a| Offset === a }
				o.comment = '%.8x' % (off+o.len+co.imm)
			end
			puts pre + hexdump(raw, 0, o.len) + ' ' + o.to_s + "\r"
		rescue RuntimeError
			puts pre + hexdump(raw, 0, 12) + " error\r"
		end
	else
		puts l
	end
}
exit
