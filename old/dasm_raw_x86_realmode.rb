#!/usr/bin/ruby

require 'metasm/ia32_emu'

include Metasm

class Ia32_Instruction
        @@adsz = 2
	@@opsz = 2
	# and voila, real mode ;)
end

class Raw
	attr_accessor :vstart
	attr_reader :raw
	
	def initialize(s, v = 0)
		@raw = s
		@vstart = v
	end
	
	def getvaddr(voff)
		voff -= @vstart
		return @raw, voff if voff >= 0 and voff < @raw.length
	end
end

begin
	require 'mmap'
	e = Raw.new(File.mmap(ARGV[0]))
rescue
	e = Raw.new(File.read(ARGV[0]))
end

if ARGV[1]
	start = ARGV[1].to_i
	if ARGV[2]
		e.vstart = ARGV[2].to_i - start
	end
else
	start = 0
end

metasm = Metassembler.new(ia32_opcode_list_pentium_sse3, Ia32_Instruction)

pg = Program.new(metasm, e)
pg.desasm([start])
pg.dump_source

