#!/usr/bin/ruby

require 'metasm/ia32/disasm'
require 'metasm/program'
#require 'metasm_ia32_emu'
require 'libelf'

include Metasm
include ELF

class ELF::ELF
	def getvaddr(voff)
		ra = va2ra voff
		[@raw, ra] if ra
	end
end

#class PE_Ia32_Program < Ia32_Program
#	def emule(instr, voff, block)
#		if (instr.name == 'mov' and instr.args[0].class == Ia32_ModRM and a0 == 'fs:[0]'
#			e = emule_backtrace([arg1])
#			@voffsets << e if e
#		else
#			super
#		end
#	end
class Elf_Ia32_Program < Program
end

elf = ELF::ELF.load ARGV[0]
metasm = Disassembler.new(ia32_opcode_list_pentium_sse3, Ia32_Instruction)

names = { 'entrypoint' => elf.rva2va(elf.entrypoint) }

#if elf.exports
#	elf.exports.exports.each { |e|
#		names[e.name] = pe.rva2va e.rva
#	}
#end

#if ARGV[1]
#	offsets = [names[ARGV[1]]]
#else
	offsets = names.values
#end

pg = Elf_Ia32_Program.new(metasm, elf)
pg.desasm(offsets)

names.sort.each { |k, v|
$stderr.puts "%8x: #{k}" % v
	next unless pg.blocks[v]
$stderr.puts "exists"
	pg.blocks[v].name = k
}

pg.dump_source

