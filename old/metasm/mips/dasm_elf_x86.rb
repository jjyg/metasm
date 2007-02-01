#!/usr/bin/ruby

require 'metasm/ia32/decode'
require 'metasm/mips/decode'
require 'metasm/desasm'
#require 'metasm_ia32_emu'
require 'libelf'

include Metasm
include ELF

class ELF::ELF
	def getvaddr(voff)
		ph = program_headers.find_all { |ph| ph.p_type == ProgramHeader::PT_LOAD }
		
		good_ph = ph.find { |ph| (voff >= ph.p_vaddr) and (voff <= ph.p_vaddr+ph.p_memsz) }
		ra = good_ph.p_offset+(voff-good_ph.p_vaddr)
		
		[@raw, ra] if ra
	end
end

class Elf_Ia32_Program < Program
end

elf = ELF::ELF.load(ARGV[0])
case elf.header.e_machine 
	when ELF::Header::EM_386
		pg = Program.new(Ia32, elf)
	when ELF::Header::EM_MIPS
		pg = Program.new(MIPS, elf, 1)
		Metasm::MIPS.endian = (elf.endian == ELF::ELFDATA2LSB ? :little : :big)
	else
		raise RuntimeError.new("Unsupported processor")
end

names = { 'entrypoint' => elf.entrypoint }

elf.symbols.each { |s| s.entries.each { |s| names[s.name] = s.st_value if (s.st_shndx != 0) and (s.st_type == ELF::SymbolTableEntry::STT_FUNC) } }


if ARGV[1]
	offsets = [names[ARGV[1]]]
else
	offsets = names.values
end

pg.desasm(offsets)

names.sort.each { |k, v|
$stderr.puts "%8x: #{k}" % v
	next unless pg.blocks[v]
$stderr.puts "exists"
	pg.blocks[v].name = k
}

pg.dump_source

