require 'metasm/exe_format/main'

module Metasm
# TODO ELF64
class ELF < ExeFormat
	CLASS = { 0 => 'NONE', 1 => '32', 2 => '64' }
	DATA  = { 0 => 'NONE', 1 => 'LSB', 2 => 'MSB' }
	VERSION = { 0 => 'INVALID', 1 => 'CURRENT' }
	TYPE = { 0 => 'NONE', 1 => 'REL', 2 => 'EXEC', 3 => 'DYN', 4 => 'CORE',
		0xff00 => 'LOPROC', 0xffff => 'HIPROC' }
	MACHINE = {
		 0 => 'NONE',   1 => 'M32',     2 => 'SPARC',   3 => '386',
		 4 => '68K',    5 => '88K',     7 => '860',
		 8 => 'MIPS',   9 => 'S370',   10 => 'MIPS_RS3_LE',
		15 => 'PARISC',
		17 => 'VPP500',18 => 'SPARC32PLUS', 19 => '960',
		20 => 'PPC',   21 => 'PPC64',  22 => 'S390',
		36 => 'V800',  37 => 'FR20',   38 => 'RH32',   39 => 'RCE',
		40 => 'ARM',   41 => 'FAKE_ALPHA', 42 => 'SH', 43 => 'SPARCV9',
		44 => 'TRICORE', 45 => 'ARC',  46 => 'H8_300', 47 => 'H8_300H',
		48 => 'H8S',   49 => 'H8_500', 50 => 'IA_64',  51 => 'MIPS_X',
		52 => 'COLDFIRE', 53 => '68HC12', 54 => 'MMA', 55 => 'PCP',
		56 => 'NCPU',  57 => 'NDR1',   58 => 'STARCORE', 59 => 'ME16',
		60 => 'ST100', 61 => 'TINYJ',  62 => 'X86_64', 63 => 'PDSP',
		66 => 'FX66',  67 => 'ST9PLUS',
		68 => 'ST7',   69 => '68HC16', 70 => '68HC11', 71 => '68HC08',
		72 => '68HC05',73 => 'SVX',    74 => 'ST19',   75 => 'VAX',
		76 => 'CRIS',  77 => 'JAVELIN',78 => 'FIREPATH', 79 => 'ZSP',
		80 => 'MMIX',  81 => 'HUANY',  82 => 'PRISM',  83 => 'AVR',
		84 => 'FR30',  85 => 'D10V',   86 => 'D30V',   87 => 'V850',
		88 => 'M32R',  89 => 'MN10300',90 => 'MN10200',91 => 'PJ',
		92 => 'OPENRISC', 93 => 'ARC_A5', 94 => 'XTENSA', 95 => 'NUM',
		0x9026 => 'ALPHA'
	}

	FLAGS = {}

	DYNAMIC_TAG = { 0 => 'NULL', 1 => 'NEEDED', 2 => 'PLTRELSZ', 3 =>
		'PLTGOT', 4 => 'HASH', 5 => 'STRTAB', 6 => 'SYMTAB', 7 => 'RELA',
		8 => 'RELASZ', 9 => 'RELAENT', 10 => 'STRSZ', 11 => 'SYMENT',
		12 => 'INIT', 13 => 'FINI', 14 => 'SONAME', 15 => 'RPATH',
		16 => 'SYMBOLIC', 17 => 'REL', 18 => 'RELSZ', 19 => 'RELENT',
		20 => 'PLTREL', 21 => 'DEBUG', 22 => 'TEXTREL', 23 => 'JMPREL',
		0x7000_0000 => 'LOPROC', 0x7fff_ffff => 'HIPROC' }

	PH_TYPE = { 0 => 'NULL', 1 => 'LOAD', 2 => 'DYNAMIC', 3 => 'INTERP',
		4 => 'NOTE', 5 => 'SHLIB', 6 => 'PHDR',
		0x7000_0000 => 'LOPROC', 0x7fff_ffff => 'HIPROC' }
	PH_FLAGS = { 1 => 'X', 2 => 'W', 4 => 'R' }

	SH_TYPE = { 0 => 'NULL', 1 => 'PROGBITS', 2 => 'SYMTAB', 3 => 'STRTAB',
		4 => 'RELA', 5 => 'HASH', 6 => 'DYNAMIC', 7 => 'NOTE',
		8 => 'NOBITS', 9 => 'REL', 10 => 'SHLIB', 11 => 'DYNSYM',
		0x7000_0000 => 'LOPROC', 0x7fff_ffff => 'HIPROC',
		0x8000_0000 => 'LOUSER', 0xffff_ffff => 'HIUSER' }

	SH_FLAGS = { 1 => 'WRITE', 2 => 'ALLOC', 4 => 'EXECINSTR',
		0xf000_0000 => 'MASKPROC' }

	SH_INDEX = { 0 => 'UNDEF', 0xff00 => 'LORESERVE', 0xff1f => 'HIPROC',		 # LOPROC == LORESERVE
		0xfff1 => 'ABS', 0xfff2 => 'COMMON', 0xffff => 'HIRESERVE' }

	SYMBOL_BIND = { 0 => 'LOCAL', 1 => 'GLOBAL', 2 => 'WEAK',
		13 => 'LOPROC', 15 => 'HIPROC' }
	SYMBOL_TYPE = { 0 => 'NOTYPE', 1 => 'OBJECT', 2 => 'FUNC',
		3 => 'SECTION', 4 => 'FILE', 13 => 'LOPROC', 15 => 'HIPROC' }

	RELOCATION_TYPE = {	# key are in MACHINE.values
		'386' => { 0 => 'NONE', 1 => '32', 2 => 'PC32', 3 => 'GOT32',
			4 => 'PLT32', 5 => 'COPY', 6 => 'GLOB_DAT', 7 => 'JMP_SLOT',
			8 => 'RELATIVE', 9 => 'GOTOFF', 10 => 'GOTPC' }
	}

	class Section
		attr_accessor :name, :type, :flags, :addr, :rawoffset, :link, :info, :align, :entsize, :edata
		attr_accessor :virt_gap	# set to true if a virtual address gap is needed with the preceding section (different memory permission needed)
	end
	class Segment
		attr_accessor :header, :encoded
	end
	class Header
		attr_accessor :ident, :type, :machine, :version, :entry, :phoff, :shoff, :flags, :ehsize, :phentsize, :phnum, :shentsize, :shnum, :shstrndx
		attr_accessor :e_class, :mag, :endianness
	end
	class ProgramHeader
		attr_accessor :type, :offset, :vaddr, :paddr, :filesz, :memsz, :flags, :align
	end
	class SectionHeader
		attr_accessor :name_p, :type, :flags, :addr, :offset, :size, :link, :info, :addralign, :entsize
	end
	class Symbol
		attr_accessor :name, :value, :size, :bind, :type, :other, :shndx, :info, :name_p
	end
	class Relocation
		attr_accessor :offset, :type, :symbol, :info, :addend
	end
	class Tag
		attr_accessor :type, :values
	end

	def self.hash_symbol_name(name)
		name.unpack('C*').inject(0) { |hash, char|
			break hash if char == 0
			hash <<= 4
			hash += char
			hash ^= (hash >> 24) & 0xf0
			hash &= 0x0fff_ffff
		}
	end
end
end
