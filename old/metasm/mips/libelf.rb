# 
# ELF format support
# by Arnaud Cornet
# 

begin
	require 'mmap'
rescue LoadError
end

module ELF
	
ELFDATANONE = 0
ELFDATA2LSB = 1
ELFDATA2MSB = 2
$ei_data = ELFDATANONE

class SectionHeader
	SHT_NULL = 0
	SHT_PROGBITS = 1
	SHT_SYMTAB = 2
	SHT_STRTAB = 3
	SHT_RELA = 4
	SHT_HASH = 5
	SHT_DYNAMIC = 6
	SHT_NOTE = 7
	SHT_NOBITS = 8
	SHT_REL = 9
	SHT_SHLIB = 10
	SHT_DYNSYM = 11
	SHT_to_s = {
		SHT_NULL => 'SHT_NULL',
		SHT_PROGBITS => 'SHT_PROGBITS',
		SHT_SYMTAB => 'SHT_SYMTAB',
		SHT_STRTAB => 'SHT_STRTAB',
		SHT_RELA => 'SHT_RELA',
		SHT_HASH => 'SHT_HASH',
		SHT_DYNAMIC => 'SHT_DYNAMIC',
		SHT_NOTE => 'SHT_NOTE',
		SHT_NOBITS => 'SHT_NOBITS',
		SHT_REL => 'SHT_REL',
		SHT_SHLIB => 'SHT_SHLIB',
		SHT_DYNSYM => 'SHT_DYNSYM'
	}
               
	attr_reader :name, :entries
	attr_writer :name, :entries
	attr_reader :sh_name, :sh_size, :sh_entsize, :sh_type, :sh_link,
			:sh_info, :sh_addr, :sh_offset

	def initialize(raw, off)
		if $ei_data == ELFDATA2LSB then
			array = raw[off .. (off + 10 * 4)].unpack('VVVVVVVVVV')
		else
			array = raw[off .. (off + 10 * 4)].unpack('NNNNNNNNNN')
		end
		@sh_name = array[0]
		@sh_type = array[1]
		@sh_flags = array[2]
		@sh_addr = array[3]
		@sh_offset = array[4]
		@sh_size = array[5]
		@sh_link = array[6]
		@sh_info = array[7]
		@sh_addralign = array[8]
		@sh_entsize = array[9]

		@raw = raw
		@entries = nil
	end

	def content
		@raw[@sh_offset .. (@sh_offset + @sh_size)]
	end

	def range_bracket(range)
		# XXX: we do not check range.last.
 		if range.first < @sh_addr or range.first > @sh_addr + @sh_size
			raise RuntimeError.new("Invalid range")
		end
		if @sh_type == SHT_NOBITS 
			return "\x0" * (range.last - range.first + 1)
		end
		return @raw[range.first + @sh_offset - @sh_addr .. 
					range.last + @sh_offset - @sh_addr]
	end

	def [](addr)
		if addr.class == Range
			return range_bracket(addr)
		end

		raise RuntimeError.new("Invalid range") if addr < @sh_addr or
				addr > @sh_addr + @sh_size

		return 0 if @sh_type == SHT_NOBITS
		@raw[addr + @sh_offset - @sh_addr]
	end

	def inspect
		type_name = SHT_to_s[@sh_type]
		if !type_name
			if @sh_type >= 0x60000000 and @sh_type <= 0x6fffffff
				type_name = 'Aucune idée'
			elsif @sh_type >= 0x70000000 and @sh_type <= 0x7fffffff
				type_name = 'Proc specific section'
			elsif @sh_type >= 0x80000000 and @sh_type <= 0xffffffff
				type_name = 'User section'
			end
		end

		"'#{@name}' type: #{type_name} a: 0x%x o:0x%x of:0x%x " % 
				[@sh_addr, @sh_offset, @sh_addr + @sh_size]
	end
end

class ProgramHeader
	PT_NULL = 0
	PT_LOAD = 1
	PT_DYNAMIC = 2
	PT_INTERP = 3
	PT_NOTE = 4
	PT_SHLIB = 5
	PT_PHDR = 6
	PT_to_s = {
		PT_NULL => 'PT_NULL',
		PT_LOAD => 'PT_LOAD',
		PT_DYNAMIC => 'PT_DYNAMIC',
		PT_INTERP => 'PT_INTERP',
		PT_NOTE => 'PT_NOTE',
		PT_SHLIB => 'PT_SHLIB',
		PT_PHDR => 'PT_PHDR'
	}

	PT_LOPROC = 0x60000000
	PT_HIPROC = 0x7fffffff
	PT_GNU_STACK = PT_LOPROC + 0x474e551

	attr_reader :p_type, :p_filesz, :p_offset, :p_vaddr, :p_memsz
	def initialize(raw, off)
		if $ei_data == ELFDATA2LSB
			array = raw[off .. (off + 8 * 4)].unpack('VVVVVVVV')
		else
			array = raw[off .. (off + 8 * 4)].unpack('NNNNNNNN')
		end
		@p_type, @p_offset, @p_vaddr, @p_paddr, @p_filesz, @p_memsz, 
		@p_flags, @p_align = *array

		@raw = raw
	end

	def content
		# we should check filez is not too big
		@raw[@p_offset .. @p_offset + @p_filesz]
	end

	def inspect
		ptname = PT_to_s[@p_type]
		ptname = "PROCSPEC" if @p_type >= PT_LOPROC and
			@p_type <= PT_HIPROC
		("#{ptname} off: 0x%x vaddr: 0x%x paddr: 0x%x fsz: 0x%x " + 
			"msz: 0x%x flags: 0x%x align: 0x%x") % 
			[@p_offset, @p_vaddr, @p_paddr, @p_filesz, @p_memsz,
				@p_flags, @p_align]
	end
end

class SymbolTableEntry
	STT_NOTYPE = 0
	STT_OBJECT = 1
	STT_FUNC = 2
	STT_SECTION = 3
	STT_FILE = 4
	STT_LOPROC = 13
	STT_HIPROC = 15

	STT_to_s = {
		STT_NOTYPE => 'STT_NOTYPE',
		STT_OBJECT => 'STT_OBJECT',
		STT_FUNC => 'STT_FUNC',
		STT_SECTION => 'STT_SECTION',
		STT_FILE => 'STT_FILE',
		STT_LOPROC => 'STT_LOPROC',
		14 => 'STT_PROC',
		STT_HIPROC => 'STT_HIPROC'
	}

	STB_LOCAL = 0
	STB_GLOBAL = 1
	STB_WEAK = 2
	STB_LOPROC = 13
	STB_HIPROC = 15

	STB_to_s = {
		STB_LOCAL => 'STB_LOCAL',
		STB_GLOBAL => 'STB_GLOBAL',
		STB_WEAK => 'STB_WEAK',
		STB_LOPROC => 'STB_LOPROC',
		14 => 'STB_PROC',
		STB_HIPROC => 'STB_HIPROC'
	}

	attr_reader :st_name, :st_value, :st_type, :st_bind, :st_shndx, :st_info, :st_other
	attr_accessor :name
	def initialize(raw, off)
		if $ei_data == ELFDATA2LSB
			array = raw[off .. (off + 8 * 3 + 2 * 1 + 2)].unpack('VVVccv')
		else
			array = raw[off .. (off + 8 * 3 + 2 * 1 + 2)].unpack('NNNccn')
		end
		@st_name, @st_value, @st_size, @st_info, @st_other, @st_shndx = *array

		@st_bind = @st_info >> 4
		@st_type = @st_info & 0xf
	end

	def inspect
		"Sym: '#{name}' 0x#{"%x" % @st_value} #{@st_size} " + 
				"#{STB_to_s[@st_bind]} #{STT_to_s[@st_type]}"
	end
end

# Relocation's header @sh_info specifies symbol table section, it's @sh_link
# specifies the section to modify
class Relocation
	R_386_NONE = 0
	R_386_32 = 1
	R_386_PC32 = 2
	R_386_GOT32 = 3
	R_386_PLT32 = 4
	R_386_COPY = 5
	R_386_GLOB_DAT = 6
	R_386_JMP_SLOT = 7
	R_386_RELATIVE = 8
	R_386_GOTOFF = 9
	R_386_GOTPC = 10
	R_to_s = {
		R_386_NONE => 'R_386_NONE',
		R_386_32 => 'R_386_32',
		R_386_PC32 => 'R_386_PC32',
		R_386_GOT32 => 'R_386_GOT32',
		R_386_PLT32 => 'R_386_PLT32',
		R_386_COPY => 'R_386_COPY',
		R_386_GLOB_DAT => 'R_386_GLOB_DAT',
		R_386_JMP_SLOT => 'R_386_JMP_SLOT',
		R_386_RELATIVE => 'R_386_RELATIVE',
		R_386_GOTOFF => 'R_386_GOTOFF',
		R_386_GOTPC => 'R_386_GOTPC'
	}

	def initialize(raw, off, sym_sh, dest_sh, rela)
		if $ei_data == ELFDATA2LSB
			array = raw[off .. (off + 4 * 2)].unpack(rela ? 'VVV' : 'VV')
		else
			array = raw[off .. (off + 4 * 2)].unpack(rela ? 'NNN' : 'NN')
		end
		@r_offset = array[0]
		@r_info = array[1]
		@r_addend = array[2] if rela

		@r_sym = @r_info >> 8
		@r_type = @r_info & 0xff
		@sym_sh = sym_sh
 		if @sym_sh.sh_type != SectionHeader::SHT_SYMTAB and
				@sym_sh.sh_type != SectionHeader::SHT_DYNSYM
			raise RuntimeError.new("Relocation argument is not " + 
					"a SYMTAB OR a DYNSYM")
		end
		@symentry = sym_sh.entries[@r_sym]
		@dest_sh = dest_sh
	end

	def is_null
		@dest_sh.sh_type == SectionHeader::SHT_NULL
	end

	def inspect
		"#{R_to_s[@r_type]} 0x#{"%x" % @r_offset} " + 
			"(#{@symentry.inspect} => #{@dest_sh.inspect})"
	end
end

class Dynamic
	DT_NULL = 0
	DT_NEEDED = 1
	DT_PLTRELSZ = 2
	DT_PLTGOT = 3
	DT_HASH = 4
	DT_STRTAB = 5
	DT_SYMTAB = 6
	DT_RELA = 7
	DT_RELASZ = 8
	DT_RELAENT = 9
	DT_STRSZ = 10
	DT_SYMENT = 11
	DT_INIT = 12
	DT_FINI = 13
	DT_SONAME = 14
	DT_RPATH = 15
	DT_SYMBOLIC = 16
	DT_REL = 17
	DT_RELSZ = 18
	DT_RELENT = 19
	DT_PLTREL = 20
	DT_DEBUG = 21
	DT_TEXTREL = 22 
	DT_JMPREL = 23

	DT_LOPROC =  0x70000000 
	DT_HIPROC =  0x7fffffff 

	DT_to_s = {
		DT_NULL => 'DT_NULL',
		DT_NEEDED => 'DT_NEEDED',
		DT_PLTRELSZ => 'DT_PLTRELSZ',
		DT_PLTGOT => 'DT_PLTGOT',
		DT_HASH => 'DT_HASH',
		DT_STRTAB => 'DT_STRTAB',
		DT_SYMTAB => 'DT_SYMTAB',
		DT_RELA => 'DT_RELA',
		DT_RELASZ => 'DT_RELASZ',
		DT_RELAENT => 'DT_RELAENT',
		DT_STRSZ => 'DT_STRSZ',
		DT_SYMENT => 'DT_SYMENT',
		DT_INIT => 'DT_INIT',
		DT_FINI => 'DT_FINI',
		DT_SONAME => 'DT_SONAME',
		DT_RPATH => 'DT_RPATH',
		DT_SYMBOLIC => 'DT_SYMBOLIC',
		DT_REL => 'DT_REL',
		DT_RELSZ => 'DT_RELSZ',
		DT_RELENT => 'DT_RELENT',
		DT_PLTREL => 'DT_PLTREL',
		DT_DEBUG => 'DT_DEBUG',
		DT_TEXTREL => 'DT_TEXTREL', 
		DT_JMPREL => 'DT_JMPREL'
	}

	attr_reader :d_tag, :d_val, :d_ptr
	def initialize(raw, off)
		if $ei_data == ELFDATA2LSB
			array = raw[off .. (off + 4 * 2)].unpack('VV')
		else
			array = raw[off .. (off + 4 * 2)].unpack('NN')
		end
		@d_tag = array[0]
		@d_val = @d_ptr = array[1]
	end

	def inspect
		dtagname = DT_to_s[@d_tag]
		dtagname = "proc specific" if @d_tag >= DT_LOPROC and
							@d_tag <= DT_HIPROC
		"Dynamic: #{dtagname} 0x#{"%x" % @st_val}"
	end
end

class Header
	ET_NONE = 0 	# No file type
	ET_REL = 1 	# Relocatable file
	ET_EXEC = 2 	# Executable file
	ET_DYN = 3 	# Shared object file
	ET_CORE = 4 	# Core file
	ET_LOPROC = 0xff00 	# Proc specific
	ET_HIPROC = 0xffff 	# Proc specific
	ET_to_s = {
		ET_NONE => 'ET_NONE',
		ET_REL => 'ET_REL',
		ET_EXEC => 'ET_EXEC',
		ET_DYN => 'ET_DYN',
		ET_CORE => 'ET_CORE'
	}

	EM_NONE = 0
	EM_M32 = 1
	EM_SPARC = 2
	EM_386 = 3
	EM_68K = 4
	EM_88K = 5
	EM_486 = 6
	EM_860 = 7
	EM_MIPS = 8
	EM_to_s = {
		EM_NONE => 'EM_NONE',
		EM_M32 => 'EM_M32',
		EM_SPARC => 'EM_SPARC',
		EM_386 => 'EM_386',
		EM_68K => 'EM_68K',
		EM_860 => 'EM_860',
		EM_MIPS => 'EM_MIPS'
	}

	EV_NONE = 0
	EV_CURRENT = 1
	EV_to_s = {
		EV_NONE => 'EV_NONE',
		EV_CURRENT => 'EV_CURRENT',
	}

	ELFCLASSNONE = 0
	ELFCLASS32 = 1
	ELFCLASS64 = 2
	ELFCLASS_to_s = {
		ELFCLASSNONE => 'ELFCLASSNONE',
		ELFCLASS32 => 'ELFCLASS32',
		ELFCLASS64 => 'ELFCLASS64',
	}

	ELFDATA_to_s = {
		ELFDATANONE => 'ELFDATANONE',
		ELFDATA2LSB => 'ELFDATA2LSB',
		ELFDATA2MSB => 'ELFDATA2MSB',
	}

	attr_reader :e_entry, :e_machine, :e_version, :e_phoff, :e_shoff, :e_flags, :e_ehsize
	attr_reader :e_phentsize, :e_phnum, :e_shentsize, :e_shnum, :e_shstrndx
	def initialize(raw)
		@e_ident = raw[0..15].unpack('a16')[0]
		@ei_class = @e_ident[4]
		$ei_data = @e_ident[5]


		if $ei_data == ELFDATA2LSB then
			array = raw[16 .. 51].unpack('vvVVVVVvvvvvv')
		else
			array = raw[16 .. 51].unpack('nnNNNNNnnnnnn')
		end
		@e_type, @e_machine, @e_version, @e_entry, @e_phoff, @e_shoff, @e_flags, 
		@e_ehsize, @e_phentsize, @e_phnum, @e_shentsize, @e_shnum, @e_shstrndx = *array

		if @e_ident[0 .. 3] + "" != "\177ELF"
			raise RuntimeError.new("Invalid ELF file")
		end

		if (@e_type != 2 && @e_type != 3) # ET_EXEC or ET_DYN
			raise RuntimeError.new("Invalid ELF type")
		end

		@raw = raw

		load_section_names_sh
		@ephs = nil
	end

	def load_section_names_sh
		return @s_names if @s_names
		s = SectionHeader.new(@raw,
				      @e_shoff + (@e_shstrndx * @e_shentsize))
		@s_names = s.content
	end

	def program_headers
		return nil if @e_phnum == 0
		return @ephs if @ephs
		@ephs = Array.new
		0.upto(@e_phnum - 1) { |i|
			eph = ProgramHeader.new(@raw,
					@e_phoff + (i * @e_phentsize))
			@ephs << eph
		}
		@ephs
	end

	def section_headers
		return @eshs if @eshs != nil
		load_section_names_sh
		@eshs = Array.new
		0.upto(@e_shnum - 1) { |i|
			esh = SectionHeader.new(@raw,
					@e_shoff + (i * @e_shentsize))
			esh.name = ELF.extract_name(@s_names, esh.sh_name)
			@eshs << esh
		}
		@eshs
	end

	def inspect
		type_name = ET_to_s[@e_type]
		type_name = 'Proc specific' if @e_type >= 0xff00 and
							@e_type <= 0xffff
		elfclass_name = ELFCLASS_to_s[@ei_class]
		elfdata_name = ELFDATA_to_s[$ei_data]
		"ELF file type: #{type_name}\n" + 
		"    machine type: #{EM_to_s[@e_machine]}\n" + 
		"    elf version: #{@e_version}\n" + 
		"    byte-order : #{elfdata_name}\n"+
		"    class : #{elfclass_name}\n"+
		"    entry point: 0x%x\n" % @e_entry + 
		"    program header offset: 0x%x\n" % @e_phoff + 
		"    section header offset: 0x%x\n" % @e_shoff + 
		"    flags: %b\n" % @e_flags
	end
end

class ELF
	attr_reader :header

	def ELF.load(filename)
		begin
			return ELF.new(File.mmap(filename))
		rescue
			return ELF.new(File.read(filename))
		end
	end
	
	def initialize(raw)
		@raw = raw
		@header = Header.new(@raw)
		@program_headers = @header.program_headers
		@section_headers = @header.section_headers
	end

	def ELF.extract_name(raw, offset)
		return '' if raw[offset] == 0
		i = offset
		i = i + 1 while raw[i] != 0
		raw[offset .. i - 1]
	end

	def program_headers
		@header.program_headers
	end

	def symbols
		return @sym_sections if @sym_sections
		@sym_sections = Array.new
		@section_headers.select { |sh|
			sh.sh_type == SectionHeader::SHT_SYMTAB or
				sh.sh_type == SectionHeader::SHT_DYNSYM
		}.each { |symtab|
			strtab = @section_headers[symtab.sh_link]

			syms = Array.new
			0.upto(symtab.sh_size / symtab.sh_entsize - 1) { |i|
				ste = SymbolTableEntry.new(symtab.content,
							i * symtab.sh_entsize)
				ste.name = ELF.extract_name(strtab.content,
							ste.st_name)
				syms << ste
			}
			symtab.entries = syms
			@sym_sections << symtab
		}
		@sym_sections
	end

	def relocations
		return @rel_sections if @rel_sections
		@rel_sections = Array.new
		@section_headers.select { |sh|
			sh.sh_type == SectionHeader::SHT_REL or
				sh.sh_type == SectionHeader::SHT_RELA
		}.each { |reloc|
			relocs = Array.new
			0.upto(reloc.sh_size / reloc.sh_entsize - 1) { |i|
				rel = Relocation.new(reloc.content,
					i * reloc.sh_entsize,
					@section_headers[reloc.sh_link],
					@section_headers[reloc.sh_info], 
					reloc.sh_type ==
						SectionHeader::SHT_RELA)
				relocs << rel
			}
			reloc.entries = relocs
			@rel_sections << reloc
		}
		@rel_sections
	end

	def dynamic
		return @dyn_section if @dyn_section
		@section_headers.select { |sh|
			sh.sh_type == SectionHeader::SHT_DYNAMIC
		}.each { |dyn|
			dyns = Array.new
			0.upto(dyn.sh_size / dyn.sh_entsize - 1) { |i|
				rel = Dynamic.new(dyn.content,
					i * dyn.sh_entsize)
				dyns << rel
			}
			dyn.entries = dyns
			@dyn_section = dyn
		}
		@dyn_section
	end

	def inspect
		@header.inspect
	end

	def find_section(sname)
		@header.section_headers.select { |e| e.name == sname }[0]
	end

	def entrypoint
		entry
	end

	def entry
		@header.e_entry
	end

	def endian
		$ei_data
	end

	def global_funcs
		return @globals if @globals
		@globals = Hash.new
		symbols.each { |s|
			s.entries.each { |sym|
				if sym.st_bind ==
					SymbolTableEntry::STB_GLOBAL and
					sym.st_type ==
					SymbolTableEntry::STT_FUNC and
					sym.name
					@globals[sym.st_value] = sym.name
				end
			}
		}
		@globals
	end

	def find_section_at_vaddr(vaddr)
		found = @section_headers.select { |e| 
			e.sh_addr <= vaddr and e.sh_addr + e.sh_size >= vaddr
		}
		# XXX: it does overlap sometimes
		#raise RuntimeError.new("I do not get it: " + found.inspect) if found.size > 1
		found[0]
	end

	def [](vaddr)
		a = (vaddr.class == Range) ? vaddr.first : vaddr
		if @last_section and @last_section.sh_addr <= a and
			@last_section.sh_addr + @last_section.sh_size >= a
			return @last_section[vaddr]
		end
		@last_section = find_section_at_vaddr(a)
		return nil if not @last_section
		@last_section[vaddr]
	end
end
end

#elf = ELF::ELF.new(IO.read(ARGV[0] ? ARGV[0] : '/lib/libc-2.3.5.so'))
#elf.relocations.each { |r|
#	puts r.inspect
#	puts r.entries.collect { |e| e.inspect }.join("\n")
#}
#elf.symbols.each { |s|
#	puts s.inspect
#	puts s.entries.collect { |e| e.inspect }.join("\n")
#}
#
#elf.find_section('.text')
#elf.find_section('.data')
