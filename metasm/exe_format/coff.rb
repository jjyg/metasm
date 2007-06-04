require 'metasm/exe_format/main'

module Metasm
class COFF < ExeFormat
	CHARACTERISTIC_BITS = {
		0x0001 => 'RELOCS_STRIPPED',    0x0002 => 'EXECUTABLE_IMAGE',
		0x0004 => 'LINE_NUMS_STRIPPED', 0x0008 => 'LOCAL_SYMS_STRIPPED',
		0x0010 => 'AGGRESSIVE_WS_TRIM', 0x0020 => 'LARGE_ADDRESS_AWARE',
		0x0040 => 'x16BIT_MACHINE',     0x0080 => 'BYTES_REVERSED_LO',
		0x0100 => 'x32BIT_MACHINE',     0x0200 => 'DEBUG_STRIPPED',
		0x0400 => 'REMOVABLE_RUN_FROM_SWAP', 0x0800 => 'NET_RUN_FROM_SWAP',
		0x1000 => 'SYSTEM',             0x2000 => 'DLL',
		0x4000 => 'UP_SYSTEM_ONLY',     0x8000 => 'BYTES_REVERSED_HI'
	}

	MACHINE = {
		0x0   => 'UNKNOWN',   0x184 => 'ALPHA',   0x1c0 => 'ARM',
		0x1d3 => 'AM33',      0x8664=> 'AMD64',   0xebc => 'EBC',
		0x9041=> 'M32R',      0x1f1 => 'POWERPCFP',
		0x284 => 'ALPHA64',   0x14c => 'I386',    0x200 => 'IA64',
		0x268 => 'M68K',      0x266 => 'MIPS16',  0x366 => 'MIPSFPU',
		0x466 => 'MIPSFPU16', 0x1f0 => 'POWERPC', 0x162 => 'R3000',
		0x166 => 'R4000',     0x168 => 'R10000',  0x1a2 => 'SH3',
		0x1a3 => 'SH3DSP',    0x1a6 => 'SH4',     0x1a8 => 'SH5',
		0x1c2 => 'THUMB',     0x169 => 'WCEMIPSV2'
	}

	SIGNATURE = { 0x10b => 'PE', 0x20b => 'PE+', 0x107 => 'ROM' }

	SUBSYSTEM = {
		0 => 'UNKNOWN',     1 => 'NATIVE',    2 => 'WINDOWS_GUI',
		3 => 'WINDOWS_CUI', 5 => 'OS/2_CUI',  7 => 'POSIX_CUI',
		8 => 'WIN9X_DRIVER', 9 => 'WINDOWS_CE_GUI',
		10 => 'EFI_APPLICATION',
		11 => 'EFI_BOOT_SERVICE_DRIVER',  12 => 'EFI_RUNTIME_DRIVER',
		13 => 'EFI_ROM', 14 => 'XBOX'
	}

	DLL_CHARACTERISTIC_BITS = {
		0x40 => 'DYNAMIC_BASE', 0x80 => 'FORCE_INTEGRITY', 0x100 => 'NX_COMPAT',
		0x200 => 'NO_ISOLATION', 0x400 => 'NO_SEH', 0x800 => 'NO_BIND',
		0x2000 => 'WDM_DRIVER', 0x8000 => 'TERMINAL_SERVER_AWARE'
	}
	
	DIRECTORIES = %w[export_table import_table resource_table exception_table certificate_table
			  base_relocation_table debug architecture global_ptr tls_table load_config
			  bound_import iat delay_import com_runtime reserved]

	SECTION_CHARACTERISTIC_BITS = {
		0x20 => 'CONTAINS_CODE', 0x40 => 'CONTAINS_DATA', 0x80 => 'CONTAINS_UDATA',
		0x100 => 'LNK_OTHER', 0x200 => 'LNK_INFO', 0x800 => 'LNK_REMOVE',
		0x1000 => 'LNK_COMDAT', 0x8000 => 'GPREL',
		0x20000 => 'MEM_PURGEABLE|16BIT', 0x40000 => 'MEM_LOCKED', 0x80000 => 'MEM_PRELOAD',
		0x100000 => 'ALIGN_1BYTES',    0x200000 => 'ALIGN_2BYTES',
		0x300000 => 'ALIGN_4BYTES',    0x400000 => 'ALIGN_8BYTES',
		0x500000 => 'ALIGN_16BYTES',   0x600000 => 'ALIGN_32BYTES',
		0x700000 => 'ALIGN_64BYTES',   0x800000 => 'ALIGN_128BYTES',
		0x900000 => 'ALIGN_256BYTES',  0xA00000 => 'ALIGN_512BYTES',
		0xB00000 => 'ALIGN_1024BYTES', 0xC00000 => 'ALIGN_2048BYTES',
		0xD00000 => 'ALIGN_4096BYTES', 0xE00000 => 'ALIGN_8192BYTES',
		0x01000000 => 'LNK_NRELOC_OVFL', 0x02000000 => 'MEM_DISCARDABLE',
		0x04000000 => 'MEM_NOT_CACHED',  0x08000000 => 'MEM_NOT_PAGED',
		0x10000000 => 'MEM_SHARED',      0x20000000 => 'MEM_EXECUTE',
		0x40000000 => 'MEM_READ',        0x80000000 => 'MEM_WRITE'
	}
	# NRELOC_OVFL means there are more than 0xffff reloc
	# the reloc count must be set to 0xffff, and the real reloc count
	# is the VA of the first relocation

	ORDINAL_REGEX = /^Ordinal_(\d+)$/

	class Header
		attr_accessor :machine, :num_sect, :time, :ptr_sym, :num_sym, :size_opthdr, :characteristics
	end

	class OptionalHeader
		attr_accessor :sig, :linkv_maj, :linkv_min, :code_size, :idata_size, :udata_size, :entrypoint, :base_of_code,
			:base_of_data,	# not in PE+
			# NT-specific fields
			:imagebase, :sect_align, :file_align, :osv_maj, :osv_min, :imgv_maj, :imgv_min, :subsys_maj, :subsys_min, :reserved,
			:image_size, :headers_size, :checksum, :subsystem, :dll_characts, :stackres_size, :stackcom_size, :heapres_size, :heapcom_size, :ldrflags, :numrva
	end

	class ImportDirectory
		attr_accessor :libname, :timestamp, :firstforwarder
		attr_accessor :imports, :iat, :iat_p

		def initialize
			@imports = []
		end

		class Import
			attr_accessor :ordinal, :hint, :name
		end
	end

	class ExportDirectory
		attr_accessor :reserved, :timestamp, :version_major, :version_minor, :dllname, :ordinal_base
		attr_accessor :exports

		def initialize
			@exports = []
		end

		class Export
			attr_accessor :forwarder_lib, :forwarder_ordinal, :forwarder_name, :target, :name, :ordinal
		end
	end

	class Section
		attr_accessor :name, :virtsize, :virtaddr, :rawsize, :rawaddr, :relocaddr, :linenoaddr, :relocnr, :linenonr, :characteristics
		attr_accessor :encoded
	end

	attr_accessor :header, :optheader, :directory, :sections, :endianness, :export, :imports

	def initialize
		@directory = {}	# DIRECTORIES.key => [rva, size]
		@sections = []
		@export = nil
		@imports = nil
		@endianness = :little
	end

	module Resource
	TYPE = {
		1 => 'CURSOR', 2 => 'BITMAP', 3 => 'ICON', 4 => 'MENU',
		5 => 'DIALOG', 6 => 'STRING', 7 => 'FONTDIR', 8 => 'FONT',
		9 => 'ACCELERATOR', 10 => 'RCADATA', 11 => 'MESSAGETABLE',
		12 => 'GROUP_CURSOR', 14 => 'GROUP_ICON', 16 => 'VERSION',
		17 => 'DLGINCLUDE', 19 => 'PLUGPLAY', 20 => 'VXD',
		21 => 'ANICURSOR', 22 => 'ANIICON', 23 => 'HTML',
		24 => 'MANIFEST' # ?
	}

	ACCELERATOR_BITS = {
		1 => 'VIRTKEY', 2 => 'NOINVERT', 4 => 'SHIFT', 8 => 'CTRL',
		16 => 'ALT', 128 => 'LAST'
	}

	# TODO
	# cursor = raw data, cursor_group = header , pareil pour les icons
	class Cursor
		attr_accessor :xhotspot, :yhotspot, :data
	end
	end
end
end
__END__

class Symbols
	attr_reader :name, :value, :sectionnumber, :type, :storageclass, :nbaux, :aux
# name: if the first 4 bytes are null, the 4 next are the index to the name in the string table

	def initialize(raw, offset)
		@name = raw[offset..offset+7].delete("\0")
		@value = bin(raw[offset+8 ..offset+11])
		@sectionnumber = bin(raw[offset+12..offset+13])
		@type = bin(raw[offset+14..offset+15])
		@storageclass = raw[offset+16]
		@nbaux = raw[offset+17]
		@aux = Array.new
		@nbaux.times { @aux << raw[offset..offset+17] ; offset += 18 }
	end
end

class Strings < Array
	attr_reader :size
	
	def initialize(raw, offset)
		@size = bin(raw[offset..offset+3])
		endoffset = offset + @size
puts "String table: 0x%.8x .. 0x%.8x" % [offset, endoffset]
		curstring = ''
		while (offset < endoffset)
			if raw[offset] != 0
				curstring << raw[offset]
			else
				self << curstring
				curstring = ''
			end
			offset += 1
		end
	end
end
