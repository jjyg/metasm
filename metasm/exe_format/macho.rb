#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2008 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'

module Metasm
class MachO < ExeFormat
	MAGIC = { 0xfeedface => 'MAGIC',   0xcefaedfe => 'CIGAM',
	          0xfeedfacf => 'MAGIC64', 0xcffaedfe => 'CIGAM64' }

	CPU = {
		1 => 'VAX', 2 => 'ROMP',
		4 => 'NS32032', 5 => 'NS32332',
		6 => 'MC680x0', 7 => 'I386',
		8 => 'MIPS', 9 => 'NS32532',
		11 => 'HPPA', 12 => 'ARM',
		13 => 'MC88000', 14 => 'SPARC',
		15 => 'I860', 16 => 'I860_LITTLE',
		17 => 'RS6000', 18 => 'POWERPC',
		0x100_0000|18 => 'POWERPC64', #0x100_0000 => 'CPU_ARCH_ABI64',
		255 => 'VEO',
		0xffff_ffff => 'ANY',
	}

	SUBCPU = {
		'VAX' => { 0 => 'ALL',
			1 => '780', 2 => '785', 3 => '750', 4 => '730',
			5 => 'UVAXI', 6 => 'UVAXII', 7 => '8200', 8 => '8500',
			9 => '8600', 10 => '8650', 11 => '8800', 12 => 'UVAXIII',
		},
		'ROMP' => { 0 => 'ALL', 1 => 'PC', 2 => 'APC', 3 => '135',
			0 => 'MMAX_ALL', 1 => 'MMAX_DPC', 2 => 'SQT',
			3 => 'MMAX_APC_FPU', 4 => 'MMAX_APC_FPA', 5 => 'MMAX_XPC',
		},
		'I386' => { 3 => 'ALL', 4 => '486', 4+128 => '486SX',
		       	0 => 'INTEL_MODEL_ALL', 10 => 'PENTIUM_4',
			5 => 'PENT', 0x16 => 'PENTPRO', 0x36 => 'PENTII_M3', 0x56 => 'PENTII_M5',
		},
		'MIPS' => { 0 => 'ALL', 1 => 'R2300', 2 => 'R2600', 3 => 'R2800', 4 => 'R2000a', },
		'MC680x0' => { 1 => 'ALL', 2 => 'MC68040', 3 => 'MC68030_ONLY', },
		'HPPA' => { 0 => 'ALL', 1 => '7100LC', },
		'ARM' => { 0 => 'ALL', 1 => 'A500_ARCH', 2 => 'A500', 3 => 'A440', 4 => 'M4', 5 => 'A680', },
		'MC88000' => { 0 => 'ALL', 1 => 'MC88100', 2 => 'MC88110', },
		:wtf => { 0 => 'MC98000_ALL', 1 => 'MC98601', },
		'I860' => { 0 => 'ALL', 1 => '860', },
		'RS6000' => { 0 => 'ALL', 1 => 'RS6000', },
		:wtf2 => { 0 => 'SUN4_ALL', 1 => 'SUN4_260', 2 => 'SUN4_110', },
		'SPARC' => { 0 => 'SPARC_ALL', },
		'POWERPC' => { 0 => 'ALL', 1 => '601', 2 => '602', 3 => '603', 4 => '603e',
			5 => '603ev', 6 => '604', 7 => '604e', 8 => '620',
			9 => '750', 10 => '7400', 11 => '7450', 100 => '970',
		},
		'VEO' => { 1 => 'VEO_1', 2 => 'VEO_ALL', },
	}


	FILETYPE = {
		1 => 'OBJECT', 2 => 'EXECUTE', 3 => 'FVMLIB',
		4 => 'CORE', 5 => 'PRELOAD', 6 => 'DYLIB',
		7 => 'DYLINKER', 8 => 'BUNDLE', 9 => 'DYLIB_STUB',
	}

	FLAGS = {
		0x1 => 'NOUNDEFS', 0x2 => 'INCRLINK', 0x4 => 'DYLDLINK', 0x8 => 'BINDATLOAD',
		0x10 => 'PREBOUND', 0x20 => 'SPLIT_SEGS', 0x40 => 'LAZY_INIT', 0x80 => 'TWOLEVEL',
		0x100 => 'FORCE_FLAT', 0x200 => 'NOMULTIDEFS', 0x400 => 'NOFIXPREBINDING', 0x800 => 'PREBINDABLE',
		0x1000 => 'ALLMODSBOUND', 0x2000 => 'SUBSECTIONS_VIA_SYMBOLS', 0x4000 => 'CANONICAL', 0x8000 => 'WEAK_DEFINES',
		0x10000 => 'BINDS_TO_WEAK', 0x20000 => 'ALLOW_STACK_EXECUTION',
}

	LOAD_COMMAND = {
		0x1 => 'SEGMENT', 0x2 => 'SYMTAB', 0x3 => 'SYMSEG', 0x4 => 'THREAD',
		0x5 => 'UNIXTHREAD', 0x6 => 'LOADFVMLIB', 0x7 => 'IDFVMLIB', 0x8 => 'IDENT',
		0x9 => 'FVMFILE', 0xa => 'PREPAGE', 0xb => 'DYSYMTAB', 0xc => 'LOAD_DYLIB',
		0xd => 'ID_DYLIB', 0xe => 'LOAD_DYLINKER', 0xf => 'ID_DYLINKER', 0x10 => 'PREBOUND_DYLIB',
		0x11 => 'ROUTINES', 0x12 => 'SUB_FRAMEWORK', 0x13 => 'SUB_UMBRELLA', 0x14 => 'SUB_CLIENT',
		0x15 => 'SUB_LIBRARY', 0x16 => 'TWOLEVEL_HINTS', 0x17 => 'PREBIND_CKSUM',
		0x8000_0018 => 'LOAD_WEAK_DYLIB', 0x19 => 'SEGMENT_64', 0x1a => 'ROUTINES_64',
		0x8000_0000 => 'REQ_DYLD',
	}

	SYM_TYPE = { 0 => 'UNDF', 1 => 'EXT', 2 => 'ABS', 0xa => 'INDR', 0xe => 'SECT', 0x1e => 'TYPE', 0xe0 => 'STAB' }

	class SerialStruct < SerialStruct
		new_int_field :xword
	end

	class Header < SerialStruct
		words :magic, :cputype, :cpusubtype, :filetype, :ncmds, :sizeofcmds, :flags
		fld_enum :magic, MAGIC
		decode_hook { |m, h|
			case h.magic
			when 'MAGIC'; m.size = 32
			when 'CIGAM'; m.size = 32 ; m.endianness = { :big => :little, :little => :big }[m.endianness] ; h.magic[0, 5] = h.magic[0, 5].reverse
			when 'MAGIC64'; m.size = 64
			when 'CIGAM64'; m.size = 64 ; m.endianness = { :big => :little, :little => :big }[m.endianness] ; h.magic[0, 5] = h.magic[0, 5].reverse
			else raise InvalidExeFormat, "Invalid Mach-O signature #{h.magic.inspect}"
			end
		}
		fld_enum :cputype, CPU
		fld_enum(:cpusubtype) { |m, h| SUBCPU[h.cputype] || {} }
		fld_enum :filetype, FILETYPE
		fld_bits :flags, FLAGS
		attr_accessor :reserved	# word 64bit only

		def set_default_values(m)
			@ncmds ||= 42
			super
		end

		def decode(m)
			super
			@reserved = m.decode_word if m.size == 64
		end
	end

	class LoadCommand < SerialStruct
		words :cmd, :cmdsize
		fld_enum :cmd, LOAD_COMMAND
		attr_accessor :data

		def decode(m)
			super
			ptr = m.encoded.ptr
			if @cmd.kind_of? String and klass = self.class.const_get(@cmd)
				@data = klass.decode(m)
			end
			m.encoded.ptr = ptr + @cmdsize - 8
		end

		class UUID < SerialStruct
			mem :uuid, 16
		end

		class SEGMENT < SerialStruct
			str :name, 16
			xwords :virtaddr, :virtsize, :fileoff, :filesize
			words :maxprot, :initprot, :nsects, :flags
			attr_accessor :sections, :encoded

			def decode(m)
				super
				@sections = []
				@nsects.times { @sections << SECTION.decode(m) }
			end
		end
		SEGMENT_64 = SEGMENT

		class SECTION < SerialStruct
			str :name, 16
			str :segname, 16
			xwords :addr, :size
			words :offset, :align, :reloff, :nreloc, :flags, :res1, :res2
			attr_accessor :sections, :encoded

			def decode_inner(m)
				@encoded = m.encoded[m.addr_to_off(@addr), @size]
			end
		end
		SECTION_64 = SECTION

		class SYMTAB < SerialStruct
			words :symoff, :nsyms, :stroff, :strsize
		end

		class DYSYMTAB < SerialStruct
			words :ilocalsym, :nlocalsym, :iextdefsym, :nextdefsym, :iundefsym, :nundefsym,
				:tocoff, :ntoc, :modtaboff, :nmodtab, :extrefsymoff, :nextrefsyms,
				:indirectsymoff, :nindirectsyms, :extreloff, :nextrel, :locreloff, :nlocrel
		end

		class THREAD < SerialStruct
			words :flavor, :count
			attr_accessor :ctx
			def decode(m)
				super
				@ctx = {}
				regs = 	case m.header.cputype
				when 'I386'; %w[eax ebx ecx edx edi esi ebp esp ss eflags eip cs ds es fs gs]
				when 'POWERPC'; %w[srr0 srr1 r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 r16 r17 r18 r19 r20 r21 r22 r23 r24 r25 r26 r27 r28 r29 r30 r31 cr xer lr ctr mq vrsave]	# XXX eip=?
				else [*1..40].map { |i| "r#{i}" }
				end
				@count.times { @ctx[regs.shift.to_sym] = m.decode_word }
			end
		end
		UNIXTHREAD = THREAD

		class STRING < SerialStruct
			xword :stroff
			attr_accessor :str

			def decode(m)
				ptr = m.encoded.ptr
				super
				ptr = m.encoded.ptr = ptr + @stroff - 8
				@str = m.encoded.read(m.encoded[ptr..-1].data.index(0) || 0)
			end
		end

		class DYLIB < STRING
			xword :stroff
			words :timestamp, :cur_version, :compat_version
		end
		LOAD_DYLIB = DYLIB
		ID_DYLIB = DYLIB

		class PREBOUND_DYLIB < STRING
			xword :stroff
			word :nmodules
			xword :linked_modules
		end

		LOAD_DYLINKER = STRING
		ID_DYLINKER = STRING

		class ROUTINES < SerialStruct
			xwords :init_addr, :init_module, :res1, :res2, :res3, :res4, :res5, :res6
		end
		ROUTINES_64 = ROUTINES

		class TWOLEVEL_HINTS < SerialStruct
			words :offset, :nhints
		end
		class TWOLEVEL_HINT < SerialStruct
			bitfield :word, 0 => :isub_image, 8 => :itoc
		end

		SUB_FRAMEWORK = STRING
		SUB_UMBRELLA = STRING
		SUB_LIBRARY = STRING
		SUB_CLIENT = STRING
	end

	class Symbol < SerialStruct
		word :nameoff
		byte :type
		byte :sect
		half :desc
		xword :value
		attr_accessor :name
		fld_enum :type, SYM_TYPE	# XXX seems wrong

		def decode(m, buf=nil)
			super(m)
			@name = buf[@nameoff...buf.index(0, @nameoff)] if buf
		end
	end

	def encode_byte(val)        Expression[val].encode( :u8, @endianness) end
	def encode_half(val)        Expression[val].encode(:u16, @endianness) end
	def encode_word(val)        Expression[val].encode(:u32, @endianness) end
	def encode_xword(val)       Expression[val].encode((@size == 32 ? :u32 : :u64), @endianness) end
	def decode_byte(edata = @encoded) edata.decode_imm( :u8, @endianness) end
	def decode_half(edata = @encoded) edata.decode_imm(:u16, @endianness) end
	def decode_word(edata = @encoded) edata.decode_imm(:u32, @endianness) end
	def decode_xword(edata= @encoded) edata.decode_imm((@size == 32 ? :u32 : :u64), @endianness) end


	attr_accessor :endianness, :size
	attr_accessor :header, :source
	attr_accessor :segments
	attr_accessor :commands
	attr_accessor :symbols

	def initialize(cpu=nil)
		super
		@endianness ||= cpu ? cpu.endianness : :little
		@size ||= cpu ? cpu.size : 32
		@header = Header.new
		@commands = []
		@segments = []
	end

	# decodes the Mach header from the current offset in self.encoded
	def decode_header
		@header.decode self
		@header.ncmds.times { @commands << LoadCommand.decode(self) }
		@commands.each { |cmd|
			e = cmd.data
			case cmd.cmd
			when 'SEGMENT'; @segments << e
			end
		}
	end

	def decode
		decode_header
		decode_symbols
		@segments.each { |s| decode_segment s }
	end

	def decode_symbols
		@symbols = []
		@commands.each { |cmd|
			e = cmd.data
			case cmd.cmd
			when 'SYMTAB'
				@encoded.ptr = e.stroff
				buf = @encoded.read e.strsize
				@encoded.ptr = e.symoff
				e.nsyms.times { @symbols << Symbol.decode(self, buf) }
			end
		}
		@symbols.each { |s|
			# TODO @encoded.add_label s.name, addr_to_off(s.value) if s.type == 'SECT'
		}
	end

	def decode_segment(s)
		s.encoded = @encoded[s.fileoff, s.filesize]
		s.encoded.virtsize = s.virtsize
		s.sections.each { |ss| ss.encoded = @encoded[ss.offset, ss.size] }
	end

	def each_section(&b)
		@segments.each { |s| yield s.encoded, s.virtaddr }
	end

	def get_default_entrypoints
		@commands.find_all { |cmd| cmd.cmd == 'THREAD' or cmd.cmd == 'UNIXTHREAD' }.map { |cmd| cmd.data.ctx[:eip] || cmd.data.ctx[:srr0] }.compact
	end

	def cpu_from_headers
		case @header.cputype
		when 'I386'; Ia32.new
		when 'POWERPC'; 
		end
	end
end



class UniversalBinary < ExeFormat
	MAGIC = { 0xcafebabe => 'MAGIC' }

	class Header < SerialStruct
		words :magic, :nfat_arch
		fld_enum :magic, MAGIC

		def decode(u)
			super
			puts '%x' % @magic if @magic.kind_of? Integer
			raise InvalidExeFormat, "Invalid UniversalBinary signature #{@magic.inspect}" if @magic != 'MAGIC'
		end
	end
	class FatArch < SerialStruct
		words :cputype, :subcpu, :offset, :size, :align
		fld_enum :cputype, MachO::CPU
		fld_enum(:subcpu) { |x, a| MachO::SUBCPU[a.cputype] || {} }
		attr_accessor :encoded
	end

	def encode_word(val)        Expression[val].encode(:u32, @endianness) end
	def decode_word(edata = @encoded) edata.decode_imm(:u32, @endianness) end

	attr_accessor :endianness, :encoded, :header, :archive
	def initialize
		@endianness = :big
		super
	end

	def decode
		@header = Header.decode(self)
		@archive = []
		@header.nfat_arch.times { @archive << FatArch.decode(self) }
		@archive.each { |a|
			a.encoded = @encoded[a.offset, a.size] || EncodedData.new
		}
	end

	def [](i) @archive[i].encoded if @archive[i] end
end
end
