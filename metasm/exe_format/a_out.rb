#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'

module Metasm
class AOut < ExeFormat
	MAGIC = { 0407 => 'OMAGIC', 0410 => 'NMAGIC', 0413 => 'ZMAGIC',
		0314 => 'QMAGIC', 0421 => 'CMAGIC'
	}
	MACHINE_TYPE = { 0 => 'OLDSUN2', 1 => '68010', 2 => '68020',
		3 => 'SPARC', 100 => 'PC386', 134 => 'I386', 135 => 'M68K',
		136 => 'M68K4K', 137 => 'NS32532', 138 => 'SPARC',
		139 => 'PMAX', 140 => 'VAX', 141 => 'ALPHA', 142 => 'MIPS',
		143 => 'ARM6', 151 => 'MIPS1', 152 => 'MIPS2', 300 => 'HP300',
		0x20B => 'HPUX800', 0x20C => 'HPUX'
	}
	FLAGS = { 0x10 => 'PIC', 0x20 => 'DYNAMIC' }
	SYMBOL_TYPE = { 0 => 'UNDF', 1 => 'ABS', 2 => 'TEXT',
		3 => 'DATA', 4 => 'BSS', 5 => 'INDR', 6 => 'SIZE',
		9 => 'COMM', 10=> 'SETA', 11=> 'SETT', 12=> 'SETD',
		13=> 'SETB', 14=> 'SETV', 15=> 'FN'
	}

	attr_accessor :endianness, :header, :text, :data, :symbols, :textrel, :datarel

	class Header < SerialStruct
		words :info, :text, :data, :bss, :syms, :entry, :trsz, :drsz
		attr_accessor :magic, :machtype, :flags

		def set_info(aout, info)
			@magic = aout.int_to_hash(info & 0xffff, MAGIC)
			@machtype = aout.int_to_hash((info >> 16) & 0xff, MACHINE_TYPE)
			@flags = aout.bits_to_hash((info >> 24) & 0xff, FLAGS)
		end
		def get_info(aout)
			(aout.int_from_hash(@magic, MAGIC) & 0xffff) |
			((aout.int_from_hash(@machtype, MACHINE_TYPE) & 0xff) << 16) |
			((aout.bits_from_hash(@flags, FLAGS) & 0xff) << 24)
		end

		def decode(aout)
			super

			set_info(aout, @info)
			@info = nil
			case @magic
			when 'OMAGIC', 'NMAGIC', 'ZMAGIC', 'QMAGIC'
			else raise InvalidExeFormat, "Bad A.OUT signature #@magic"
			end
		end

		def set_default_values(aout)
			@magic ||= 'QMAGIC'
			@machtype ||= 'PC386'
			@flags ||= 0
			@info ||= get_info(aout)
			@text ||= aout.text.length + (@magic == 'QMAGIC' ? 32 : 0) if aout.text
			@data ||= aout.data.length if aout.data

			super
		end
	end

	class Relocation < SerialStruct
		attr_accessor :symbolnum, :pcrel, :length, :extern, :baserel, :jmptable, :relative, :rtcopy
		words :address, :info

		def get_info(aout)
			(@symbolnum & 0xffffff) |
			((pcrel    ? 1 : 0) << 24) |
			(({1=>0, 2=>1, 4=>2, 8=>3}[@length] || 0) << 25) |
			((extern   ? 1 : 0) << 27) |
			((baserel  ? 1 : 0) << 28) |
			((jmptable ? 1 : 0) << 29) |
			((relative ? 1 : 0) << 30) |
			((rtcopy   ? 1 : 0) << 31)
		end
		def set_info(aout, info)
			@symbolnum = info & 0xffffff
			@pcrel    = (info[24] == 1)
			@length = 1 << ((info >> 25) & 3)
			@extern   = (info[27] == 1)
			@baserel  = (info[28] == 1)
			@jmptable = (info[29] == 1)
			@relative = (info[30] == 1)
			@rtcopy   = (info[31] == 1)
		end

		def decode(aout)
			super

			set_info(aout, @info)
			@info = nil
		end

		def set_default_values(aout)
			@length ||= 4
			@symbolnum ||= 0
			@info ||= get_info(aout)

			super
		end
	end

	class Symbol < SerialStruct
		word :name_p
		bytes :info, :other
		half :desc
 		word :value
		attr_accessor :extern, :type, :stab
		attr_accessor :name

		def get_info(aout)
			(extern ? 1 : 0) |
			((aout.int_from_hash(@type, SYMBOL_TYPE) & 0xf) << 1) |
			((@stab & 7) << 5)
		end
		def set_info(aout, info)
			@extern = (info[0] == 1)
			@type = aout.int_to_hash((info >> 1) & 0xf, SYMBOL_TYPE)
			@stab = (info >> 5) & 7
		end

		def decode(aout, strings=nil)
			super(aout)
			set_info(aout, @info)
			@info = nil
			@name = strings[@name_p...(strings.index(0, @name_p))] if strings
		end

		def set_default_values(aout, strings=nil)
			if strings and @name and @name != ''
				if not @name_p or strings[@name_p, @name.length] != @name
					@name_p = strings.length
					strings << @name << 0
				end
			end

			@type ||= 0
			@stab ||= 0
			@info ||= get_info(aout)
			super
		end
	end

	def decode_byte(edata = @encoded) edata.decode_imm(:u8 , @endianness) end
	def decode_half(edata = @encoded) edata.decode_imm(:u16, @endianness) end
	def decode_word(edata = @encoded) edata.decode_imm(:u32, @endianness) end
	def encode_byte(w) Expression[w].encode(:u8 , @endianness) end
	def encode_half(w) Expression[w].encode(:u16, @endianness) end
	def encode_word(w) Expression[w].encode(:u32, @endianness) end

	def initialize(cpu = nil)
		@endianness = cpu ? cpu.endianness : :little
		@header = Header.new
		@text = EncodedData.new
		@data = EncodedData.new
		super
	end

	def decode_header
		@encoded.ptr = 0
		@header.decode(self)
	end

	def decode
		decode_header

		tlen = @header.text
		case @header.magic
		when 'ZMAGIC'; @encoded.ptr = 1024
		when 'QMAGIC'; tlen -= 32	# header is included in .text
		end
		@text = EncodedData.new << @encoded.read(tlen)

		@data = EncodedData.new << @encoded.read(@header.data)

		textrel = @encoded.read @header.trsz
		datarel = @encoded.read @header.drsz
		syms    = @encoded.read @header.syms
		strings = @encoded.read
		# TODO
	end

	def encode
		# non mmapable on linux anyway
		# could support OMAGIC..
		raise EncodeError, 'cannot encode non-QMAGIC a.out' if @header.magic and @header.magic != 'QMAGIC'

		# data must be 4096-aligned
		# 32 bytes of header included in .text
		@text.virtsize = (@text.virtsize + 32 + 4096 - 1) / 4096 * 4096 - 32
		if @data.rawsize % 4096 != 0
			@data[(@data.rawsize + 4096 - 1) / 4096 * 4096 - 1] = 0
		end

		@header.text = @text.length+32
		@header.data = @data.rawsize
		@header.bss = @data.virtsize - @data.rawsize

		@encoded = EncodedData.new
		@encoded << @header.encode(self)
		binding = @text.binding(4096+32).merge @data.binding(4096 + @header.text)
		@encoded << @text << @data
		@encoded.fixup! binding
		@encoded.data
	end

	def parse_init
		@textsrc ||= []
		@datasrc ||= []
		@cursource ||= @textsrc
		super
	end

	def parse_parser_instruction(instr)
		case instr.raw.downcase
		when '.text'; @cursource = @textsrc
		when '.data'; @cursource = @datasrc
		when '.entrypoint'
			# ".entrypoint <somelabel/expression>" or ".entrypoint" (here)
			@lexer.skip_space
			if tok = @lexer.nexttok and tok.type == :string
				raise instr if not entrypoint = Expression.parse(@lexer)
			else
				entrypoint = new_label('entrypoint')
				@cursource << Label.new(entrypoint, instr.backtrace.dup)
			end
			@header.entry = entrypoint
		else super
		end
	end

	def assemble
		@text << assemble_sequence(@textsrc, @cpu)
		@textsrc.clear
		@data << assemble_sequence(@datasrc, @cpu)
		@datasrc.clear
		self
	end

	def each_section
		tva = 0
		tva = 4096+32 if @header.magic == 'QMAGIC'
		yield @text, tva
		yield @data, tva + @text.virtsize
	end
end
end
