#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'
begin
	require 'zlib'
rescue LoadError
end

module Metasm
class SWF < ExeFormat
	attr_accessor :signature, :version, :header, :chunks

	class SerialStruct < Metasm::SerialStruct
		new_int_field :u8, :u16, :u32, :f16, :f32
	end

	class Rectangle < SerialStruct
		attr_accessor :nbits, :xmin, :xmax, :ymin, :ymax

		def decode(swf)
			byte = swf.decode_u8
			consumd = 5
			@nbits = byte >> 3
			@xmin, @xmax, @ymin, @ymax = (0..3).map {
				nb = @nbits
				v = 0
				while nb > 0
					if consumd == 8
						consumd = 0
						byte = swf.decode_u8
					end
					w = [8-consumd, nb].min
					v <<= w
					v |= (byte >> (8-(consumd+w))) & ((1<<w)-1)
					consumd += w
					nb -= w
				end
				Expression.make_signed(v, @nbits)
			}
		end
	end

	class Header < SerialStruct
		attr_accessor :view
		u16 :framerate	# XXX bigendian...
		u16 :framecount

		def decode(swf)
			@view = Rectangle.decode(swf)
			super(swf)
			@framerate = ((@framerate >> 8) & 0xff) | ((@framerate & 0xff) << 8)
		end
	end

	class Chunk < SerialStruct
		bitfield :u16, 0 => :length, 6 => :tag
		attr_accessor :data

		def decode(swf)
			super(swf)
			@length = swf.decode_u32 if @length == 0x3f
			@data = swf.encoded.read(@length)
			@data = @data[0, 256]
		end
	end

	def decode_u8( edata=@encoded) edata.decode_imm(:u8,  @endianness) end
	def decode_u16(edata=@encoded) edata.decode_imm(:u16, @endianness) end
	def decode_u32(edata=@encoded) edata.decode_imm(:u32, @endianness) end
	def decode_f16(edata=@encoded) edata.decode_imm(:i16, @endianness)/256.0 end
	def decode_f32(edata=@encoded) edata.decode_imm(:i32, @endianness)/65536.0 end
	def encode_u8(w)  Expression[w].encode(:u8,  @endianness) end
	def encode_u16(w) Expression[w].encode(:u16, @endianness) end
	def encode_u32(w) Expression[w].encode(:u32, @endianness) end
	def encode_f16(w) Expression[(w*256).to_i].encode(:u16, @endianness) end
	def encode_f32(w) Expression[(w*65536).to_i].encode(:u32, @endianness) end

	def initialize(cpu = nil)
		@endianness = :little
		@header = Header.new
		@chunks = []
		super(cpu)
	end

	def decode_header
		@signature = @encoded.read(3)
		@version = decode_u8
		@data_length = decode_u32
		case @signature
		when 'FWS'
		when 'CWS'
			# data_length = uncompressed data length
			data = @encoded.read(@encoded.length-8)
			data = Zlib::Inflate.inflate(data)
			@encoded = EncodedData.new(data)
		else raise InvalidExeFormat, "Bad signature #{@signature.inspect}"
		end
		@data_length = [@data_length, @encoded.length].min
		@header = Header.decode(self)
	end

	def decode
		decode_header
		while @encoded.ptr < @data_length
			@chunks << Chunk.decode(self)
		end
	end
end
end
