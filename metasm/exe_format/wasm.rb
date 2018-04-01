#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'


module Metasm
# WebAssembly
# leb integer encoding taken from dex.rb
class WASM < ExeFormat
	MAGIC = "\0asm"
	MAGIC.force_encoding('binary') if MAGIC.respond_to?(:force_encoding)

	SECTION_NAME = { 1 => 'Type', 2 => 'Import', 3 => 'Function', 4 => 'Table',
		         5 => 'Memory', 6 => 'Global', 7 => 'Export', 8 => 'Start',
			 9 => 'Element', 10 => 'Code', 11 => 'Data' }

	TYPE = { -1 => 'i32', -2 => 'i64', -3 => 'f32', -4 => 'f64',
		 -0x10 => 'anyfunc', -0x20 => 'func', -0x40 => 'block' }


	class SerialStruct < Metasm::SerialStruct
		# TODO move uleb/sleb to new_field for sizeof
		new_int_field :u4, :uleb, :sleb
	end

	class Header < SerialStruct
		mem :sig, 4, MAGIC
		decode_hook { |exe, hdr| raise InvalidExeFormat, "E: invalid WASM signature #{hdr.sig.inspect}" if hdr.sig != MAGIC }
		u4 :ver, 1
	end

	class Module < SerialStruct
		uleb :id
		fld_enum :id, SECTION_NAME
		uleb :payload_len
		# if id == 0, this in not a well-known module, then the name is encoded here (uleb name length + actual name)
		# payload_len counts this field in the payload
		#new_field(:name, lambda { |exe, hdr| exe.encoded.read(exe.decode_uleb) if hdr.id == 0 }, lambda { |exe, hdr, val| exe.encode_uleb(val.length) + val if hdr.id == 0 }, lambda { |exe, hdr| hdr.id == 0 ? 0 : 1 }, 0)
		attr_accessor :payload

		def decode(exe)
			super(exe)
			@payload = exe.encoded[exe.encoded.ptr, @payload_len]
			exe.encoded.ptr += @payload_len
		end
	end

	class TypeEntry
		def self.decode(exe, edata)
			t = new
			t.decode(exe, edata)
			t
		end

		attr_accessor :type, :params, :ret

		def decode(exe, edata)
			form = exe.decode_sleb(edata)
			@type = TYPE[form] || "unk_type_#{form}"
			if @type == 'func'
				@params = []
				exe.decode_uleb(edata).times {
					@params << TypeEntry.decode(exe, edata)
				}
				@ret = []
				exe.decode_uleb(edata).times {
					@ret << TypeEntry.decode(exe, edata)
				}
			end
		end

		def to_s
			if @type == 'func'
				ret = @ret.join(', ')
				ret << ' ' if not ret.empty?
				ret << @type
				ret << '('
				ret << @params.join(', ')
				ret << ')'
			else @type
			end
		end
	end

	attr_accessor :endianness

	def encode_u4(val) Expression[val].encode(:u32, @endianness) end
	def decode_u4(edata = @encoded) edata.decode_imm(:u32, @endianness) end
	def sizeof_u4 ; 4 ; end
	def encode_uleb(val)
		v = val
		out = Expression[v & 0x7f].encode(:u8, @endianness)
		v >>= 7
		while v > 0 or v < -1
			out = Expression[0x80 | (v & 0x7f)].encode(:u8, @endianness) << out
			v >>= 7
		end
		out
	end
	def decode_uleb(ed = @encoded, signed=false)
		v = s = 0
		while s < 5*7
			b = ed.read(1).unpack('C').first.to_i
			v |= (b & 0x7f) << s
			s += 7
			break if (b&0x80) == 0
		end
		v = Expression.make_signed(v, s) if signed
		v
	end
	def encode_sleb(val) encode_uleb(val) end
	def decode_sleb(ed = @encoded) decode_uleb(ed, true) end
	attr_accessor :header, :modules, :type, :import

	def initialize(endianness=:little)
		@endianness = endianness
		@encoded = EncodedData.new
		super()
	end

	def decode_header
		@header = Header.decode(self)
		@modules = []
	end

	def decode
		decode_header
		while @encoded.ptr < @encoded.length
			@modules << Module.decode(self)
		end
		@modules.each { |m|
			f = "decode_module_#{m.id.to_s.downcase}"
			send(f, m) if respond_to?(f)
		}
	end

	def decode_module_type(m)
		@type = []
		decode_uleb(m.payload).times {
			@type << TypeEntry.decode(self, m.payload)
		}
	end

	def cpu_from_headers
		WasmCPU.new(self)
	end

	def each_section
		yield @encoded, 0
	end

	def get_default_entrypoints
		[]
	end
end
end
