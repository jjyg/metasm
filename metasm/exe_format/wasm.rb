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
class WasmFile < ExeFormat
	MAGIC = "\0asm"
	MAGIC.force_encoding('binary') if MAGIC.respond_to?(:force_encoding)

	SECTION_NAME = { 1 => 'Type', 2 => 'Import', 3 => 'Function', 4 => 'Table',
		         5 => 'Memory', 6 => 'Global', 7 => 'Export', 8 => 'Start',
			 9 => 'Element', 10 => 'Code', 11 => 'Data' }

	TYPE = { -1 => 'i32', -2 => 'i64', -3 => 'f32', -4 => 'f64',
		 -0x10 => 'anyfunc', -0x20 => 'func', -0x40 => 'block' }

	EXTERNAL_KIND = { 0 => 'function', 1 => 'table', 2 => 'memory', 3 => 'global' }

	# begin WTF
	OPCODE_IMM_COUNT = Hash.new(0)
	[2, 3, 4, 0xc, 0xd, 0x10].each { |op| OPCODE_IMM_COUNT[op] = 1 }
	OPCODE_IMM_COUNT[0x11] = 2
	(0x20..0x24).each { |op| OPCODE_IMM_COUNT[op] = 1 }
	(0x28..0x3e).each { |op| OPCODE_IMM_COUNT[op] = 2 }
	(0x3f..0x44).each { |op| OPCODE_IMM_COUNT[op] = 1 }
	# end WTF


	class SerialStruct < Metasm::SerialStruct
		# TODO move uleb/sleb to new_field for sizeof
		new_int_field :u4, :uleb, :sleb
	end

	class Header < SerialStruct
		mem :sig, 4, MAGIC
		decode_hook { |exe, hdr| raise InvalidExeFormat, "E: invalid WasmFile signature #{hdr.sig.inspect}" if hdr.sig != MAGIC }
		u4 :ver, 1
	end

	class Module < SerialStruct
		uleb :id
		fld_enum :id, SECTION_NAME
		uleb :payload_len
		attr_accessor :edata, :raw_offset, :name

		def decode(exe)
			@raw_offset = exe.encoded.ptr
			super(exe)
			@edata = exe.encoded[exe.encoded.ptr, @payload_len]
			exe.encoded.ptr += @payload_len
		end
	end

	attr_accessor :endianness

	def encode_u4(val) Expression[val].encode(:u32, @endianness) end
	def decode_u4(edata = @encoded) edata.decode_imm(:u32, @endianness) end
	def sizeof_u4 ; 4 ; end
	def encode_uleb(val, signed=false)
		v = val
		# force_more_bytes: ensure sign bit is not mistaken as value when signed (eg encode 0x40 as 0x80, 0x40 ; not 0x40 (decoded as -0x40))
		force_more_bytes = (signed and v & 0x40 > 0)
		out = Expression[v & 0x7f].encode(:u8, @endianness)
		v >>= 7
		while v > 0 or v < -1 or force_more_bytes
			force_more_bytes = (signed and v & 0x40 > 0)
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
	def encode_sleb(val) encode_uleb(val, true) end
	def decode_sleb(ed = @encoded) decode_uleb(ed, true) end
	attr_accessor :header, :modules, :type, :import, :function_signature,
		:table, :memory, :global, :export, :start_function_index,
		:element, :function_body

	def initialize(endianness=:little)
		@endianness = endianness
		@encoded = EncodedData.new
		super()
	end

	def decode_type(edata=@encoded)
		form = decode_sleb(edata)
		type = TYPE[form] || "unk_type_#{form}"
		if type == 'func'
			type = { :params => [], :ret => [] }
			decode_uleb(edata).times {
				type[:params] << decode_type(edata)
			}
			decode_uleb(edata).times {
				type[:ret] << decode_type(edata)
			}
		end
		type
	end

	def type_to_s(t)
		return t unless t.kind_of?(::Hash)
		t[:ret].map { |tt| type_to_s(tt) }.join(', ') << ' f(' << t[:params].map { |tt| type_to_s(tt) }.join(', ') << ')'
	end

	def decode_limits(edata=@encoded)
		flags = decode_uleb(edata)
		out = { :initial_size => decode_uleb(edata) }
		out[:maximum] = decode_uleb(edata) if flags & 1
		out
	end

	# wtf
	# read wasm bytecode until reaching the end opcode
	# return the byte offset
	def read_code_until_end(m=nil)
		if m
			raw_offset = m.raw_offset + m.edata.ptr
			edata = m.edata
		else
			edata = @encoded
		end

		# XXX uleb / u8 ?
		while op = decode_uleb(edata)
			case op
			when 0xb
				# end opcode
				return raw_offset
			when 0xe
				# indirect branch wtf
				decode_uleb(edata).times { decode_uleb(edata) }
				decode_uleb(edata)
			else
				OPCODE_IMM_COUNT[op].times {
					decode_uleb(edata)
				}
			end
		end
		raw_offset
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
		export.to_a.each { |e|
			next if e[:kind] != 'function'	# TODO resolve init_offset for globals etc?
			off = function_body.to_a[e[:index]]
			@encoded.add_export(new_label(e[:field]), off, true) if off
		}
	end

	def decode_module_type(m)
		@type = []
		decode_uleb(m.edata).times {
			@type << decode_type(m.edata)
		}
	end

	def decode_module_import(m)
		@import = []
		decode_uleb(m.edata).times {
			mod = m.edata.read(decode_uleb(m.edata))
			fld = m.edata.read(decode_uleb(m.edata))
			kind = decode_uleb(m.edata)
			kind = { :kind => EXTERNAL_KIND[kind] || kind }
			case kind[:kind]
			when 'function'
				kind[:type] = @type[decode_uleb(m.edata)]	# XXX keep index only, in case @type is not yet known ?
			when 'table'
				kind[:type] = decode_type(m.edata)
				kind[:limits] = decode_limits(m.edata)
			when 'memory'
				kind[:limits] = decode_limits(m.edata)
			when 'global'
				kind[:type] = decode_type(m.edata)
				kind[:mutable] = decode_uleb(m.edata)
			end

			@import << { :module => mod, :field => fld, :kind => kind }
		}
	end

	def decode_module_function(m)
		@function_signature = []
		decode_uleb(m.edata).times {
			@function_signature << @type[decode_uleb(m.edata)]
		}
	end

	def decode_module_table(m)
		@table = []
		decode_uleb(m.edata).times {
			@table << { :type => decode_type(m.edata), :limits => decode_limits(m.edata) }
		}
	end

	def decode_module_memory(m)
		@memory = []
		decode_uleb(m.edata).times {
			@memory << { :limits => decode_limits(m.edata) }
		}
	end

	def decode_module_global(m)
		@global = []
		decode_uleb(m.edata).times {
			@global << { :type => decode_type(m.edata), :init_offset => read_code_until_end(m) }
			@encoded.add_export new_label("global_#{@global.length-1}_init"), @global.last[:init_offset]
		}
	end

	def decode_module_export(m)
		@export = []
		decode_uleb(m.edata).times {
			flen = decode_uleb(m.edata)
			fld = m.edata.read(flen)
			kind = decode_uleb(m.edata)
			kind = EXTERNAL_KIND[kind] || kind
			index = decode_uleb(m.edata)
			@export << { :field => fld, :kind => kind, :index => index }
		}
	end

	def decode_module_start(m)
		@start_function_index = decode_uleb(m.edata)
	end

	def decode_module_element(m)
		@element = []
		decode_uleb(m.edata).times {
			seg = { :table_index => decode_uleb(m.edata),
				:init_offset => read_code_until_end(m),
				:elems => [] }
			decode_uleb(m.edata).times {
				seg[:elems] << decode_uleb(m.edata) 
			}
			@element << seg
			@encoded.add_export new_label("element_#{@element.length-1}_init_addr"), @element.last[:init_offset]
		}
	end

	def decode_module_code(m)
		@function_body = []
		decode_uleb(m.edata).times {
			local_vars = []
			body_size = decode_uleb(m.edata)	# size of local defs + bytecode (in bytes)
			next_ptr = m.edata.ptr + body_size
			decode_uleb(m.edata).times {		# nr of local vars types
				n_vars_of_this_type = decode_uleb(m.edata)	# nr of local vars of this type
				type = decode_type(m.edata)	# actual type
				n_vars_of_this_type.times {
					local_vars << type
				}
			}
			code_offset = m.raw_offset + m.edata.ptr	# bytecode comes next
			m.edata.ptr = next_ptr
			@function_body << { :local_var => local_vars, :init_offset => code_offset }
			@encoded.add_export new_label("function_#{@function_body.length-1}"), @function_body.last[:init_offset]
		}
	end

	def decode_module_data(m)
		@data = []
		decode_uleb(m.edata).times {
			@data << { :index => decode_uleb(m.edata),
				   :init_offset => read_code_until_end(m),
				   :data => m.edata.read(decode_uleb(m.edata)) }
			@encoded.add_export new_label("data_#{@data.length-1}_init_addr"), @data.last[:init_offset]
		}
	end

	def decode_module_0(m)
		# id == 0 for not well-known modules
		# the module name is encoded at start of payload (uleb name length + actual name)
		m.name = m.edata.read(decode_uleb(m.edata))
		f = "decode_module_0_#{m.name.downcase}"
		send(f, m) if respond_to?(f)
	end

	def decode_module_0_name(m)
		# TODO parse stored names of local variables etc
	end

	def cpu_from_headers
		WebAsm.new(self)
	end

	def init_disassembler
		dasm = super()
		@function_body.each_with_index { |fb, i|
			p = @function_signature[i] if function_signature
			v = fb[:local_var].map { |lv| type_to_s(lv) }.join(' ; ')
			dasm.comment[fb[:init_offset]] = ["proto: #{p || 'unknown'}", "vars: #{v}"]
		}
		dasm
	end

	def each_section
		yield @encoded, 0
	end

	def get_default_entrypoints
		global.to_a.map { |g| g[:init_offset] } +
		element.to_a.map { |e| e[:init_offset] } +
		data.to_a.map { |d| d[:init_offset] } +
		function_body.to_a.map { |f| f[:init_offset] }
	end
end
end
