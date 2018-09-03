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
		 -0x10 => 'anyfunc', -0x20 => 'func', -0x40 => 'none' }

	EXTERNAL_KIND = { 0 => 'function', 1 => 'table', 2 => 'memory', 3 => 'global' }

	# begin WTF
	OPCODE_IMM_COUNT = Hash.new(0)
	[2, 3, 4, 0xc, 0xd, 0x10].each { |op| OPCODE_IMM_COUNT[op] = 1 }
	OPCODE_IMM_COUNT[0x11] = 2
	(0x20..0x24).each { |op| OPCODE_IMM_COUNT[op] = 1 }
	(0x28..0x3e).each { |op| OPCODE_IMM_COUNT[op] = 2 }
	(0x3f..0x42).each { |op| OPCODE_IMM_COUNT[op] = 1 }
	# 0x43 followed by uint32, 0x44 followed by uint64 (float constants)
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
			super(exe)
			@raw_offset = exe.encoded.ptr
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
		out = EncodedData.new
		while v > 0x7f or v < -0x40 or (signed and v > 0x3f)
			out << Expression[0x80 | (v&0x7f)].encode(:u8, @endianness)
			v >>= 7
		end
		out << Expression[v & 0x7f].encode(:u8, @endianness)
	end
	def decode_uleb(ed = @encoded, signed=false)
		v = s = 0
		while s < 10*7
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
		:element, :function_body, :data, :code_info

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

	# return the nth global
	# use the @global array and the @import array
	def get_global_nr(nr)
		glob_imports = @import.to_a.find_all { |i| i[:kind] == 'global' }
		return glob_imports[nr] if nr < glob_imports.length
		nr -= glob_imports.length
		@global[nr]
	end

	# return the nth function body
	# use the @function_body array and the @import array
	def get_function_nr(nr)
		func_imports = @import.to_a.find_all { |i| i[:kind] == 'function' }
		return func_imports[nr] if nr < func_imports.length
		nr -= func_imports.length
		@function_body[nr]
	end

	def type_to_s(t)
		return t unless t.kind_of?(::Hash)
		(t[:ret].map { |tt| type_to_s(tt) }.join(', ') << ' f(' << t[:params].map { |tt| type_to_s(tt) }.join(', ') << ')').strip
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

		while op = edata.decode_imm(:u8, @endianness)
			case op
			when 0xb
				# end opcode
				return raw_offset
			when 0xe
				# indirect branch wtf
				decode_uleb(edata).times { decode_uleb(edata) }
				decode_uleb(edata)
			when 0x43
				edata.read(4)
			when 0x44
				edata.read(8)
			else
				OPCODE_IMM_COUNT[op].times { decode_uleb(edata) }
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
			@encoded.add_export(new_label("module_#{m.id}"), m.raw_offset)
			f = "decode_module_#{m.id.to_s.downcase}"
			send(f, m) if respond_to?(f)
		}
		func_imports = @import.to_a.find_all { |i| i[:kind] == 'function' }
		export.to_a.each { |e|
			next if e[:kind] != 'function'	# TODO resolve init_offset for globals etc?
			idx = e[:index] - func_imports.length
			next if not fb = function_body.to_a[idx]
			@encoded.add_export(new_label(e[:field]), fb[:init_offset], true)
		}
		# bytecode start addr => { :local_var => [], :params => [], :ret => [] }
		# :local_var absent for external code (imported funcs)
		@code_info = {}
		import.to_a.each { |i|
			next unless i[:kind] == 'function'
			@code_info["#{i[:module]}_#{i[:field]}"] = { :params => i[:type][:params], :ret => i[:type][:ret] }
		}
		function_body.to_a.each { |fb|
			@code_info[fb[:init_offset]] = { :local_var => fb[:local_var], :params => fb[:type][:params], :ret => fb[:type][:ret] }
		}
		global_idx = import.to_a.find_all { |i| i[:kind] == 'global' }.length - 1
		global.to_a.each { |g|
			@code_info[g[:init_offset]] = { :local_var => [], :params => [], :ret => [g[:type]] }
			@encoded.add_export new_label("global_#{global_idx += 1}_init"), g[:init_offset]
		}
		element.to_a.each { |e|
			@code_info[e[:init_offset]] = { :local_var => [], :params => [], :ret => ['i32'] }
		}
		data.to_a.each { |d|
			@code_info[d[:init_offset]] = { :local_var => [], :params => [], :ret => ['i32'] }
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
			i = {}
			i[:module] = m.edata.read(decode_uleb(m.edata))
			i[:field] = m.edata.read(decode_uleb(m.edata))
			kind = decode_uleb(m.edata)
			i[:kind] = EXTERNAL_KIND[kind] || kind
			case i[:kind]
			when 'function'
				i[:type] = @type[decode_uleb(m.edata)]	# XXX keep index only, in case @type is not yet known ?
			when 'table'
				i[:type] = decode_type(m.edata)
				i[:limits] = decode_limits(m.edata)
			when 'memory'
				i[:limits] = decode_limits(m.edata)
			when 'global'
				i[:type] = decode_type(m.edata)
				i[:mutable] = decode_uleb(m.edata)
			end
			@import << i
		}
	end

	def decode_module_function(m)
		@function_signature = []
		idx = 0
		decode_uleb(m.edata).times {
			@function_signature << @type[decode_uleb(m.edata)]
			@function_body[idx][:type] = @function_signature[idx] if function_body
			idx += 1
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
			@global << { :type => decode_type(m.edata), :mutable => decode_uleb(m.edata), :init_offset => read_code_until_end(m) }
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
		idx = 0
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
			@function_body.last[:type] = @function_signature[idx] if function_signature
			@encoded.add_export new_label("function_#{@function_body.length-1}"), @function_body.last[:init_offset]
			idx += 1
		}
	end

	def decode_module_data(m)
		@data = []
		decode_uleb(m.edata).times {
			idx = decode_uleb(m.edata)
			initoff = read_code_until_end(m)
			data_len = decode_uleb(m.edata)
			data_start_ptr = m.raw_offset + m.edata.ptr
			data = m.edata.read(data_len)
			data_end_ptr = m.raw_offset + m.edata.ptr

			@data << { :index => idx, :init_offset => initoff, :data => data }
			@encoded.add_export new_label("data_#{@data.length-1}_init_addr"), initoff
			@encoded.add_export new_label("data_#{@data.length-1}_start"), data_start_ptr
			@encoded.add_export new_label("data_#{@data.length-1}_end"), data_end_ptr
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
		function_body.to_a.each { |fb|
			v = []
			fb[:local_var].map { |lv| type_to_s(lv) }.each { |lv|
				v.last && lv == v.last.last ? v.last << lv : v << [lv]
			}
			v.map! { |sublist|
				# i32 ; i32 ; i32 ; i32 ; i32 ; i32 ; i64  ->  5 * i32 ; i64
				sublist.length > 3 ? "#{sublist.length} * #{sublist.first}" : sublist.join(' ; ')
			}
			dasm.add_comment fb[:init_offset], "proto: #{fb[:type] ? type_to_s(fb[:type]) : 'unknown'}"
			dasm.add_comment fb[:init_offset], "vars: #{v.join(' ; ')}"
		}
		global.to_a.each { |g|
			dasm.add_comment g[:init_offset], "type: #{type_to_s(g[:type])}"
		}
		dasm.function[:default] = @cpu.disassembler_default_func
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
