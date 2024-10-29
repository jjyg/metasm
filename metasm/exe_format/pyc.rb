#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'


module Metasm
# Python preparsed module (.pyc)
class PYC < ExeFormat
	# 1 magic per python version, header fmt changes with time...
	# file = MAGIC(u16) \r \n <u32> [<u32>] [<u32>] <marshal encoded code object>
	# see python3src/Lib/importlib/_bootstrap_external.py, Python/marshal.c
	MAGICS = [
		20121,	# python1.5
		50428,	# python1.6
		60202,	# python2.1
		62011,	# python2.3
		62211,  # python2.7
		3000,	# python3.0
		3370,	# python3.6 16 bytes opcodes
		3392,	# python3.7 deterministic pyc
		3413,   # python3.8
		3570,	# python3.13
	]

	class Header < SerialStruct
		half :version
		half :rn
		attr_accessor :flags, :timestamp, :hash, :sourcesz
	end

	attr_accessor :refs

	# return the python version according to the magic
	# TODO find more precise values
	def py_version
		ver = @header.version
		@py_version ||=
			if    ver <  3000
				0
			elsif ver <  3370
				0x03000000
			elsif ver <  3392
				0x03060000
			elsif ver <  3413
				0x03070000
			elsif ver <  3570
				0x03080000
			elsif ver < 20000
				0x030D0000
			elsif ver < 50000
				0x01050000
			elsif ver < 60000
				0x01060000
			elsif ver < 62011
				0x02010000
			elsif ver < 62211
				0x02030000
			else
				0x02070000
			end
	end

	def decode_byte(edata=@encoded) edata.decode_imm(:u8,  @endianness) end
	def decode_half(edata=@encoded) edata.decode_imm(:u16, @endianness) end
	def decode_word(edata=@encoded) edata.decode_imm(:u32, @endianness) end
	def decode_long(edata=@encoded) edata.decode_imm(:i32, @endianness) end
	def sizeof_byte ; 1 ; end
	def sizeof_half ; 2 ; end
	def sizeof_word ; 4 ; end
	def sizeof_long ; 4 ; end

	# file header
	attr_accessor :header
	# the marshalled object
	attr_accessor :root
	# list of all code objects
	attr_accessor :all_code

	def initialize()
		@endianness = :little
		@encoded = EncodedData.new
		super()
	end

	def decode_header
		@header = Header.decode(self)
		if py_version < 0x03070000
			# pre 3.7: 12b header
			@header.timestamp = decode_word
			@header.sourcesz = decode_word
		elsif py_version < 0x03000000
			# pre 3.X ?: 8b header
			@header.timestamp = decode_word
		else
			# post 3.7: 16b header
			@header.flags = decode_word
			@header.timestamp = decode_word
			@header.sourcesz = decode_word
			# depending on flags, ts/sz may be srchash
		end
		@header
	end

	def decode_pymarshal
		pre_off = @encoded.ptr
		c_full = decode_byte
		c = c_full & 0x7f
		c_flags = c_full & 0x80
		puts "#{'%x' % (pre_off)}  #{'%02X' % c_full} #{c.chr.inspect}" if $DEBUG
		ret = { :off => pre_off, :chr => c_full }
		case c.chr
		when '0' # NULL
			ret[:type] = :null
		when 'N' # None
			ret[:type] = :none
		when 'F' # False
			ret[:type] = :false
		when 'T' # True
			ret[:type] = :true
		when 'S' # stopiter
			ret[:type] = :stopiter
		when '.' # ellipsis
			ret[:type] = :ellipsis
		when 'i' # long (i32)
			ret[:type] = :integer
			ret[:value] = decode_long
		when 'I' # long (i64)
			ret[:type] = :integer
			ret[:value] = decode_word | (decode_long << 32)
		when 'f' # float (ascii)
			ret[:type] = :float
			ret[:value] = @encoded.read(decode_byte).to_f
		when 'g' # float (binary)
			ret[:type] = :float
			ret[:value] = @encoded.read(8).unpack('d').first	# XXX check unpack
		when 'x' # complex (f f)
			ret[:type] = :complex	# [real, img]
			ret[:value] = [@encoded.read(decode_byte).to_f, @encoded.read(decode_byte).to_f]
		when 'y' # complex (g g)
			ret[:type] = :complex
			ret[:value] = [@encoded.read(8).unpack('d').first, @encoded.read(8).unpack('d').first]
		when 'l' # long (i32?)
			ret[:type] = :integer
			ret[:value] = decode_long
		when 's', 't' # string, interned: len (long), data
			ret[:type] = :string
			ret[:value] = @encoded.read(decode_long)
		when 'r', 'R' # backreference
			idx = decode_long
			ret[:type] = :ref
			ret[:ref_idx] = idx
			ret[:value] = @refs[idx]
		when '(', '[', '<', '>'	# tuple, list, set, frozenset: length l*objs
			ret[:type] = case c.chr
			when '('; :tuple
			when '['; :list
			when '<', '>'; :set
			end
			ret[:value] = (0...decode_long).map { decode_pymarshal }
		when ')'	# short tuple
			ret[:type] = :tuple
			ret[:value] = (0...decode_byte).map { decode_pymarshal }
		when '{' # dict (Hash)
			ret[:type] = :hash
			ret[:value] = {}
			loop do
				k = decode_pymarshal
				break if k[:type] == :null
				ret[:value][k] = decode_pymarshal
			end
		when 'c' # code
			# XXX format varies with python version
			ret[:type] = :code
			if c_flags & 0x80 > 0
				# pre-reserve backref slot
				@refs << ret
				c_flags = 0	# dont re-register ref in footer
			end
			ret[:argcount] = decode_long
			ret[:posonly_argcount] = decode_long if py_version >= 0x03080000 # > 3401
			ret[:kwonly_argcount] = decode_long  if py_version >= 0x03000000 # > 3020
			ret[:nlocals] = decode_long
			ret[:stacksize] = decode_long
			ret[:flags] = decode_long	# TODO bit-decode this one

			ret[:codeoff] = @encoded.ptr + 5	# XXX assume :code is a 's'
			ret[:code] = decode_pymarshal
			ret[:codelen] = to_rb(ret[:code]).length
			ret[:consts] = decode_pymarshal
			ret[:names] = decode_pymarshal
			ret[:varnames] = decode_pymarshal
			ret[:freevars] = decode_pymarshal
			ret[:cellvars] = decode_pymarshal
			ret[:filename] = decode_pymarshal
			ret[:name] = decode_pymarshal
			ret[:firstlineno] = decode_long
			ret[:lnotab] = decode_pymarshal
			@all_code << ret
                        name = to_rb(ret[:name])
                        label_at(@encoded, ret[:codeoff], name) if name.kind_of?(String)
                        ret[:value] = "<code #{name.inspect} #{Expression[pre_off]}>"
		when '?' # unknown
			ret[:type] = :unknown
		when 'u', 'a', 'A'	# unicode, ascii
			ret[:type] = :string
			ret[:value] = @encoded.read(decode_long)
		when 'z', 'Z'	# short ascii
			ret[:type] = :string
			ret[:value] = @encoded.read(decode_byte)
		else
			raise "unsupported python marshal #{c.chr.inspect} near #{pre_off}"
		end
		@refs << ret if c_flags & 0x80 > 0
		ret
	end

	# convert a deserialized object to a native ruby one (eg tuple => actual array of values)
	def to_rb(obj=@root)
		return obj if not obj.kind_of?(Hash)
		case obj[:type]
		when :tuple, :set, :list
			obj[:value].map { |o| to_rb(o) }
		when :hash
			ret = {}
			obj[:value].each { |k, v|
				ret[to_rb(k)] = to_rb(v)
			}
			ret
		when :integer, :string
			obj[:value]
		when :ref
			to_rb(obj[:value])
		else
			ret = {}
			obj.each { |k, v|
				next if k == :chr or k == :off
				ret[k] = to_rb(v)
			}
			ret
		end
	end

	def decode
		decode_header
		@all_code = []
		@refs = []
		@root = decode_pymarshal
	end

	def cpu_from_headers
		Python.new(self)
	end

	def each_section
		yield @encoded, 0
	end

	def get_default_entrypoints
		@all_code.map { |c| c[:codeoff] }
	end

	# return the :code part which contains off
	def pycode_at_off(off)
		@all_code.find { |c| c[:codeoff] <= off and c[:codeoff] + c[:codelen] > off }
	end
end
end
