module Metasm

# superclass for all metasm exceptions
class Exception < RuntimeError ; end

# holds context of a processor
# endianness, current mode, opcode list...
class CPU
	attr_reader :valid_args, :valid_props, :fields_mask, :opcode_list
	attr_reader :endianness, :size

	def initialize
		@fields_mask = {}
		@valid_args  = []
		@valid_props = []
		@opcode_list = []
	end
end

# a specific cpu instruction description
class Opcode
	# formal arguments
	attr_reader :name, :args
	# binary string, and fields within (fields class used change if cpu is fixed len or variable len)
	attr_accessor :bin, :fields
	# generic attributes/restrictions
	attr_reader :props

	def initialize(cpu, name)
		@cpu = cpu
		@name = name
		@args = []
		@fields = {}
		@props = {}
	end
end

# a name for a location
class Label
	attr_reader :name
	def initialize(name)
		@name = name
	end
end

# an instruction: opcode name + arguments
class Instruction
	# +@args+ is an array of arguments (cpu-specific classes)
	# +@pfx+  is a hash of present prefixes (Symbol)
	# +@opname+ the name of the instruction mnemonic (String)
	attr_reader :args, :pfx
	attr_accessor :opname
	def initialize(opname=nil, args=[], pfx={})
		@pfx, @args = pfx, args
		@opname = opname
	end

	def dup
		Instruction.new((@opname.dup rescue @opname), @args.dup, @pfx.dup)
	end
end

# all kind of data (incl. repeated/uninitialized)
class Data
	INT_TYPE = {:db => :u8, :dw => :u16, :dd => :u32}
	Uninitialized = :udata

	attr_reader :data, :type, :count
	# +@data+ is either an +Expression+, an Array of +Data+, a String, or Uninitialized
	def initialize(type, data, count=1)
		@data, @type, @count = data, type, count
	end
end

class Align
	attr_reader :val
	def initialize(val)
		@val = val
	end
end

# represents an executable section
# ie no holes, same permissions
class Section
	# +@name+
	# +@encoded+ EncodedData
	# +@source+  +Array+ of +Label+/+Instruction+/+Data+
	attr_reader :name, :source, :encoded
	# +@mprot+   memory protection (Array [:read, :write, :exec])
	# +@base+    absolute base adress wanted
	# +@align+   base adress must be a multiple of that (octets)
	attr_accessor :mprot, :base, :align
	
	# XXX dynamic label insertion when disassembling..
	
	def initialize(program, name)
		@program = program
		@name    = name
		@source  = []
		@mprot   = [:read]
		@encoded = EncodedData.new
		@base = @align = nil
	end
	def <<(a) @source << a end
end

class Program
	# sections = array of Section
	# export = hash exportedname => label     XXX could be Export - function, data, int, ...
	# import = hash libname      => [imported list]
	attr_reader :cpu, :sections, :export, :import
	def initialize(cpu)
		@cpu = cpu
		@sections = []
		@export = {}
		@import = {}
	end
end

# handle immediate values
class Expression
	# TODO floats
	INT_SIZE = {:u8 => 8,    :u16 => 16,     :u32 => 32,
		    :i8 => 8,    :i16 => 16,     :i32 => 32
	}
	INT_MIN  = {:u8 => 0,    :u16 => 0,      :u32 => 0,
		    :i8 =>-0x80, :i16 =>-0x8000, :i32 =>-0x80000000
	}
	INT_MAX  = {:u8 => 0xff, :u16 => 0xffff, :u32 => 0xffffffff,
		    :i8 => 0x7f, :i16 => 0x7fff, :i32 => 0x7fffffff
	}

	# alternative constructor: Expression[[:-, 42], :*, [1, :+, [4, :*, 7]]]
	def self.[](l, op = nil, r = nil)
		l, op, r = nil, :+, l if not op
		l, op, r = nil, l, op if not r
		l = self[*l] if l.kind_of? Array
		r = self[*r] if r.kind_of? Array
		new(op, r, l)
	end


	# XXX -1 could be a valid u32
	def self.in_range?(val, type)
		val = val.reduce if val.kind_of? self
		return unless val.kind_of? Numeric

		case type
		when :u8, :u16, :u32, :i8, :i16, :i32
			val == val.to_i and
			val >= INT_MIN[type] and val <= INT_MAX[type]
		end
	end

	attr_accessor :op, :lexpr, :rexpr
	# !! args reversed
	def initialize(op, rexpr, lexpr)
		@op, @lexpr, @rexpr = op, lexpr, rexpr
	end

	def ==(o)
		# shortcircuit recursion
		o.object_id == object_id or (o.class == self.class and [o.op, o.rexpr, o.lexpr] == [@op, @rexpr, @lexpr])
	end

	def bind(vals = {})
		l, r = @lexpr, @rexpr
		if l.kind_of?(Expression)
			l = l.bind(vals)
		else
			l = vals.fetch(l, l)
		end
		if r.kind_of?(Expression)
			r = r.bind(vals)
		else
			r = vals.fetch(r, r)
		end
		Expression[l, @op, r]
	end

	def externals
		[@rexpr, @lexpr].inject([]) { |a, e|
			case e
			when Expression: a.concat e.externals
			when nil, Numeric: a
			else a << e
			end
		}
	end

	def inspect
		"(#{@lexpr.inspect if @lexpr} #@op #{@rexpr.inspect})"
	end
end

class Relocation
	attr_accessor :type, :target, :endianness
	# +@target+ what the relocation points to (Expression)
	# +@type+   relocation field type (:u8, :i32 ..)
	def initialize(target, type, endianness)
		@target     = target
		@type       = type
		@endianness = endianness
	end
end

class EncodedData
	attr_reader :data, :reloc, :export
	attr_accessor :virtsize
	# +@data+     string with binary data
	# +@reloc+   hash: key = offset, value = +Relocation+
	# +@export+  hash: key = name, value = offset
	# +@virtsize+ total data virtual size (+Integer+)
	def initialize(data = '', opts={})
		@data = data
		@reloc   = opts[:reloc]   || {}
		@export  = opts[:export]  || {}
		@virtsize = opts[:virtsize] || @data.length
	end

	def dup
		self.class.new @data.dup, :reloc => @reloc.dup, :export => @export.dup, :virtsize => @virtsize
	end
end
end # module Metasm
