module Metasm

# superclass for all metasm exceptions
class Exception < RuntimeError ; end

# holds context of a processor
# endianness, current mode, opcode list...
class CPU
	attr_reader :valid_args, :valid_props, :fields_mask, :opcode_list
	attr_reader :endianness, :size
	attr_accessor :opcode_list_byname

	def initialize
		@fields_mask = {}
		@valid_args  = []
		@valid_props = []
		@opcode_list = []
	end

	def opcode_list_byname
		@opcode_list_byname ||= @opcode_list.inject({}) { |h, o| (h[o.name] ||= []) << o ; h }
	end
end

class UnknownCPU < CPU
	def initialize(size, endianness)
		super()
		@size, @endianness = size, endianness
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
	# +@prefix+  is a hash of present prefixes (Symbol)
	# +@opname+ the name of the instruction mnemonic (String)
	attr_reader :args, :prefix, :cpu
	attr_accessor :opname
	def initialize(cpu, opname=nil, args=[], pfx={})
		@cpu = cpu
		@prefix, @args = pfx, args
		@opname = opname
	end

	def dup
		Instruction.new(@cpu, (@opname.dup rescue @opname), @args.dup, @prefix.dup)
	end
end

# contiguous/uninterrupted sequence of instructions, chained to other blocks
class InstructionBlock
	# TODO add content when interface is stable (ie chains through addr or directly etc)
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
	attr_reader :val, :fillwith
	def initialize(val, fillwith=nil)
		@val = val
		@fillwith = fillwith
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
	# graph  = addr => InstructionBlock
	attr_reader :graph
	def initialize(cpu)
		@cpu = cpu
		@sections = []
		@export = {}
		@import = {}
		@graph = {}
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
		return l if l.kind_of? Expression and not op
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
		raise 'invalid arg order' if not op.kind_of? Symbol
		@op, @lexpr, @rexpr = op, lexpr, rexpr
	end

	def ==(o)
		# shortcircuit recursion
		o.object_id == object_id or (o.class == self.class and [o.op, o.rexpr, o.lexpr] == [@op, @rexpr, @lexpr])
	end

	def hash
		[@lexpr, @op, @rexpr].hash
	end
	alias eql? ==

	def bind(vals = {})
		l, r = @lexpr, @rexpr
		if l.respond_to? :bind
			l = l.bind(vals)
		else
			l = vals.fetch(l, l)
		end
		if r.respond_to? :bind
			r = r.bind(vals)
		else
			r = vals.fetch(r, r)
		end
		Expression[l, @op, r]
	end

	def bind!(vals = {})
		if @lexpr.kind_of?(Expression)
			@lexpr.bind!(vals)
		else
			@lexpr = vals.fetch(@lexpr, @lexpr)
		end
		if @rexpr.kind_of?(Expression)
			@rexpr.bind!(vals)
		else
			@rexpr = vals.fetch(@rexpr, @rexpr)
		end
		self
	end

	# try to symplify itself
	# non destructive
	# can return self or another +Expression+ or a +Numeric+
	def reduce
		case e = reduce_rec
		when Expression, Numeric, true, false: e
		else Expression[:+, e]
		end
	end

	def reduce_rec
		l = @lexpr.respond_to?(:reduce_rec) ? @lexpr.reduce_rec : @lexpr
		r = @rexpr.respond_to?(:reduce_rec) ? @rexpr.reduce_rec : @rexpr

		v = 
		if r.kind_of?(Numeric) and (not l or l.kind_of?(Numeric))
			# calculate numerics
			if l
				case @op
				when :'&&': l && r
				when :'||': l || r
				when :'!=': l != r
				else l.send(@op, r)
				end
			else
				case @op
				when :'!': !r
				when :+:  r
				when :-: -r
				when :~: ~r
				end
			end
		elsif @op == :-
			if not l and r.kind_of? Expression and (r.op == :- or r.op == :+)
				if r.op == :- # no lexpr (reduced)
					# -(-x) => x
					r.rexpr
				else # :+ and lexpr (r is reduced)
					# -(a+b) => (-a)+(-b)
					Expression[[:-, r.lexpr], :+, [:-, r.rexpr]].reduce_rec
				end
			elsif l
				# a-b => a+(-b)
				Expression[l, :+, [:-, r]].reduce_rec
			end
		elsif @op == :+
			if not l: r	# +x  => x
			elsif r == 0: l	# x+0 => x
			elsif l.kind_of? Numeric
				if r.kind_of? Expression and r.op == :+
					# 1+(x+y) => x+(y+1)
					Expression[r.lexpr, :+, [r.rexpr, :+, l]].reduce_rec
				else
					# 1+a => a+1
					Expression[r, :+, l].reduce_rec
				end
			elsif l.kind_of? Expression and l.op == :+
				# (a+b)+foo => a+(b+foo)
				Expression[l.lexpr, :+, [l.rexpr, :+, r]].reduce_rec
			else
				# a+(b+(c+(-a))) => b+c+0
				# a+((-a)+(b+c)) => 0+b+c
				neg_l = l.rexpr if l.kind_of? Expression and l.op == :-

				# recursive search & replace -lexpr by 0
				simplifier = proc { |cur|
					if (neg_l and neg_l == cur) or (cur.kind_of? Expression and cur.op == :- and not cur.lexpr and cur.rexpr == l)
						# -l found
						0
					else
						# recurse
						if cur.kind_of? Expression and cur.op == :+
							if newl = simplifier[cur.lexpr]
								Expression[newl, cur.op, cur.rexpr].reduce_rec
							elsif newr = simplifier[cur.rexpr]
								Expression[cur.lexpr, cur.op, newr].reduce_rec
							end
						end
					end
				}

				simplifier[r]
			end
		end
		# no dup if no new value
		v.nil? ? ((r == @rexpr and l == @lexpr) ? self : Expression[l, @op, r]) : v
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
	attr_accessor :ptr

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

	# replace a relocation by its value calculated from +binding+, if the value is not numeric and replace_target is true the relocation target is replaced with the reduced computed value
	def fixup(binding, replace_target = false)
		@reloc.keys.each { |off|
			val = @reloc[off].target.bind(binding).reduce
			if val.kind_of? Integer
				reloc = @reloc.delete(off)
				str = Expression.encode_immediate(val, reloc.type, reloc.endianness)
				fill off
				@data[off, str.length] = str
			elsif replace_target
				@reloc[off].target = val
			end
		}
	end

	# fill virtual space with real bytes
	def fill(len = @virtsize, pattern = 0.chr)
		# XXX mark this space as freely mutable
		@virtsize = len if len > @virtsize
		@data = @data.ljust(len, pattern) if len > @data.length
	end

	# ensure virtsize is a multiple of len
	def align_size(len)
		@virtsize = (@virtsize + len - 1) / len * len
	end

	# concatenation of another +EncodedData+ or a +String+ or a +Fixnum+
	def << other
		other = other.chr            if other.class == Fixnum
		other = self.class.new other if other.class == String

		fill if other.data.length > 0

		other.reloc.each  { |k, v| @reloc[k + @virtsize] = v  }
		other.export.each { |k, v| @export[k] = v + @virtsize }
		@data << other.data
		@virtsize += other.virtsize
		self
	end
end
end # module Metasm
