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

	# returns a hash opcode_name => array of opcodes with this name
	def opcode_list_byname
		@opcode_list_byname ||= @opcode_list.inject({}) { |h, o| (h[o.name] ||= []) << o ; h }
	end
end

# generic CPU, with no instructions, just size/endianness
class UnknownCPU < CPU
	def initialize(size, endianness)
		super()
		@size, @endianness = size, endianness
	end
end

# a specific cpu instruction description
class Opcode
	# the name of the instruction
	attr_accessor :name
	# formal description of arguments (array of cpu-specific symbols)
	attr_accessor :args
	# binary encoding of the opcode (integer for risc, array of bytes for cisc)
	attr_accessor :bin
	# list of bit fields in the binary encoding
	# hash position => field
	# position is bit shift for risc, [byte index, bit shift] for risc
	# field is cpu-specific
	attr_accessor :fields
	# hash of opcode generic properties/restrictions (mostly property => true/false)
	attr_accessor :props

	def initialize(name)
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
	# arguments (cpu-specific objects)
	attr_accessor :args
	# hash of prefixes (unused in simpler cpus)
	attr_accessor :prefix
	# name of the associated opcode
	attr_accessor :opname
	# reference to the cpu which issued this instruction (used for rendering)
	attr_accessor :cpu

	def initialize(cpu, opname=nil, args=[], pfx={})
		@cpu = cpu
		@prefix, @args = pfx, args
		@opname = opname
	end

	# duplicates the argument list and prefix hash
	def dup
		Instruction.new(@cpu, (@opname.dup rescue @opname), @args.dup, @prefix.dup)
	end
end

# contiguous/uninterrupted sequence of instructions, chained to other blocks
# TODO
class InstructionBlock
end

# all kind of data description (including repeated/uninitialized)
class Data
	# maps data type to Expression parameters (signedness/bit size)
	INT_TYPE = {:db => :u8, :dw => :u16, :dd => :u32}

	# an Expression, an Array of Data, a String, or :uninitialized
	attr_accessor :data
	# the data type, from INT_TYPE (TODO store directly Expression parameters ?)
	attr_accessor :type
	# the repetition count of the data parameter (dup constructs)
	attr_accessor :count

	def initialize(type, data, count=1)
		@data, @type, @count = data, type, count
	end
end

# alignment/padding directive
class Align
	# the size to pad/align to
	# nil when dynamic (see +Offset+)
	attr_accessor :val
	# the Data used to pad
	attr_accessor :fillwith
	# true for alignment, false for padding
	attr_accessor :modulo

	def initialize(val, fillwith=nil, modulo=true)
		@val, @fillwith, @modulo = val, fillwith, modulo
	end
end

# an offset directive, for dynamically computed padding length
class Offset
	# the assembler will arrange to make this pseudo-instruction
	# be at this offset from beginning of current section
	attr_accessor :val

	def initialize(val)
		@val = val
	end
end

# represents an executable section
# ie no holes, same permissions
# XXX will die today !
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

# generic program representation
# XXX will die today !
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

# handle immediate values, and arbitrary arithmetic/logic expression involving variables
# XXX separate logic expressions ?
# TODO replace #type with #size => bits + #type => [:signed/:unsigned/:any/:floating]
# TODO floats
class Expression
	INT_SIZE = {:u8 => 8,    :u16 => 16,     :u32 => 32, :u64 => 64,
		    :i8 => 8,    :i16 => 16,     :i32 => 32, :i64 => 64
	}
	INT_MIN  = {:u8 => 0,    :u16 => 0,      :u32 => 0, :u64 => 0,
		    :i8 =>-0x80, :i16 =>-0x8000, :i32 =>-0x80000000, :i64 => -0x8000_0000_0000_0000
	}
	INT_MAX  = {:u8 => 0xff, :u16 => 0xffff, :u32 => 0xffffffff, :u64 => 0xffff_ffff_ffff_ffff,
		    :i8 => 0x7f, :i16 => 0x7fff, :i32 => 0x7fffffff, :i64 => 0x7fff_ffff_ffff_ffff
	}

	# alternative constructor
	# in operands order, and allows nesting using sub-arrays
	# ex: Expression[[:-, 42], :*, [1, :+, [4, :*, 7]]]
	# with a single argument, return it if already an Expression, else construct a new one (using unary +/-)
	def self.[](l, op = nil, r = nil)
		return l if l.kind_of? Expression and not op
		l, op, r = nil, :-, -r if op == nil and r.kind_of? Numeric and r < 0
		l, op, r = nil, :+, l  if op == nil	# can find false in boolean expression
		l, op, r = nil, l, op  if  r == nil
		l = self[*l] if l.kind_of? Array
		r = self[*r] if r.kind_of? Array
		new(op, r, l)
	end


	# checks if a given Expression/Integer is in the type range
	# returns true if it is, false if it overflows, and nil if cannot be determined (eg unresolved variable)
	def self.in_range?(val, type)
		val = val.reduce if val.kind_of? self
		return unless val.kind_of? Numeric

		case type
		when :u8, :u16, :u32, :i8, :i16, :i32
			val == val.to_i and
			val >= INT_MIN[type] and val <= INT_MAX[type]
		end
	end

	# the operator (symbol)
	attr_accessor :op
	# the lefthandside expression (nil for unary expressions)
	# XXX may be false in logic expression TODO use 0/1 for false/true (allows true + 40, as in C)
	attr_accessor :lexpr
	# the righthandside expression
	# XXX may be false in logic expression
	attr_accessor :rexpr

	# basic constructor
	# XXX funny args order, you should use +Expression[]+ instead
	def initialize(op, rexpr, lexpr)
		raise "Expression: invalid arg order: op #{op.inspect}, r l = #{rexpr.inspect} #{lexpr.inspect} #{caller.join("\n")}" if not op.kind_of? Symbol
		@op, @lexpr, @rexpr = op, lexpr, rexpr
	end

	# recursive check of equity using #==
	# will not match 1+2 and 2+1
	def ==(o)
		# shortcircuit recursion
		o.object_id == object_id or (o.class == self.class and [o.op, o.rexpr, o.lexpr] == [@op, @rexpr, @lexpr])
	end

	# make it useable as Hash key (see +==+)
	def hash
		[@lexpr, @op, @rexpr].hash
	end
	alias eql? ==

	# returns a new Expression with all variables found in the binding replaced with their value
	# does not check the binding's key class except for numeric
	# calls lexpr/rexpr #bind if they respond_to? it
	def bind(binding = {})
		l, r = @lexpr, @rexpr
		if l.respond_to? :bind
			l = l.bind(binding)
		else
			raise "Do not want to bind #{l.inspect}" if binding[l].kind_of? Numeric
			l = binding.fetch(l, l)
		end
		if r.respond_to? :bind
			r = r.bind(binding)
		else
			raise "Do not want to bind #{l.inspect}" if binding[l].kind_of? Numeric
			r = binding.fetch(r, r)
		end
		Expression[l, @op, r]
	end

	# bind in place (replace self.lexpr/self.rexpr with the binding value)
	# only recurse with Expressions (does not use respond_to?)
	def bind!(binding = {})
		if @lexpr.kind_of?(Expression)
			@lexpr.bind!(binding)
		else
			@lexpr = binding.fetch(@lexpr, @lexpr)
		end
		if @rexpr.kind_of?(Expression)
			@rexpr.bind!(binding)
		else
			@rexpr = binding.fetch(@rexpr, @rexpr)
		end
		self
	end

	# returns a simplified copy of self
	# can return an +Expression+ or a +Numeric+ or true/false, may return self
	# see +reduce_rec+ for simplifications description
	def reduce
		case e = reduce_rec
		when Expression, Numeric, true, false: e
		else Expression[e]
		end
	end

	# resolves logic operations (true || false, etc)
	# computes numeric operations (1 + 3)
	# expands substractions to addition of the opposite
	# reduces double-oppositions (-(-1) => 1)
	# reduces addition of 0 and unary +
	# canonicalize additions: put variables in the lhs, descend addition tree in the rhs => (a + (b + (c + 12)))
	# make formal reduction if finds somewhere in addition tree (a) and (-a)
	def reduce_rec
		l = @lexpr.respond_to?(:reduce_rec) ? @lexpr.reduce_rec : @lexpr
		r = @rexpr.respond_to?(:reduce_rec) ? @rexpr.reduce_rec : @rexpr

		v = 
		if (r == true or r == false) and (l == nil or l == true or l == false) and (@op == :'!' or @op == :'&&' or @op == :'||')
			if l != nil
				case @op
				when :'&&': l && r
				when :'||': l || r
				end
			else
				if @op == :'!'
					!r
				end
			end

		elsif r.kind_of?(Numeric) and (l == nil or l.kind_of?(Numeric))
			# calculate numerics
			if l
				case @op
				when :'!=': l != r
				else l.send(@op, r)
				end
			else
				case @op
				# when :'!': !r
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

	# returns the array of non-numeric members of the expression
	# if a variables appears 3 times, it will be present 3 times in the returned array
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
		"#<Expression:#{'%08x' % object_id} #{@lexpr.inspect} #{@op.inspect} #{@rexpr.inspect}>"
	end
end

# an EncodedData relocation, specifies a value to patch in
class Relocation
	# the relocation value (an Expression)
	attr_accessor :target
	# the relocation expression type
	attr_accessor :type
	# the endianness of the relocation
	attr_accessor :endianness

	def initialize(target, type, endianness)
		@target     = target
		@type       = type
		@endianness = endianness
	end
end

# a String-like, with export/relocation informations added
class EncodedData
	# string with raw data
	attr_accessor :data
	# hash, key = offset within data, value = +Relocation+
	attr_accessor :reloc
	# hash, key = export name, value = offset within data
	attr_accessor :export
	# virtual size of data (all 0 by default, see +fill+)
	attr_accessor :virtsize
	# arbitrary pointer, often used when decoding immediates
	attr_accessor :ptr

	# opts' keys in :reloc, :export, :virtsize, defaults to empty/empty/data.length
	def initialize(data = '', opts={})
		@data     = data
		@reloc    = opts[:reloc]    || {}
		@export   = opts[:export]   || {}
		@virtsize = opts[:virtsize] || @data.length
	end

	# returns the size of raw data, that is [data.length, last relocation end].max
	def rawsize
		[@data.length, *@reloc.map { |off, rel| off + Expression::INT_SIZE[rel.type]/8 } ].max
	end
	# String-like
	alias length virtsize
	# String-like
	alias size virtsize

	# returns a copy of itself, with reloc/export duped (but not deep)
	def dup
		self.class.new @data.dup, :reloc => @reloc.dup, :export => @export.dup, :virtsize => @virtsize
	end

	# resolve relocations:
	# calculate each reloc target using Expression#bind(binding)
	# if numeric, replace the raw data with the encoding of this value (+fill+s preceding data if needed) and remove the reloc
	# if replace_target is true, the reloc target is replaced with its bound counterpart
	def fixup_choice(binding, replace_target)
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

	# +fixup_choice+ binding, false
	def fixup(binding)
		fixup_choice(binding, false)
	end

	# +fixup_choice+ binding, true
	def fixup!(binding)
		fixup_choice(binding, true)
	end

	# returns a default binding suitable for use in +fixup+
	# every export is expressed as base + offset
	# base defaults to the first export name + its offset
	def binding(base = nil)
		if not base
			key = @export.keys.sort_by { |k| @export[k] }.first
			return {} if not key
			base = Expression[key, :-, @export[key]]
		end
		@export.inject({}) { |binding, (n, o)| binding.update n => Expression[base, :+, o] }
	end

	# fill virtual space by repeating pattern (String) up to len
	# expand self if len is larger than self.virtsize
	def fill(len = @virtsize, pattern = 0.chr)
		@virtsize = len if len > @virtsize
		@data = @data.ljust(len, pattern) if len > @data.length
	end

	# rounds up virtsize to next multiple of len
	def align(len)
		@virtsize = EncodedData.align_size(@virtsize, len)
	end

	# returns the value val rounded up to next multiple of len
	def self.align_size(val, len)
		((val + len - 1) / len).to_i * len
	end

	# concatenation of another +EncodedData+ (or nil/Fixnum/anything supporting String#<<)
	def << other
		case other
		when nil
		when Fixnum
			fill
			@data << other
			@virtsize += 1
		when EncodedData
			fill if not other.data.empty?
			other.reloc.each  { |k, v| @reloc[k + @virtsize] = v  }
			other.export.each { |k, v| @export[k] = v + @virtsize }
			if @data.empty?: @data = other.data.dup
			else @data << other.data
			end
			@virtsize += other.virtsize
		else
			if @data.empty?: @data = other.dup
			else @data << other
			end
			@virtsize += other.length
		end

		self
	end

	# equivalent to dup << other, filters out Integers & nil
	def + other
		raise ArgumentError if not other or other.kind_of?(Integer)
		dup << other
	end

	# slice
	def [](from, len=nil)
		if not len and from.kind_of? Range
			b = from.begin
			e = from.end
			b = b + @virtsize if b < 0
			e = e + @virtsize if e < 0
			len = e - b
			len += 1 if not from.exclude_end?
			from = b
		end
		from = from + @virtsize if from < 0

		return @data[from] if not len
		ret = EncodedData.new @data[from, len]
		ret.virtsize = len
		@reloc.each { |o, r|
			ret.reloc[o - from] = r if o >= from and o + Expression::INT_SIZE[r.type]/8 < from+len
		}
		@export.each { |e, o|
			ret.export[e] = o - from if o >= from and o <= from+len		# XXX include end ?
		}
		ret
	end

	# slice replacement, supports size change (shifts following relocs/exports)
	# discards old exports/relocs from the overwritten space
	def []=(from, len, val=nil)
		if not val
			val = len
			len = nil
		end
		if not len and from.kind_of? Range
			b = from.begin
			e = from.end
			b = b + @virtsize if b < 0
			e = e + @virtsize if e < 0
			len = e - b
			len += 1 if not from.exclude_end?
			from = b
		end
		from = from + @virtsize if from < 0

		if not len
			val = val.chr
			len = val.length
		end
		val = EncodedData.new val unless val.kind_of? EncodedData

		# remove overwritten
		@export.delete_if { |name, off| off > from and off < from + len }
		@reloc.delete_if { |off, rel| off - Expression::INT_SIZE[r.type]/8 > from and off < from + len }
		# shift after insert
		if val.virtsize != len
			diff = val.virtsize - len
			@export.keys.each { |name| @export[name] = @export[name] + diff if @export[name] > from }
			@reloc.keys.each  { |off| @reloc[off+diff] = @reloc.delete(off) if off > from }
			@virtsize += diff
		end
		# replace
		fill(from) if not val.data.empty?
		@data[from, len] = val.data
		val.export.each { |name, off| @export[name] = from + off }
		val.reloc.each { |off, rel| @reloc[from + off] = rel }
	end
end
end
