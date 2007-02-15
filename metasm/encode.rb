require 'metasm/main'
require 'metasm/parse'

module Metasm
class EncodeError < Exception ; end

class Program
	# returns the label pointing to edata[offset], create it if needed
	def label_at(edata, offset)
		if not label = edata.export.invert[offset]
			edata.export[label = new_unique_label] = offset
		end
		label
	end

	def encode
		@sections.each { |s| s.encode }
	end
end

class EncodedData
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

class Section
	def encode
		encoded = [EncodedData.new]

		@source.each { |e|
			case e
			when Label: encoded.last << EncodedData.new('', :export => {e.name => 0})
			when Data:  encoded.last << e.encode(@program.cpu.endianness)
			when Align: encoded << e << EncodedData.new
			when Instruction:
				case i = @program.cpu.encode_instr(@program, e)
				when Array
					if i.length == 1
						encoded.last << i.first
					else
						encoded << i << EncodedData.new
					end
				else
					encoded.last << i
				end
			end
		}

		@encoded = encode_resolve encoded
		start = @program.label_at @encoded, 0
		@encoded.fixup @encoded.export.inject({}) { |binding, (name, offset)| binding.update name => Expression[start, :+, offset] }
		@encoded
	end

	def encode_resolve(encoded)
		startlabel = @program.label_at(@encoded, 0)

		# 
		# instruction choice resolution
		#
		# This is a choice that will be optimal in many cases
		# XXX make a real optimal alg ?

		# calc all labels offsets in the worst case (as if choice = widest)
		worstbinding = {}
		curoff = 0
		encoded.each { |enc|
			case enc
			when Array
				enc.each { |e|
					e.export.each { |label, off|
						worstbinding[label] = Expression[startlabel, :+, curoff + off] if label != startlabel
					}
				}
				curoff += enc.map { |e| e.virtsize }.max
			when Align
				curoff += enc.val - 1
			else
				enc.export.each { |label, off|
					worstbinding[label] = Expression[startlabel, :+, curoff + off] if label != startlabel
				}
				curoff += enc.virtsize
			end
		}

		# now select instructions on:
		# if a relocation depends on non-section offsets, chose widest field size
		# if a relocatios can be resolved, chose the instruction with the smallest size (but still able to encode the resolved value)
		result = encoded.shift
		encoded.each { |enc|
			case enc
			when Array
				result << enc.sort_by { |edata|
					[
					# most significant: chose widest field for external deps (sum fields len)
					edata.reloc.values.map { |rel|
						case Expression.in_range?(rel.target.bind(worstbinding), rel.type)
						when true
							# immediate: ignore
							0
						when false
							# immediate not fitting: reject
							1000000 - Expression::INT_SIZE[rel.type]
						when nil
							# external: wider = better
							- Expression::INT_SIZE[rel.type]
						end
					}.inject(0) { |a, b| a+b } ,
					# least significant: on tie, chose the smallest total size
					edata.virtsize
					]
				}.first
			when Align
				result.align_size enc.val
			else
				result << enc
			end
		}
		result
	end
end

class Expression
	def encode(type, endianness)
		case val = reduce
		when Integer: Expression.encode_immediate(val, type, endianness)
		else          EncodedData.new('', :reloc => {0 => Relocation.new(self, type, endianness)}, :virtsize => INT_SIZE[type]/8)
		end
	end

	def self.encode_immediate(val, type, endianness)
		raise EncodeError, "unsupported endianness #{endianness.inspect}" unless [:big, :little].include? endianness
		# XXX warn on overflow ?
		s = (0...INT_SIZE[type]/8).map { |i| (val >> (8*i)) & 0xff }.pack('C*')
		endianness != :little ? s.reverse : s
	end

	# try to symplify itself
	# non destructive
	# can return self or another +Expression+ or a +Numeric+
	def reduce
		case e = reduce_rec
		when Expression, Numeric: e
		else Expression[:+, e]
		end
	end

	def reduce_rec
		l = case @lexpr
		    when Expression: @lexpr.reduce_rec
		    else @lexpr
		    end
		r = case @rexpr
		    when Expression: @rexpr.reduce_rec
		    else @rexpr
		    end


		if r.kind_of?(Numeric) and (not l or l.kind_of?(Numeric))
			# calculate numerics
			if l
				l.send(@op, r)
			else
				case @op
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
		end or
		# no dup if no new value
		((r == @rexpr and l == @lexpr) ? self : Expression[l, @op, r])
	end
end

class Data
	def encode(endianness)
		edata = case @data
		when Uninitialized
			EncodedData.new('', :virtsize => Expression::INT_SIZE[INT_TYPE[@type]]/8)
		when String
			# db 'foo' => 'foo' # XXX could be optimised, but should not be significant
			# dw 'foo' => "f\0o\0o\0" / "\0f\0o\0o"
			@data.unpack('C*').inject(EncodedData.new) { |ed, chr| ed << Expression.encode_immediate(chr, INT_TYPE[@type], endianness) }
		when Expression
			@data.encode INT_TYPE[@type], endianness
		when Array
			@data.inject(EncodedData.new) { |ed, d| ed << d.encode(endianness) }
		end

		# n times
		(0...@count).inject(EncodedData.new) { |ed, cnt| ed << edata }
	end
end

class CPU
	# returns an EncodedData
	# uses +#parse_arg_valid?+ to find the opcode whose signature matches with the instruction
	def encode_instr(program, i)
		op = @opcode_list_byname[i.opname].to_a.find { |o|
			o.args.length == i.args.length and o.args.zip(i.args).all? { |f, a| parse_arg_valid?(o, f, a) }
		}
		encode_instr_op program, i, op
	end
end
end # module
