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
				targetsize = (result.virtsize + enc.val - 1) / enc.val * enc.val
				if enc.fillwith
					pad = enc.fillwith.encode(@program.cpu.endianness)
					while result.virtsize + pad.virtsize <= targetsize
						result << pad
					end
					if result.virtsize < targetsize
						choplen = targetsize - result.virtsize
						pad.reloc.delete_if { |off, rel| off + Expression::INT_SIZE[rel.type]/8 > choplen }
						pad.data[choplen..-1] = '' if pad.data.length > choplen
						pad.virtsize = choplen
						result << pad
					end
				else
					result.virtsize = targetsize if result.virtsize < targetsize
				end
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
