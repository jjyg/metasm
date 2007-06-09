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

	# encode every program's section
	def encode
		@sections.each { |s| s.encode }
	end
end

class Section
	# encodes the source array to an unique EncodedData
	def encode
		encoded = [EncodedData.new]

		@source.each { |e|
			case e
			when Label: encoded.last.export[e.name] = encoded.last.virtsize
			when Data:  encoded.last << e.encode(@program.cpu.endianness)
			when Align, Padding:
				e.fillwith = e.fillwith.encode(@program.cpu.endianness) if e.fillwith
				encoded << e << EncodedData.new
			when Offset: encoded << e << EncodedData.new
			when Instruction:
				case i = @program.cpu.encode_instruction(@program, e)
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

		encode_resolve encoded

		@encoded.fixup @encoded.binding
		@encoded
	end

	# chose among multiple possible sub-EncodedData
	# assumes all ambiguous edata has same relocation, with exact same targets (used as Hash key)
	def encode_resolve(encoded)
		startlabel = @program.label_at(@encoded, 0)

		# create two bindings where all encodeddata are the shortest/longest possible
		minbinding = {}
		minoff = 0
		maxbinding = {}
		maxoff = 0
	
		encoded.each { |elem|
			case elem
			when Array
				elem.each { |e|
					e.export.each { |label, off|
						minbinding[label] = Expression[startlabel, :+, minoff + off]
						maxbinding[label] = Expression[startlabel, :+, maxoff + off]
					}
				}
				minoff += elem.map { |e| e.virtsize }.min
				maxoff += elem.map { |e| e.virtsize }.max

			when EncodedData
				elem.export.each { |label, off|
					minbinding[label] = Expression[startlabel, :+, minoff + off] if label != startlabel
					maxbinding[label] = Expression[startlabel, :+, maxoff + off] if label != startlabel
				}
				minoff += elem.virtsize
				maxoff += elem.virtsize

			when Align
				minoff += 0
				maxoff += elem.val - 1

			when Padding
				# find the surrounding Offsets and compute the largest/shortest edata sizes to determine min/max length for the padding
				prevoff = encoded[0..encoded.index(elem)].grep(Offset).last
				nextoff = encoded[encoded.index(elem)..-1].grep(Offset).first
				raise EncodeError, 'need .offset after .pad' if not nextoff

				previdx = prevoff ? encoded.index(prevoff) + 1 : 0
				surround = encoded[previdx..encoded.index(nextoff)-1]
				surround.delete elem
				if surround.find { |nelem| nelem.kind_of? Padding }
					raise EncodeError, 'need .offset beetween two .pad'
				end
				if surround.find { |nelem| nelem.kind_of? Align and encoded.index(nelem) > encoded.index(elem) }
					raise EncodeError, 'cannot .align after a .pad'
				end

				lenmin = lenmax = nextoff.val - (prevoff ? prevoff.val : 0)
				surround.each { |nelem|
					case nelem
					when Array
						lenmin -= nelem.map { |e| e.virtsize }.max
						lenmax -= nelem.map { |e| e.virtsize }.min
					when EncodedData
						lenmin -= nelem.virtsize
						lenmax -= nelem.virtsize
					when Align
						lenmin -= nelem.val - 1
						lenmax -= 0
					end
				}
				# not sure what would happen if we just checked lenmax...
				raise EncodeError, "no room for .pad before .offset #{nextoff.val}" if lenmin < 0
				minoff += lenmin
				maxoff += lenmax

			when Offset
				# nothing to do for now
			else
				raise "Internal error: bad object #{elem.inspect} in encode_resolve"
			end
		}

		# check expression linearity
		check_linear = proc { |expr|
			expr = expr.reduce if expr.kind_of? Expression
			while expr.kind_of? Expression
				case expr.op
				when :*
					if    expr.lexpr.kind_of? Numeric: expr = expr.rexpr
					elsif expr.rexpr.kind_of? Numeric: expr = expr.lexpr
					else  break
					end
				when :/, :>>, :<<
					if    expr.rexpr.kind_of? Numeric: expr = expr.lexpr
					else  break
					end
				when :+, :-
					if    not expr.lexpr:              expr = expr.rexpr
					elsif expr.lexpr.kind_of? Numeric: expr = expr.rexpr
					elsif expr.rexpr.kind_of? Numeric: expr = expr.lexpr
					else
						break if not check_linear[expr.rexpr]
						expr = expr.lexpr
					end
				else break
				end
			end

			not expr.kind_of? Expression
		}

		# now we can resolve all relocations
		# for linear expressions of internal variables (all exports from current section)
		#  - calc bounds target numeric bounds, and reject reloc not accepting worst case value 
		#  - else reject all but largest place available
		# then chose the shortest overall EData left
		encoded.map! { |elem|
			case elem
			when Array
				# for each external, compute numeric target values using minbinding[external] and maxbinding[external]
				# this gives us all extrem values for linear expressions
				target_bounds = {}
				rec_checkminmax = proc { |target, binding, extlist|
					if extlist.empty?
						(target_bounds[target] ||= []) << target.bind(binding).reduce
					else
						rec_checkminmax[target, binding.merge(extlist.last => minbinding[extlist.last]), extlist[0...-1]]
						rec_checkminmax[target, binding.merge(extlist.last => maxbinding[extlist.last]), extlist[0...-1]]
					end
				}
				# biggest size disponible for this relocation (for non-linear/external)
				wantsize = {}

				elem.first.reloc.each { |o, r|
					# has external ref
					if not r.target.bind(minbinding).reduce.kind_of?(Numeric) or not check_linear[r.target]
						# find the biggest relocation type for the current target
						wantsize[r.target] = elem.map { |edata|
							edata.reloc.values.find { |rel| rel.target == r.target }.type
						}.sort_by { |type| Expression::INT_SIZE[type] }.last
					else
						rec_checkminmax[r.target, {}, r.target.externals]
						target_bounds[r.target] = [target_bounds[r.target].min, target_bounds[r.target].max]
					end
				}

				# reject candidates with reloc type too small
				acceptable = elem.find_all { |edata|
					edata.reloc.values.all? { |rel|
						if wantsize[rel.target]
							rel.type == wantsize[rel.target]
						else
							target_bounds[rel.target].all? { |target| Expression.in_range?(target, rel.type) }
						end
					}
				}

				raise EncodeError, "cannot find candidate in #{elem.inspect}, relocations too small" if acceptable.empty?

				# keep the shortest
				acceptable.sort_by { |edata| edata.virtsize }.first
			else
				elem
			end
		}

		# assemble all parts, resolve padding sizes, check offset directives
		@encoded = EncodedData.new
		fillwith = proc { |targetsize, data|
			if data
				while @encoded.virtsize + data.virtsize <= targetsize
					@encoded << data
				end
				if @encoded.virtsize < targetsize
					@encoded << data[0, targetsize - @encoded.virtsize]
				end
			else
				@encoded.virtsize = targetsize
			end
		}

		encoded.each { |elem|
			case elem
			when EncodedData
				@encoded << elem
			when Align
				fillwith[EncodedData.align_size(@encoded.virtsize, elem.val), elem.fillwith]
			when Offset
				raise EncodeError, "could not enforce .offset #{elem.val} directive: offset now #{@encoded.virtsize}" if @encoded.virtsize != elem.val
			when Padding
				nextoff = encoded[encoded.index(elem)..-1].grep(Offset).first
				targetsize = nextoff.val
				encoded[encoded.index(elem)+1..encoded.index(nextoff)-1].each { |nelem| targetsize -= nelem.virtsize }
				raise EncodeError, "no room for .pad before .offset #{nextoff.val}: would be #{targetsize} bytes long" if targetsize < 0
				fillwith[targetsize, elem.fillwith]
			end
		}

		@encoded
	end
end

class Expression
	def encode(type, endianness)
		case val = reduce
		when Integer: EncodedData.new Expression.encode_immediate(val, type, endianness)
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
		when :uninitialized
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
	def encode_instruction(program, i)
		op = opcode_list_byname[i.opname].to_a.find { |o|
			o.args.length == i.args.length and o.args.zip(i.args).all? { |f, a| parse_arg_valid?(o, f, a) }
		}
		encode_instr_op program, i, op
	end
end
end # module
