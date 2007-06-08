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
			when Align: encoded << e << EncodedData.new
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
	# assumes all ambiguous edata has same relocation targets (with same object_id)
	def encode_resolve(encoded)
		startlabel = @program.label_at(@encoded, 0)

		# create two bindings where all encodeddata are the shortest/longest
		minbinding = {}
		minoff = 0
		maxbinding = {}
		maxoff = 0
	
		encoded.each { |enc|
			case enc
			when Array
				enc.each { |e|
					e.export.each { |label, off|
						minbinding[label] = Expression[startlabel, :+, minoff + off]
						maxbinding[label] = Expression[startlabel, :+, maxoff + off]
					}
				}
				minoff += enc.map { |e| e.virtsize }.min
				maxoff += enc.map { |e| e.virtsize }.max
			when Align
				minoff += 0
				maxoff += enc.val - 1	# XXX suboptimal (.padto 42 ; foo ; .padto 45 => should be max 3)
			else
				enc.export.each { |label, off|
					minbinding[label] = Expression[startlabel, :+, minoff + off] if label != startlabel
					maxbinding[label] = Expression[startlabel, :+, maxoff + off] if label != startlabel
				}
				minoff += enc.virtsize
				maxoff += enc.virtsize
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
				when :/
					if    expr.rexpr.kind_of? Numeric: expr = expr.lexpr
					else  break
					end
				when :+, :-
					if    not expr.lexpr:              expr = expr.rexpr
					elsif expr.lexpr.kind_of? Numeric: expr = expr.rexpr
					elsif expr.rexpr.kind_of? Numeric: expr = expr.lexpr
					else
						break if not check_linear[expr.rexpr] or not check_linear[expr.lexpr]
						expr = expr.lexpr
					end
				else break
				end
			end

			not expr.kind_of? Expression
		}

		# now we can resolve all relocations
		# for linear expressions of internal variables (all exports from current section): calc bounds, and use worst case smallest place
		# else use largest reloc place
		# on tie, chose overall shortest Edata

		@encoded = encoded.shift

		encoded.each { |enc|
			case enc
			when Array
				# for each external, compute target value using minbinding[external] and maxbinding[external]
				# if target is not found in bounds.keys, use largest relocation
				target_bounds = {}
				rec_checkminmax = proc { |target, binding, extlist|
					if extlist.empty?
						(target_bounds[target] ||= []) << target.bind(binding).reduce
					else
						rec_checkminmax[target, binding.merge(extlist.last => minbinding[extlist.last]), extlist[0...-1]]
						rec_checkminmax[target, binding.merge(extlist.last => maxbinding[extlist.last]), extlist[0...-1]]
					end
				}

				# biggest size for this relocation (for non-linear/external)
				wantsize = {}

				enc.first.reloc.each { |o, r|
					# has external ref
					if not r.target.bind(minbinding).reduce.kind_of?(Numeric) or not check_linear[r.target]
						# find the biggest relocation type for the current target
						wantsize[r.target] = enc.map { |edata|
							edata.reloc.values.find { |rel| rel.target == r.target }.type
						}.sort_by { |type| Expression::INT_SIZE[type] }.last
					else
						rec_checkminmax[r.target, {}, r.target.externals]
						target_bounds[r.target] = [target_bounds[r.target].min, target_bounds[r.target].max]
					end
				}

				# reject candidates with reloc type too small
				acceptable = enc.find_all { |edata|
					edata.reloc.values.all? { |rel|
						if wantsize[rel.target]
							rel.type == wantsize[rel.target]
						else
							target_bounds[rel.target].all? { |target| Expression.in_range?(target, rel.type) }
						end
					}
				}

				raise EncodeError, "cannot find candidate in #{enc.inspect}, relocations too small" if acceptable.empty?

				# keep the shortest
				@encoded << acceptable.sort_by { |edata| edata.virtsize }.first

			when EncodedData
				@encoded << enc

			when Align
				if enc.modulo
					targetsize = EncodedData.align_size(@encoded.virtsize, enc.val)
				else
					targetsize = enc.val
				end

				if enc.fillwith
					pad = enc.fillwith.encode(@program.cpu.endianness)
					while @encoded.virtsize + pad.virtsize <= targetsize
						@encoded << pad
					end
					if @encoded.virtsize < targetsize
						choplen = targetsize - @encoded.virtsize
						pad.reloc.delete_if { |off, rel| off + Expression::INT_SIZE[rel.type]/8 > choplen }
						pad.data[choplen..-1] = '' if pad.data.length > choplen
						pad.virtsize = choplen
						@encoded << pad
					end
				else
					@encoded.virtsize = targetsize if @encoded.virtsize < targetsize
				end

				raise EncodeError, "cannot pad current section to #{targetsize} bytes - off by #{@encoded.virtsize - targetsize} bytes" if @encoded.virtsize > targetsize

			else
				raise 'Internal error: bad object in encode_resolve'
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
