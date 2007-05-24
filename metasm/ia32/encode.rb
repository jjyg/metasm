require 'metasm/ia32/opcodes'
require 'metasm/ia32/parse'
require 'metasm/encode'

module Metasm
class Ia32
	class InvalidModRM < Exception ; end
	class ModRM
		# returns the byte representing the register encoded as modrm
		# works with Reg/SimdReg
		def self.encode_reg(reg, mregval = 0)
			0xc0 | (mregval << 3) | reg.val
		end

		# The argument is an integer representing the 'reg' field of the mrm
		#
		# The instruction encoder is responsible for setting the adsz
		#  override prefix / segment override prefix if needed
		# returns an array, 1 element per possible immediate size (when un-reduce()ible Expression)
		def encode(reg = 0, endianness = :little)
			case @adsz
			when 16: encode16(reg, endianness)
			when 32: encode32(reg, endianness)
			end
		end

		private
		def encode16(reg, endianness)
			if not @b
				# imm only
				return [EncodedData.new << (6 | (reg << 3)) << @imm.encode(:u16, endianness)]
			end

			imm = @imm.reduce
			imm = nil if imm == 0
			ret = EncodedData.new
			ret <<
			case [@b.val, (@s.val if @s)]
			when [3, 6], [6, 3]: 0
			when [3, 7], [7, 3]: 1
			when [5, 6], [6, 5]: 2
			when [5, 7], [7, 5]: 3
			when [6, nil]: 4
			when [7, nil]: 5
			when [5, nil]
				imm ||= 0
				6
			when [3, nil]: 7
			else raise InvalidModRM, 'invalid modrm16'
			end

			ret.data[0] |= reg << 3
			
			if imm
				if Expression.in_range?(imm, :i8)		
					ret.data[0] |= 1 << 6
					[ret << Expression.encode_immediate(imm, :i8, endianness)]
				else
					retl = ret.dup
					ret.data[0] |= 1 << 6
					retl.data[0] |= 2 << 6
					ret << @imm.encode(:i8, endianness)
					retl << @imm.encode(:i16, endianness)
					[retl, ret]
				end
			else
				[ret]
			end
		end

		def encode32(reg, endianness)
			# 0 => [ [0      ], [1      ], [2      ], [3      ], [:sib      ], [:i32   ], [6      ], [7      ] ], \
			# 1 => [ [0, :i8 ], [1, :i8 ], [2, :i8 ], [3, :i8 ], [:sib, :i8 ], [5, :i8 ], [6, :i8 ], [7, :i8 ] ], \
			# 2 => [ [0, :i32], [1, :i32], [2, :i32], [3, :i32], [:sib, :i32], [5, :i32], [6, :i32], [7, :i32] ]
			#
			# b => 0  1  2  3  4  5+i|i 6  7
			# i => 0  1  2  3 nil   5   6  7

			ret = EncodedData.new << (reg << 3)

			if not @b and not @i
				ret.data[0] |= 5
				[ret << @imm.encode(:u32, endianness)]

			elsif not @b and @s != 1
				# sib with no b
				raise EncodeError, "Invalid ModRM #{self}" if @i.val == 4
				ret.data[0] |= 4
				s = {8=>3, 4=>2, 2=>1}[@s]
				imm = @imm || Expression[0]
				[ret << ((s << 6) | (@i.val << 3) | 5) << imm.encode(:i32, endianness)]
			else
				imm = @imm.reduce if @imm
				imm = nil if imm == 0

				if not @i or (not @b and @s == 1)
					# no sib byte (except for [esp])
					b = @b || @i

					ret.data[0] |= b.val
					ret << 0x24 if b.val == 4
				else
					# sib
					ret.data[0] |= 4

					i, b = @i, @b
					b, i = i, b if @s == 1 and (i.val == 4 or b.val == 5)

					raise EncodeError, "Invalid ModRM #{self}" if i.val == 4

					s = {8=>3, 4=>2, 2=>1, 1=>0}[@s]
					ret << ((s << 6) | (i.val << 3) | b.val)
				end

				imm ||= 0 if b.val == 5
				if imm
					if Expression.in_range?(imm, :i8)		
						ret.data[0] |= 1 << 6
						[ret << Expression.encode_immediate(imm, :i8, endianness)]
					else
						retl = ret.dup
						ret.data[0] |= 1 << 6
						retl.data[0] |= 2 << 6
						ret << @imm.encode(:i8, endianness)
						retl << @imm.encode(:i32, endianness)
						[retl, ret]
					end
				else
					[ret]
				end
			end
		end
	end
	
	# returns an array of EncodedData
	def encode_instruction(program, i)
		oplist = opcode_list_byname[i.opname].to_a.find_all { |o|
			o.args.length == i.args.length and
			o.args.zip(i.args).all? { |f, a| parse_arg_valid?(o, f, a) }
		}
		raise EncodeError, "no matching opcode found for #{i}" if oplist.empty?
		oplist.inject([]) { |ret, op| ret.concat encode_instr_op(program, i, op) }
	end

	private
	def encode_instr_op(program, i, op)
		base      = op.bin.pack('C*')
		oi        = op.args.zip(i.args)
		set_field = proc { |base, f, v|
			fld = op.fields[f]
			base[fld[0]] |= v << fld[1]
		}

		# 
		# handle prefixes and bit fields
		#
		pfx = i.prefix.map { |k, v|
			case k
			when :jmp:  {:jmp => 0x3e, :nojmp => 0x2e}[v]
			when :lock: 0xf0
			when :rep:  {'repnz' => 0xf2, 'repz' => 0xf3, 'rep' => 0xf2}[v] # TODO
			end
		}.pack 'C*'
		pfx << op.props[:needpfx].pack('C*') if op.props[:needpfx]

		# opsize override / :s :w fields
		if op.name == 'movsx' or op.name == 'movzx'
			case [i.arg[0].sz, i.arg[1].sz]
			when [32, 16]
				raise EncodeError, "Incompatible arg size in #{i}"
			when [16, 16]
				set_field[base, :w, 1]
				pfx << 0x66 if @size == 32
			when [32, 8]
				pfx << 0x66 if @size == 16
			when [16, 8]
				pfx << 0x66 if @size == 32
			end

		else
			opsz = nil
			imm32s = false
			mayimm32s = false
			oi.each { |oa, ia|
				case oa
				when :reg, :reg_eax, :modrm, :modrmA, :mrm_imm
					raise EncodeError, "Incompatible arg size in #{i}" if (ia.sz and opsz and opsz != ia.sz) or (ia.sz == 8 and not op.fields[:w])
					opsz = ia.sz
				when :i
					if op.fields[:s] and opsz != 8
						if Expression.in_range?(ia, :i8)
							imm32s = true 
							set_field[base, :s, 1]
						elsif not ia.reduce.kind_of? Integer
							mayimm32s = true
						end
					end
				end
			}
			pfx << 0x66 if (opsz and ((opsz == 16 and @size == 32) or (opsz == 32 and @size == 16))) or (op.props[:opsz] and op.props[:opsz] != @size)

			set_field[base, :w, 1] if op.fields[:w] and opsz != 8
		end

		# addrsize override / segment override
		if mrm = i.args.grep(ModRM).first
			pfx << 0x67 if (mrm.b and mrm.b.sz != @size) or (mrm.i and mrm.i.sz != @size)
			pfx << "\x26\x2E\x36\x3E\x64\x65"[mrm.seg.val] if mrm.seg
		end

	
		#
		# encode embedded arguments
		#
		postponed = []
		oi.each { |oa, ia|
			case oa
			when :reg, :seg3, :seg2, :seg2A, :eeec, :eeed, :regfp, :regmmx, :regxmm
				# field arg
				set_field[base, oa, ia.val]
			when :imm_val1, :imm_val3, :reg_cl, :reg_eax, :reg_dx, :regfp0
				# implicit
			else
				postponed << [oa, ia]
			end
		}

		if not (op.args & [:modrm, :modrmA, :modrmxmm, :modrmmmx]).empty?
			# reg field of modrm
			regval = (base[-1] >> 3) & 7
			base.chop!
		end

		# convert label name for jmp/call/loop to relative offset
		if op.props[:setip] and op.name[0, 3] != 'ret' and i.args.first.kind_of? Expression
			postlabel = program.new_unique_label
			postponed.first[1] = Expression[postponed.first[1], :-, postlabel]
		end

		#
		# append other arguments
		#
		# this is an array of hashes, each element is an EncodedData + its context (imm32s)
		ret = [{:edata => EncodedData.new(pfx + base)}]
		if mayimm32s
			set_field[base, :s, 1]
			ret << {:edata => EncodedData.new(pfx+base), :imm32s => true}
		end

		postponed.each { |oa, ia|
			case oa
			when :farptr
				# XXX opsz/adsz override not supported (nonsense anyway)
				ret.each { |h| h[:edata] << ia.addr.encode("u#@size".to_sym, @endianness) << Expression.encode_immediate(ia.seg, :u16, @endianness) }
			when :modrm, :modrmA, :modrmmmx, :modrmxmm
				if ia.class == ModRM
					mrm = ia.encode(regval, @endianness)
					ret.dup.each { |h|
						if mrm.length > 1
							mrm[1..-1].each { |m|
								ret << h.dup
								ret.last[:edata] = h[:edata].dup << m
							}
						end
						h[:edata] << mrm.first
					}
				else
					ret.each { |h| h[:edata] << ModRM.encode_reg(ia, regval) }
				end
			when :mrm_imm
				ret.each { |h| h[:edata] << ia.imm.encode("u#@size".to_sym, @endianness) }
			when :i8, :u8, :u16
				ret.each { |h| h[:edata] << ia.encode(oa, @endianness) }
			when :i
				ret.each { |h|
					if h[:imm32s]
						oa = :i8
					else
						oa = imm32s ? :i8 : "u#{opsz || @size}".to_sym
					end
					h[:edata] << ia.encode(oa, @endianness)
				}
			else
				raise SyntaxError, "Internal error: want to encode field #{oa.inspect} as arg in #{i}"
			end
		}

		ret.map { |h|
			h[:edata].export[postlabel] = h[:edata].virtsize if postlabel
			h[:edata]
		}
	end
end
end
