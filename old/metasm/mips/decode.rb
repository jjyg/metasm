require 'metasm/mips/opcodes'
require 'metasm/decode'

module Metasm

class MIPS
	# Constant Hash that matches special opcodes
	# with their decoding function
	Field_class_decoders = {    0b000000 => "decode_special",
				    0b000001 => "decode_regimm",
				    0b010000 => "decode_cop0",
				    0b010001 => "decode_cop1",
				    0b010010 => "decode_cop2",
				    0b010011 => "decode_cop1x",
				    0b011100 => "decode_special2"}

		
	class << self
		private
		def find_opcode(type, op_bin, full_opcode)
			opcodes = @@opcodes_by_class[type].find_all { |o| o.bin == op_bin }
			return opcodes[0] if opcodes.length <= 1
			diff_bits = opcodes[0].diff_bits
			flag = (full_opcode >> diff_bits[0]) & diff_bits[1]
			return opcodes.find { |o| o.diff_bits[2] == flag }
		end
		
		# Return the MIPSOpcode encoded in the function field of the *SPECIAL* +opcode+
		def decode_special(opcode)
			function_field = opcode&0x3F
			return find_opcode(:special, function_field, opcode)
		end

		# Return the MIPSOpcode encoded in the _rt_ field of the *REGIMM* +opcode+
		def decode_regimm(opcode)
			operation = (opcode>>16)&0x1F
			return find_opcode(:regimm, operation, opcode)
		end
		
		# Return the MIPSOpcode encoded in the function field of the *SPECIAL2* +opcode+
		def decode_special2(opcode)
			function_field = opcode&0x3F
			return find_opcode(:special2, function_field, opcode)
		end

		# Return the MIPSOpcode encoded in the _sa_ field of the *BSHFL* +opcode+
		def decode_bshfl(opcode)
			function_field = (opcode>>6)&0x1F
			return find_opcode(:bshfl, function_field, opcode)
		end
		
		# Return the MIPSOpcode encoded in the function field of the *SPECIAL3* +opcode+
		def decode_special3(opcode)
			function_field = opcode&0x3F
			# BSHFL
			if function_field == 0b100000
				return decode_bshfl(opcode)
			else
				return find_opcode(:special3, function_field, opcode)
			end
		end
		
		# Return the MIPSOpcode encoded in the _rs_ field of the *COP0* +opcode+
		def decode_cop0(opcode)
			rs_field = (opcode>>21)&0x1F
			if (rs_field & 0x10 != 0) then
				return find_opcode(:cop0_c0, opcode&0x3F, opcode)
			else
				return find_opcode(:cop0, rs_field, opcode)
			end
		end
	
		
		# Return the MIPSOpcode encoded in the function field of the *COP1* +opcode+ when _rs_ == S
		def decode_cop1_single(opcode)
			function_field = opcode&0x3F
			if (function_field&0b110000) == 0b110000 then
				comp = decode_cop1_compare_code(function_field&0xF)
				return @@opcodes_by_class[:cop1_s].find { |o| o.name == "c.#{comp}.s" }
			else
				return find_opcode(:cop1_s, function_field, opcode)
			end
		end

		def decode_cop1_compare_code(code)
			codes = %w(f un eq ueq olt ult ole ule sf ngle seq ngl lt nge le ngt);
			return codes[code];
		end
		
		def decode_cop1_double(opcode)
			function_field = opcode&0x3F
			if (function_field&0b110000) == 0b110000 then
				comp = decode_cop1_compare_code(function_field&0xF)
				return @@opcodes_by_class[:cop1_d].find { |o| o.name == "c.#{comp}.d" }
			else
				return find_opcode(:cop1_d, function_field, opcode)
			end
		end
		
		def decode_cop1_w(opcode)
			function_field = opcode&0x3F
			return find_opcode(:cop1_w, function_field, opcode)
		end
		
		def decode_cop1_l(opcode)
			function_field = opcode&0x3F
			return find_opcode(:cop1_l, function_field, opcode)
		end
		
		def decode_cop1(opcode)
			precision = {	0b10000 => 'decode_cop1_single',
					0b10001 => 'decode_cop1_double',
					0b10100 => 'decode_cop1_w',
					0b10101 => 'decode_cop1_l',
					0b10110 => 'decode_cop1_paired_single'}
			rs_field = (opcode>>21)&0x1F
			precision_decoder = precision[rs_field]
			if precision_decoder then
				return send(precision_decoder, opcode)
			else
				return find_opcode(:cop1, rs_field, opcode)
			end
			
		end

		
		public
		def opcode_lookaside
			cv[:opcode_lookaside] ||= {} 
		end

		def decode(*args, &b) new.decode(*args, &b) end
	end

	# Fill the _fields_vals_ hash with the values of the args
	# based on the fields attribute of _opcode_
	def decode_fields(op, opcode)
		@fields_vals = Hash.new()

		op.fields.each do |field|
			infos = MIPS.fields_specs[field]
			# infos is an array : [mask, position, class]
			mask = infos[0]<<(infos[1])
			val = (opcode & mask)>>infos[1]
	
			case infos[2]
				when :fpu_reg
					argval = FPUReg.new(val)
				when :register
					@cmt = "#{field} should be zero, but is #{val} !" if op.props["#{field}_zero".to_sym] and val!=0
					argval = Reg.new(val)
				when :imm 
					argval = Immediate.new(val, 2, true)
				when :fpcc
					argval = FPCC.new(val)
				when :code
					argval = Immediate.new(val, 3, false)
				else
					raise infos[2].to_s
			end
			@fields_vals[field] =  argval
		end
	end

	# Interprets the binary +str+ to decode the current instruction and its arguments 
	# raises InvalidOpcode on no match
	# uses decode_msg
	def decode(str, idx=0)
		# Decode according to endianness
		opcode = str[idx..(idx+4)].unpack(MIPS.endian == :big ? 'N' : 'V')[0]

		raise InvalidOpcode.new(str, 0) if not opcode
		
		@op = self.class.opcode_lookaside[opcode]
	
		if not @op
			# Get opcode field
			op_field = opcode >> 26

			# Check if the opcode is a field class, i.e. further decoding is needed
			field_class_decoder = Field_class_decoders[op_field]
			if field_class_decoder
				@op = MIPS.send(field_class_decoder, opcode)
			else
				@op = @@opcodes_by_class[:normal].find { |o| o.bin == op_field }
			end

			raise InvalidOpcode.new(str, 0) if not @op

			self.class.opcode_lookaside[opcode] = @op
		end
		
		decode_fields(@op, opcode)
		@fields_vals.each { |f, v| @args << v if @op.fmt.include?(f.to_s) }
		self
	end
	
	def to_s
		instr = @op.name+" "
		args = op.fmt.dup
		@fields_vals.each { |f,v| args.sub!(f.to_s, v.to_s) }
		instr += args
		instr += "\t; " + @cmt if @cmt != ''
		instr
	end
end
end
