require 'metasm/mips/opcodes'
require 'metasm/encode'

module Metasm

class MIPS
	class Parser
	# parses one instruction from the source string +str+ starting at +idx+ into +instr+
	# raises InvalidMnemonic if impossible
	#
#	 Grammar :
#		< mips_line > ::= [ <label> ] <mnem> [ <args> ] [ <comment> ];
#		<label> ::= IDENT ":";
#		<mnem> ::= IDENT | IDENT "." FMT | IDENT "." COND "." FMT;
#		<args> ::= <arg> [ "," <arg> ];
#		<arg> ::= REG | IMMHEX | IMMDEC | IMMBIN | <displ> | IDENT;
#		<comment> ::= ";" .*;
#		<displ> ::= IMMHEX "(" REG ")";
#		REG = $[0-9a-z]+
#		IMMHEX = [+-]?0x[0-9A-Fa-f]+
#		IMMDEC = [+-]?[0-9]+
#		IMMBIN = [+-]?0b[01]+
#		IDENT = [a-z0-9_]+
#		FMT = 
#		COND = 

	class << self
		def check_ident(str, error_msg="Invalid identifier : ")
			if not str =~ /^[a-z0-9_]+$/ then
				raise SyntaxError.new(error_msg+str)
			end
			true
		end

		def decode_label(str)
			# Check for a label
			if str.include?(':')
				check_ident(str.sub(':',''), "Invalid label identifier : ")
				return str.sub(':','')
			end
		end

		def decode_comment(string, elements)
			0.upto(elements.length-1) do |idx|
				if elements[idx].include?(';') then
					return idx-1, string[/;.*/]
				end
			end
			return elements.length-1, nil
			end

		def decode_args(args, format)
			args_vals = Hash.new()
			args_fmt = format.split(', ')
			if args.length != args_fmt.length
				raise SyntaxError.new("Invalid number of arguments (#{args.length} of #{args_fmt.length}) : "+args.join(', '))
			end

			idx = 0
			args_fmt.each do |a|
				sym = a.to_sym
				a_class = MIPS::fields_specs[sym]
				a_class = a_class[2] if a_class

				a_class = :displ if not a_class and a == 'off(base)'
				syn_error = false
				case a_class
					when :register
						syn_error = true if not args[idx] =~ /^\$[a-z0-9]{1,3}$/
						args_vals[sym] = Reg.new(args[idx])
					when :imm, :code
						syn_error = true if not (args[idx] =~ /^[+-]?0x[0-9a-fA-F]+$/ \
									 or args[idx] =~ /^[+-]?0b[01]+$/ \
									 or args[idx] =~ /^[+-]?[0-9]+$/)
						args_vals[sym] = Immediate.new(args[idx].to_i(0), 2, true)
					when :displ
						syn_error = true if not args[idx] =~ /^[+-]?0x[0-9a-fA-F]+\(\$[a-z0-9]{1,3}\)$/
						displ = Displ.new(args[idx])
						args_vals[:off] = displ.off
						args_vals[:base] = displ.base
					when :fpu_reg
						syn_error = true if not args[idx] =~ /^\$f[0-9]{1,2}$/
						args_vals[sym] = FPUReg.new(args[idx][/[0-9]{1,2}/].to_i)
					when :fpcc
						syn_error = true if not args[idx] =~ /^\$fcc[0-9]$/
						args_vals[sym] = FPCC.new(args[idx][/[0-9]/].to_i)
					else
						raise RuntimeError.new("Internal error : unknown arg class "+a_class.to_s)
				end
				raise SyntaxError.new("Invalid arg syntax : '#{args[idx]}'") if syn_error==true
				idx += 1
			end
			
			return args_vals
		end
	end

	def initialize(str, idx=0)
		elements = str.split(' ')
		
		idx = 0

		@label = Parser::decode_label(elements[idx])
		idx += 1 if @label
		
		@mnem = elements[idx]

		@op = MIPS::opcode_list.find { |o| o.name == @mnem }
		if not @op
			raise SyntaxError.new("Invalid mnemonic : "+@mnem);
		end
		
		idx += 1

		endidx, @cmt = Parser::decode_comment(str, elements)

		@args = Parser::decode_args(elements[idx..endidx].each { |e| e.sub!(',','') }, @op.fmt)
		op_args = @op.fmt.split(", ")
			

		#puts @label.to_s+(@label ? ': ':'')+@mnem.to_s+' '+@args.values.join(', ')+(@cmt ? ' '+@cmt : '')
		
                self
        end

	Cop1_bin = { :cop1_s => 0b10000, :cop1_d => 0b10001, :cop1_w => 0b10100, :cop1_l => 0b10101, :cop1_ps => 0b10110 }
	def compile(str, idx=0)
		opcode_bin = {  :special =>   0b000000,
				:regimm =>    0b000001,
				:cop0 =>      0b010000, 
				:cop1 =>      0b010001, 
				:cop2 =>      0b010010, 
				:cop1x =>     0b010011,
				:special2 =>  0b011100,
				:normal =>    @op.bin}

		opcode = 0
		case @op.type
			when :special, :special2, :special3
				opcode |= opcode_bin[@op.type]<<26
				opcode |= @op.bin
			when :cop1
				opcode |= opcode_bin[@op.type]<<26
				opcode |= @op.bin<<21
			when :cop1_s, :cop1_d, :cop1_w, :cop1_l, :cop1_ps
				opcode |= opcode_bin[:cop1] << 26
				opcode |= Cop1_bin[@op.type] << 21
				opcode |= @op.bin
			when :regimm
				opcode |= opcode_bin[@op.type]<<26
				opcode |= @op.bin << 16
			when :normal
				opcode |= @op.bin << 26
			else
				raise RuntimeError.new("Unknown type : "+@op.type.to_s);
		end

		if @op.props[:diff_bits] then
			opcode |= @op.diff_bits[2]<<@op.diff_bits[0];
		end

		@op.fields.each do |f|
			field_s = MIPS::fields_specs[f]
			field_val = @args[f]
	
			if not field_val and @op.props["#{f}_zero".to_sym] then
				field_val = 0
			elsif field_val
				field_val = field_val.to_i
			else
				raise RuntimeError.new("Field error : #{f}")
			end
			opcode |= (field_val&field_s[0]) << field_s[1]
			
		end

		case MIPS.endian #opt[:endianness]
			when :little :
				4.times { |i| str[idx+i] = opcode & 0xff ; opcode >>= 8 }
			when :big : 
				4.times { |i| str[idx+i] = (opcode >> (8*(3-i))) & 0xff  }
			else raise SyntaxError, "Unsupported endianness #{MIPS.endian}"
		end
		str
	end
	
	end

	class << self
		# lookaside table of opcodes (hash, key = opcode name downcased, value = opcode)
		def asc_lookaside
			cv[:asc_lookaside] ||= opcode_list.inject({}) { |h, o| (h[o.name.downcase] ||= []) << o ; h }
		end

		# returns the array of all possible instructions, which may contain fixups. It is up to the caller to determine
		# the prefered encoding.
		def encode(str, idx)
			pfxlist = []
		end

		def parse(str, idx=0)
			Parser.new(str, idx)
		end
	end

	# +asc_length+ is the length of the source string (including prefix and args)
	def asc_length ; @asc_length ||= 0 end
	attr_writer :asc_length

end
end
