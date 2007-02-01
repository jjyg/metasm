require 'metasm/main'

module Metasm

class MIPSOpcode < Opcode
	attr_reader :type,:fmt
	attr_accessor :fields, :diff_bits

	def initialize(name, bin, type, fmt)
		super(name, bin)
		@type = type
		@fmt = fmt
		@fields = []
		@diff_bits = []
	end
end

class Immediate
	def class
		:imm
	end
end

class MIPS < Instruction
	# Normal MIPS CPU register
	class Reg < Argument
		@@regs = %w( $0 $1 $v0 $v1 $a0 $a1 $a2 $a3 $t0 $t1 $t2 $t3 $t4 $t5 $t6 $t7
			      $s0 $s1 $s2 $s3 $s4 $s5 $s6 $s7 $t8 $t9 $k0 $k1 $gp $sp $fp $ra )

		attr_reader :v
		
		def initialize(v)
			if v.kind_of?(String) then
				if not v =~ /[a-z]/ then
					@v = v[/[0-9]+/].to_i
				else
					@v = @@regs.index(v)
				end
			else
				@v = v
			end
		end

		def to_i
			@v
		end

		def to_s
			@@regs[@v]
		end

		def class
			:register
		end
				
	end

	# Normal MIPS FPU register
	class FPUReg < Argument
		@@fpu_regs = (0..31).map { |n| "$f#{n}" }
		attr_reader :v
		
		def initialize(v)
			@v = v
		end

		def to_i
			@v
		end

		def to_s
			@@fpu_regs[@v]
		end
		
		def class
			:fpu_reg
		end
	end

	# Floating-Point condition code
	class FPCC < Argument
		@@fpcc = (0..7).map { |n| "$fcc#{n}" }
		
		def initialize(v)
			@v = v
		end

		def to_i
			@v
		end

		def to_s
			@@fpcc[@v]
		end	

		def class
			:fpcc
		end
	end

	class Displ < Argument
		attr_reader :base, :off
		
		def initialize(str)
			@base = Reg.new(str[/\$[a-z0-9]{1,3}/])
			@off = Immediate.new(str[/[+-]?0x[0-9a-fA-F]+/].to_i(0), 2, true)
		end

		def to_s
			@off.to_s+'('+@base.to_s+')'
		end

		def class
			:displ
		end
	end

	# Class variable that contains the specifications of operand fields
	# [ mask, position, class ]
	# mask:: bitmask, i.e. 3 bits => 7
	# position:: position of the starting bit (from the right) in the opcode
	# class:: type of field, for example : :register
	# for example: :rt => [ 0x1F, 16, :register]
	def MIPS.fields_specs ; cv[:fields_specs] ||= {} end

	# Endianness : either :little or :big
	@@endian = :little

	@@opcodes_by_class = Hash.new()

	def MIPS.endian
		@@endian
	end
	def MIPS.endian=(endian)
		@@endian = endian
	end

	def initialize
		super
		@bin_length = 4
		@cmt = ''
		@endian = @@endian
	end

end

end
