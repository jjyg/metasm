require 'metasm/mips/main'

module Metasm

class MIPS
class << self
	private

        # helper function: creates a new MIPSOpcode based on the arguments, eventually                                                          
        # yields it for further customisation, and append it to the instruction set	
	def addop(name, type, bin, fmt, fields=[], *aprops)
		o = MIPSOpcode.new(name, bin, type, fmt)
		
		o.fields |= fields
		aprops.each { |p|
			if    props_allowed[p]:     o.props[p] = true
			elsif args_allowed[p]:      o.args[p] = true
			elsif metaprops_allowed[p]: o.metaprops[p] = true
			elsif p.kind_of?(Array):    o.diff_bits = p
			else  raise SyntaxError, "invalid prop #{p.inspect} for #{o.name}"
			end
		}

		yield o if block_given?
		
		o.fields_mask = fields_mask
		opcode_list << o

		o
	end

	def macro_addop_arith(name, bin, fmt='rt, rs, imm', *aprops)
		flds = [ :rs, :rt, :imm ]
		addop name, :normal, bin, fmt, flds, *aprops
	end
	
	def macro_addop_branch(name, bin, *aprops)
		flds = [ :rs, :rt, :off ]
#		aprops << :modip
		addop name, :normal, bin, 'rs, rt, off', flds, *aprops
	end
	
	def macro_addop_load_store(name, bin, *aprops)
		flds = [ :base, :rt, :off ]
		addop name, :normal, bin, 'rt, off(base)', flds, *aprops
	end
	
	def macro_addop_oper(name, bin, *aprops)
		flds = [ :base, :op, :off ]
		addop name, :normal, bin, 'op, off(base)', flds, *aprops
	end

	def macro_addop_special(name, bin, fmt, *aprops)
		flds = [ :rs, :rt, :rd, :sa ]
		addop name, :special, bin, fmt, flds, *aprops
	end

	def macro_addop_regimm(name, bin, field2, *aprops)
		flds = [ :rs, field2 ]
		addop name, :regimm, bin, "rs, #{field2}", flds, *aprops
	end
	
	def macro_addop_special2(name, bin, fmt, *aprops)
		flds = [ :rs, :rt, :rd ]
		addop name, :special2, bin, fmt, flds, *aprops
	end

	def macro_addop_cop0_c0(name, bin, *aprops)
		flds = []
		addop name, :cop0_c0, bin, '', flds, *aprops
	end
	
	def macro_addop_cop1(name, bin, *aprops)
		flds = [ :rt, :fs ] 
		addop name, :cop1, bin, 'rt, fs', flds, *aprops
	end
	
	def macro_addop_cop1_precision(name, type, bin, fmt, *aprops)
		flds = [ :ft, :fs, :fd ] 
		addop name+'.'+(type.to_s[5,7]), type, bin, fmt, flds, *aprops
	end


	public
	# Initialize the instruction set with the MIPS32 Instruction Set
	def init_mips32
		# xx_zero is used to specify that a given field should be zero
		# this is usefull for macros
		# :diff_bits is used to distinguish between a few opcodes
		# typically when only <= 4
		# this implies the presence of an array in the properties
		# [ bit_pos, mask, value ]
		# see movf / movt for an example
		[ :rd_zero, :rs_zero, :rt_zero, :sa_zero, :ft_zero, :diff_bits ].each { |p| props_allowed[p] = true }
                fields_specs.merge!({ 
					:rs => [0x1F, 21, :register ], :fr => [0x1F, 21, :fpu_reg ],
					:base => [0x1F, 21, :register ],
					:cc => [7, 18, :fpcc],
					:rt => [0x1F, 16, :register ], :ft => [0x1F, 16, :fpu_reg ], :hint => [0x1F, 16, :hint ], 
					:op => [0x1F, 16, :op ], :cp2_rt => [0x1F, 16, :cp2_reg ],
					:rd => [0x1F, 11, :register ], :fs => [0x1F, 11, :fpu_reg ],
					:sa => [0x1F, 6, :imm ], :fd => [ 0x1F, 6, :fpu_reg], 
					:stype => [0x1F, 6, :imm ],
					:code => [0xFFFFF, 6, :code ],
					:imm => [0xFFFF, 0, :imm ], :off => [0xFFFF, 0, :imm ],
					:instr_index => [ 0x3FFFFFF, 26, :instr_index ],
					:sel => [3, 0, :sel ]})
                                                                                 		

		# arithmetic operations
		macro_addop_arith 'addi',  0b001000			# ADD imm
		macro_addop_arith 'addiu', 0b001001			# ADD imm 'unsigned'
		macro_addop_arith 'slti',  0b001010			# Set on less than imm
		macro_addop_arith 'sltiu', 0b001011			# Set on less than imm unsigned
		macro_addop_arith 'andi',  0b001100			# AND immediate
		macro_addop_arith 'ori',   0b001101			# OR
		macro_addop_arith 'xori',  0b001110			# XOR
		macro_addop_arith 'lui',   0b001111, 'rt, imm', :rs_zero# Load Upper Imm

		# Branch operations 
		addop "j",    :normal, 0b000010, 'instr_index', [ :instr_index ], :setip, :stopexec
		addop "jal",  :normal, 0b000011, 'instr_index', [ :instr_index ], :setip
		macro_addop_branch 'beq',   0b000100 			# branch on ==
		macro_addop_branch 'bne',   0b000101 			# branch on !=
		macro_addop_branch 'blez',  0b000110, :rt_zero		# branch on <= 0
		macro_addop_branch 'bgtz',  0b000111, :rt_zero		# branch on > 0
		macro_addop_branch 'beql',  0b010100			# branch on == , exec delay slot only if jump taken
		macro_addop_branch 'bnel',  0b010101			# same with !=
		macro_addop_branch 'blezl', 0b010110, :rt_zero		# same with <= 0
		macro_addop_branch 'bgtzl', 0b010111, :rt_zero		# same with > 0

		# Load/Store operations 
		macro_addop_load_store 'lb',  0b100000			# load byte
		macro_addop_load_store 'lh',  0b100001			# load halfword
		macro_addop_load_store 'lwl', 0b100010			# load word left
		macro_addop_load_store 'lw',  0b100011			# load word
		macro_addop_load_store 'lbu', 0b100100			# load byte unsigned
		macro_addop_load_store 'lhu', 0b100101			# load halfword unsigned
		macro_addop_load_store 'lwr', 0b100110			# load word right

		macro_addop_load_store 'sb',  0b101000			# store byte
		macro_addop_load_store 'sh',  0b101001			# store halfword
		macro_addop_load_store 'swl', 0b101010			# store word left
		macro_addop_load_store 'sw',  0b101011			# store word
		macro_addop_load_store 'swr', 0b101110			# store word right

		macro_addop_load_store 'll',  0b110000			# load linked word
		addop 'lwc1', :normal, 0b110001, 'ft, off(base)', [ :base, :ft, :off ]
		addop 'lwc2', :normal, 0b110010, 'rt, off(base)', [ :base, :cp2_rt, :off ]
		addop 'ldc1', :normal, 0b110101, 'ft, off(base)', [ :base, :ft, :off ]
		addop 'ldc2', :normal, 0b110110, 'rt, off(base)', [ :base, :cp2_rt, :off ]

		macro_addop_load_store 'sc',    0b111000			# Store conditional word
		addop 'swc1', :normal, 0b111001, 'ft, off(base)', [ :base, :ft, :off ]
		addop 'swc2', :normal, 0b111010, 'rt, off(base)', [ :base, :cp2_rt, :off ]
		addop 'sdc1', :normal, 0b111101, 'ft, off(base)', [ :base, :ft, :off ]
		addop 'sdc2', :normal, 0b111110, 'rt, off(base)', [ :base, :cp2_rt, :off ]

		# Special ops
		macro_addop_oper 'cache', 0b101111			# cache operation
		macro_addop_oper 'pref',  0b110011			# prefetch

		# ---------------------------------------------------------------
		# SPECIAL opcode encoding of function field
		# ---------------------------------------------------------------
		
		macro_addop_special 'sll',   0b000000, 'rd, rt, sa', :rs_zero
		macro_addop_special 'srl',   0b000010, 'rd, rt, sa', :rs_zero, :diff_bits, [ 21, 1, 0 ]
		macro_addop_special 'sra',   0b000011, 'rd, rt, sa', :rs_zero
		macro_addop_special 'sllv',  0b000100, 'rd, rt, rs', :sa_zero
		macro_addop_special 'srlv',  0b000110, 'rd, rt, rs', :sa_zero, :diff_bits, [ 6, 1, 0 ]
		macro_addop_special 'srav',  0b000111, 'rd, rt, rs', :sa_zero

		addop 'movf', :special, 0b000001, 'rd, rs, cc', [ :rs, :cc, :rd ], :diff_bits, [ 16, 1, 0 ]
		addop 'movt', :special, 0b000001, 'rd, rs, cc', [ :rs, :cc, :rd ], :diff_bits, [ 16, 1, 1 ]

		macro_addop_special 'jr',    0b001000, 'rs',		:rt_zero, :sa_zero, :rd_zero, :setip, :stopexec
		macro_addop_special 'jalr',  0b001001, 'rd, rs',	:rt_zero, :sa_zero, :setip
		macro_addop_special 'movz',  0b001010, 'rd, rs, rt',	:sa_zero
		macro_addop_special 'movn',  0b001011, 'rd, rs, rt',	:sa_zero

		addop 'syscall', :special, 0b001100, 'code', [ :code ]
		addop 'break',   :special, 0b001101, 'code', [ :code ]
		addop 'sync',    :special, 0b001111, 'stype', [ :stype ]

		addop 'mfhi', :special, 0b010000, 'rd', [ :rd ]
		addop 'mthi', :special, 0b010001, 'rs', [ :rs ]
		addop 'mflo', :special, 0b010010, 'rd', [ :rd ]
		addop 'mtlo', :special, 0b010011, 'rs', [ :rs ]

		macro_addop_special 'mult',  0b011000, 'rs, rt', :rd_zero, :sa_zero
		macro_addop_special 'multu', 0b011001, 'rs, rt', :rd_zero, :sa_zero
		macro_addop_special 'div',   0b011010, 'rs, rt', :rd_zero, :sa_zero
		macro_addop_special 'divu',  0b011011, 'rs, rt', :rd_zero, :sa_zero

		macro_addop_special 'add',   0b100000, 'rd, rs, rt', :sa_zero
		macro_addop_special 'addu',  0b100001, 'rd, rs, rt', :sa_zero
		macro_addop_special 'sub',   0b100010, 'rd, rs, rt', :sa_zero
		macro_addop_special 'subu',  0b100011, 'rd, rs, rt', :sa_zero
		macro_addop_special 'and',   0b100100, 'rd, rs, rt', :sa_zero
		macro_addop_special 'or',    0b100101, 'rd, rs, rt', :sa_zero
		macro_addop_special 'xor',   0b100110, 'rd, rs, rt', :sa_zero
		macro_addop_special 'nor',   0b100111, 'rd, rs, rt', :sa_zero
		
		macro_addop_special 'slt',   0b101010, 'rd, rs, rt', :sa_zero
		macro_addop_special 'sltu',  0b101011, 'rd, rs, rt', :sa_zero
		
		addop 'tge',  :special, 0b110000, 'rs, rt', [:rs, :rt, :code ]
		addop 'tgeu', :special, 0b110001, 'rs, rt', [:rs, :rt, :code ]
		addop 'tlt',  :special, 0b110010, 'rs, rt', [:rs, :rt, :code ]
		addop 'tltu', :special, 0b110011, 'rs, rt', [:rs, :rt, :code ]
		addop 'teq',  :special, 0b110100, 'rs, rt', [:rs, :rt, :code ]
		addop 'tne',  :special, 0b110110, 'rs, rt', [:rs, :rt, :code ]

		# ---------------------------------------------------------------
		# REGIMM opcode encoding of function field
		# ---------------------------------------------------------------

		macro_addop_regimm 'bltz',   0b00000, :off
		macro_addop_regimm 'bgez',   0b00001, :off
		macro_addop_regimm 'btlzl',  0b00010, :off
		macro_addop_regimm 'bgezl',  0b00011, :off
		
		macro_addop_regimm 'tgei',   0b01000, :imm
		macro_addop_regimm 'tgeiu',  0b01001, :imm
		macro_addop_regimm 'tlti',   0b01010, :imm
		macro_addop_regimm 'tltiu',  0b01011, :imm
		macro_addop_regimm 'teqi',   0b01100, :imm
		macro_addop_regimm 'tnei',   0b01110, :imm

		macro_addop_regimm 'bltzal',  0b10000, :off
		macro_addop_regimm 'bgezal',  0b10001, :off
		macro_addop_regimm 'bltzall', 0b10010, :off
		macro_addop_regimm 'bgezall', 0b10011, :off

		
		# ---------------------------------------------------------------
		# SPECIAL2 opcode encoding of function field
		# ---------------------------------------------------------------

		macro_addop_special2 'madd',  0b000000, 'rs, rt', :rd_zero
		macro_addop_special2 'maddu', 0b000001, 'rs, rt', :rd_zero
		macro_addop_special2 'mul',   0b000010, 'rd, rs, rt'
		macro_addop_special2 'msub',  0b000100, 'rs, rt', :rd_zero
		macro_addop_special2 'msubu', 0b000101, 'rs, rt', :rd_zero

		macro_addop_special2 'clz',   0b100000, 'rd, rs'
		macro_addop_special2 'clo',   0b100001, 'rd, rs'

		addop 'sdbbp', :special2, 0b111111, 'rs, rt', [ :code ]

		# ---------------------------------------------------------------
		# COP0, field rs
		# ---------------------------------------------------------------
		
		addop 'mfc0', :cop0, 0b00000, 'rt, rd, sel', [ :rt, :rd, :sel ]
		addop 'mtc0', :cop0, 0b00100, 'rt, rd, sel', [ :rt, :rd, :sel ]
	
		# ---------------------------------------------------------------
		# COP0 when rs=C0
		# ---------------------------------------------------------------
		 
		macro_addop_cop0_c0 'tlbr',  0b000001
		macro_addop_cop0_c0 'tlbwi', 0b000010
		macro_addop_cop0_c0 'tlwr',  0b000110
		macro_addop_cop0_c0 'tlbp',  0b001000
		macro_addop_cop0_c0 'eret',  0b011000
		macro_addop_cop0_c0 'deret', 0b011111
		macro_addop_cop0_c0 'wait',  0b100000
		
		# ---------------------------------------------------------------
		# COP1, field rs
		# ---------------------------------------------------------------
		
		macro_addop_cop1 'mfc1', 0b00000
		macro_addop_cop1 'cfc1', 0b00010
		macro_addop_cop1 'mtc1', 0b00100
		macro_addop_cop1 'ctc1', 0b00110

		addop "bc1f",  :cop1, 0b01000, 'cc, off', [ :cc, :off ], :diff_bits, [ 16, 3, 0 ]
		addop "bc1fl", :cop1, 0b01000, 'cc, off', [ :cc, :off ], :diff_bits, [ 16, 3, 2 ]
		addop "bc1t",  :cop1, 0b01000, 'cc, off', [ :cc, :off ], :diff_bits, [ 16, 3, 1 ]
		addop "bc1tl", :cop1, 0b01000, 'cc, off', [ :cc, :off ], :diff_bits, [ 16, 3, 3 ]
		
		# ---------------------------------------------------------------
		# COP1, field rs=S/D
		# ---------------------------------------------------------------

		[ :cop1_s, :cop1_d ].each do |type|
		type_str = type.to_s[5,7]
		
		macro_addop_cop1_precision 'add',  type, 0b000000, 'fd, fs, ft' 
		macro_addop_cop1_precision 'sub',  type, 0b000001, 'fd, fs, ft' 
		macro_addop_cop1_precision 'mul',  type, 0b000010, 'fd, fs, ft' 
		macro_addop_cop1_precision 'abs',  type, 0b000101, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'mov',  type, 0b000110, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'neg',  type, 0b000111, 'fd, fs', :ft_zero
		
		macro_addop_cop1_precision 'movz', type, 0b010010, 'fd, fs, ft' 
		macro_addop_cop1_precision 'movn', type, 0b010011, 'fd, fs, ft' 

		addop "movf.#{type_str}", type, 0b010001, 'fd, fs, cc', [ :cc, :fs, :fd ], :diff_bits, [ 16, 1, 0 ]
		addop "movt.#{type_str}", type, 0b010001, 'fd, fs, cc', [ :cc, :fs, :fd ], :diff_bits, [ 16, 1, 1 ]

		%w(f un eq ueq olt ult ole ule sf ngle seq ngl lt nge le ngt).each_with_index do |cond, index|
			addop "c.#{cond}.#{type_str}", type, 0b110000+index, 'cc, fs, ft',
			[ :ft, :fs, :cc ]
		end
		end
		
		# S and D Without PS
		
		[:cop1_s, :cop1_d].each do |type|
		macro_addop_cop1_precision 'div',  type, 0b000011, 'fd, fs, ft' 
		macro_addop_cop1_precision 'sqrt', type, 0b000100, 'fd, fs', :ft_zero
		
		macro_addop_cop1_precision 'round.w', type, 0b001100, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'trunc.w', type, 0b001101, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'ceil.w',  type, 0b001110, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'floor.w', type, 0b001111, 'fd, fs', :ft_zero
		
		end

		# COP2 is not decoded (pretty useless)
		
		[:cop1_d,:cop1_w].each { |type| macro_addop_cop1_precision 'cvt.s', type, 0b100000, 'fd, fs', :ft_zero }
		[:cop1_s,:cop1_w].each { |type| macro_addop_cop1_precision 'cvt.d', type, 0b100001, 'fd, fs', :ft_zero }
		[:cop1_s,:cop1_d].each { |type| macro_addop_cop1_precision 'cvt.w', type, 0b100100, 'fd, fs', :ft_zero }
		
		[ :normal, :special, :regimm, :special2, :cop0, :cop0_c0, :cop1, :cop1_s,
		  :cop1_d, :cop1_w ].each \
			{ |t| @@opcodes_by_class[t] = opcode_list.find_all { |o| o.type == t } }
	end

	# Initialize the instruction set with the MIPS32 Instruction Set Release 2
	def init_mips64
		init_mips32
			
		#SPECIAL
		macro_addop_special "rotr",  0b000010, 'rd, rt, sa', :diff_bits, [ 26, 1, 1 ]
		macro_addop_special "rotrv", 0b000110, 'rd, rt, rs', :diff_bits, [ 6, 1, 1 ]
		
		# REGIMM
		addop "synci", :regimm, 0b11111, '', {:base => [5,21], :off => [16, 0] }
		
		# ---------------------------------------------------------------
		# SPECIAL3 opcode encoding of function field
		# ---------------------------------------------------------------

		addop "ext", :special3, 0b00000, 'rt, rs, pos, size', { :rs => [5, 21], :rt => [5, 16],
									:msbd => [5, 11], :lsb => [5, 6] }
		addop "ins", :special3, 0b00100, 'rt, rs, pos, size', { :rs => [5, 21], :rt => [5, 16],
									:msb => [5, 11], :lsb => [5, 6] }

		addop "rdhwr", :special3, 0b111011, 'rt, rd', { :rt => [5, 16], :rd => [5, 11] }
		
		addop "wsbh", :bshfl, 0b00010, 'rd, rt', { :rt => [5, 16], :rd => [5, 11] }
		addop "seb",  :bshfl, 0b10000, 'rd, rt', { :rt => [5, 16], :rd => [5, 11] }
		addop "seh",  :bshfl, 0b11000, 'rd, rt', { :rt => [5, 16], :rd => [5, 11] }

		# ---------------------------------------------------------------
		# COP0
		# ---------------------------------------------------------------

		addop "rdpgpr", :cop0, 0b01010, 'rt, rd', {:rt => [5, 16], :rd => [5, 11] }
		addop "wdpgpr", :cop0, 0b01110, 'rt, rd', {:rt => [5, 16], :rd => [5, 11] }
		addop "di",     :cop0, 0b01011, '', {}, :diff_bits, [ 5, 1 , 0]
		addop "ei",     :cop0, 0b01011, '', {}, :diff_bits, [ 5, 1 , 1]
		
		# ---------------------------------------------------------------
		# COP1, field rs
		# ---------------------------------------------------------------
		
		macro_addop_cop1 "mfhc1", 0b00011
		macro_addop_cop1 "mthc1", 0b00111

		# Floating point
		
		[:cop1_s, :cop1_d].each do |type|
		macro_addop_cop1_precision 'round.l', type, 0b001000, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'trunc.l', type, 0b001001, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'ceil.l',  type, 0b001010, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'floor.l', type, 0b001011, 'fd, fs', :ft_zero
		
		macro_addop_cop1_precision 'recip', type, 0b010101, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'rsqrt', type, 0b010110, 'fd, fs', :ft_zero
		
		macro_addop_cop1_precision 'cvt.l', type, 0b100101, 'fd, fs', :ft_zero
		end
		macro_addop_cop1_precision 'cvt.ps', :cop1_s, 0b100110, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'cvt.s', :cop1_l, 0b100000, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'cvt.d', :cop1_l, 0b100000, 'fd, fs', :ft_zero
		
		macro_addop_cop1_precision 'add',  :cop1_ps, 0b000000, 'fd, fs, ft' 
		macro_addop_cop1_precision 'sub',  :cop1_ps, 0b000001, 'fd, fs, ft' 
		macro_addop_cop1_precision 'mul',  :cop1_ps, 0b000010, 'fd, fs, ft' 
		macro_addop_cop1_precision 'abs',  :cop1_ps, 0b000101, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'mov',  :cop1_ps, 0b000110, 'fd, fs', :ft_zero
		macro_addop_cop1_precision 'neg',  :cop1_ps, 0b000111, 'fd, fs', :ft_zero
		
		macro_addop_cop1_precision 'movz', :cop1_ps, 0b010010, 'fd, fs, ft' 
		macro_addop_cop1_precision 'movn', :cop1_ps, 0b010011, 'fd, fs, ft' 

		addop "movf.#{:cop1_ps_str}", :cop1_ps, 0b010001, 'fd, fs, cc', [ :cc, :fs, :fd ]
		addop "movt.#{:cop1_ps_str}", :cop1_ps, 0b010001, 'fd, fs, cc', [ :cc, :fs, :fd ]

		%w(f un eq ueq olt ult ole ule sf ngle seq ngl lt nge le ngt).each_with_index do |cond, index|
			addop "c.#{cond}.ps", :cop1_cond, 0b110000+index, 'cc, fs, ft',
			[ :ft, :fs, :cc ]

		# TODO: COP1X
		
		[ :special3, :bshfl, :cop1_l, :cop1_ps ].each \
			{ |t| @@opcodes_by_class[t] = opcode_list.find_all { |o| o.type == t } }
	end

	end

	# Reset all instructions
	def reset
		metaprops_allowed.clear
		args_allowed.clear
		props_allowed.clear
		fields_spec.clear
		opcode_list.clear
	end
	
end
	# Array containing all the supported opcodes
	attr_reader :opcode_list	
	
	init_mips32
end

end
