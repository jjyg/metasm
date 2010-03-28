#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/arm/main'

module Metasm
class ARM
	private
	def addop(name, bin, *args)
		args << :cond if not args.delete :uncond

		o = Opcode.new name

		o.bin = bin
		o.args.concat(args & @valid_args)
		(args & @valid_props).each { |p| o.props[p] = true }
		o.props[:baseincr] = :post if args.include? :postincr
		o.props[:baseincr] = :pre  if args.include? :preincr

		# special args -> multiple fields
		case (o.args & [:i8_r, :rm_is, :rm_rs, :mem_rn_rm, :mem_rn_i12]).first
		when :i8_r; args << :i8 << :rotate
		when :rm_is; args << :rm << :shift << :shifta
		when :rm_rs; args << :rm << :shift << :rs
		when :mem_rn_rm; args << :rn << :rm << :shift << :shifta << :u
		when :mem_rn_i12; args << :rn << :i12 << :u
		end

		(args & @fields_mask.keys).each { |f|
			o.fields[f] = [@fields_mask[f], @fields_shift[f]]
		}

		@opcode_list << o
	end

	def addop_data(name, op, a1, a2)
		addop name, (op << 21) | (1 << 25), :s, a1, a2, :i8_r, :rotate
		addop name, (op << 21), :s, a1, a2, :rm_is
		addop name, (op << 21) | (1 << 4), :s, a1, a2, :rm_rs
	end

	def addop_load_bpw(name, op, *incr)
		addop name, op, :rd, :mem_rn_i12, *incr
		addop name, op | (1 << 25), :rd, :mem_rn_rm, *incr
	end
	def addop_load_b(name, op)
		addop_load_bpw name, op, :postincr
		addop_load_bpw name+'t', op | (1 << 21), :postincr
		addop_load_bpw name, op | (1 << 24)
		addop_load_bpw name, op | (1 << 24) | (1 << 21), :preincr
	end
	def addop_load(name, op)
		addop_load_b name, op
		addop_load_b name+'b', op | (1 << 22)
	end

	# ARMv6 instruction set, aka arm7/arm9
	def init_arm_v6
		@opcode_list = []
		@valid_props << :baseincr << :cond << :s << :tothumb << :tojazelle
		@valid_args.concat [:rn, :rd, :rm, :crn, :crd, :crm, :cpn, :reglist,
			:rm_rs, :rm_is, :i8_r, :mem_rn_i12, :mem_rn_rm]
		@fields_mask.update :rn => 0xf, :rd => 0xf, :rs => 0xf, :rm => 0xf,
			:crn => 0xf, :crd => 0xf, :crm => 0xf, :cpn => 0xf,
			:rnx => 0xf, :rdx => 0xf,
			:shifta => 0x1f, :shift => 3, :rotate => 0xf, :reglist => 0xffff,
			:i8 => 0xff, :i12 => 0xfff, :i24 => 0xff_ffff,
			:u => 1, :s => 1,
			:mask => 0xf, :sbo => 0xf, :cond => 0xf

		@fields_shift.update :rn => 16, :rd => 12, :rs => 8, :rm => 0,
			:crn => 16, :crd => 12, :crm => 0, :cpn => 8,
			:rnx => 16, :rdx => 12,
			:shifta => 7, :shift => 5, :rotate => 8, :reglist => 0,
			:i8 => 0, :i12 => 0, :i24 => 0,
			:u => 23, :s => 20,
			:mask => 16, :sbo => 12, :cond => 28
		
		addop_data 'and', 0,  :rd, :rn
		addop_data 'eor', 1,  :rd, :rn
		addop_data 'xor', 1,  :rd, :rn
		addop_data 'sub', 2,  :rd, :rn
		addop_data 'rsb', 3,  :rd, :rn
		addop_data 'add', 4,  :rd, :rn
		addop_data 'adc', 5,  :rd, :rn
		addop_data 'sbc', 6,  :rd, :rn
		addop_data 'rsc', 7,  :rd, :rn
		addop_data 'tst', 8,  :rdx, :rn
		addop_data 'teq', 9,  :rdx, :rn
		addop_data 'cmp', 10, :rdx, :rn
		addop_data 'cmn', 11, :rdx, :rn
		addop_data 'orr', 12, :rd, :rn
		addop_data 'or',  12, :rd, :rn
		addop_data 'mov', 13, :rd, :rnx
		addop_data 'bic', 14, :rd, :rn
		addop_data 'mvn', 15, :rd, :rnx
		
		addop 'b',  0b1010 << 24, :setip, :stopexec, :i24
		addop 'bl', 0b1011 << 24, :setip, :stopexec, :i24, :saveip
		addop 'bkpt', (0b00010010 << 20) | (0b0111 << 4)		# other fields are available&unused, also cnd != AL is undef
		addop 'blx', 0b1111101 << 25, :setip, :stopexec, :saveip, :tothumb, :h, :nocond, :i24
		addop 'blx', (0b00010010 << 20) | (0b0011 << 4), :setip, :stopexec, :saveip, :tothumb, :rm
		addop 'bx',  (0b00010010 << 20) | (0b0001 << 4), :setip, :stopexec, :rm
		addop 'bxj',  (0b00010010 << 20) | (0b0010 << 4), :setip, :stopexec, :rm, :tojazelle

		addop_load 'ldr',  1 << 26
		addop_load 'str', (1 << 26) | (1 << 20)
	end
	alias init_latest init_arm_v6
end
end

__END__
all shift == 0
:offsetimm => 0xfff, :movwimm => 0x0f0fff
			:writeback => 21,
			:psr => 22,
			:up => 23,
			:preindexing => 24,
			:offsetimm => 25

		addop_cond 'mrs',  0b0001000011110000000000000000, :rd
		addop_cond 'msr',  0b0001001010011111000000000000, :rd
		addop_cond 'msrf', 0b0001001010001111000000000000, :rd

		addop_cond 'mul',  0b000000000000001001 << 4, :rd, :rn, :rs, :rm
		addop_cond 'mla',  0b100000000000001001 << 4, :rd, :rn, :rs, :rm

		addop_cond 'swp',   0b0001000000000000000010010000, :rd, :rn, :rs, :rm
		addop_cond 'swpb',  0b0001010000000000000010010000, :rd, :rn, :rs, :rm

		addop_datat 'ldr',  0b01000001 << 20
		addop_datat 'ldrb', 0b01000101 << 20
		addop_datat 'str',  0b01000000 << 20
		addop_datat 'strb', 0b01000100 << 20

		addop_cond 'undef', 0b00000110000000000000000000010000

		block_props = [:psr, :writeback]
		addop_variants 'ldmed',  0b10011001 << 20, block_props, :rn, :rlist
		addop_variants 'ldmfd',  0b10001001 << 20, block_props, :rn, :rlist
		addop_variants 'ldmea',  0b10001001 << 20, block_props, :rn, :rlist
		addop_variants 'ldmfa',  0b10000001 << 20, block_props, :rn, :rlist
		addop_variants 'stmfa',  0b10011000 << 20, block_props, :rn, :rlist
		addop_variants 'stmea',  0b10001000 << 20, block_props, :rn, :rlist
		addop_variants 'stmfd',  0b10010000 << 20, block_props, :rn, :rlist
		addop_variants 'stmed',  0b10000000 << 20, block_props, :rn, :rlist

		addop_cond 'b',  0b1010 << 24, :boffset, :setip
		addop_cond 'bl', 0b1011 << 24, :boffset, :setip, :saveip
		addop_cond 'blx',  0x12FFF30 , :rm, :setip
		addop_cond 'bx',  0x12FFF10 , :rm, :setip, :saveip

		
		#Coproc data transfer
		#Coproc data operation
		#Coproc register transfer
		
		#Software interrupt	
		addop_cond 'swi', 0b00001111 << 24

		#Other
		addop_cond 'bkpt',  0b1001000000000000001110000
		addop_cond 'movw',  0b0011 << 24, :movwimm
		#mov r0,r0 => nop
		addop_cond 'nop', 0xE1A00000 

	def addop_datat(name, bin, *args)
		vars = [:up, :preindexing, :writeback]
		addop_variants(name, bin, vars, :rd, :rn, :offsetimm, *args)
		addop_variants(name, bin | (1 << 25), vars, :rd, :rn, :offsetreg, *args)
	end

	def addop_variants(name, bin, options, *args)
		#XXX foireux mais bon
		choices = (1...options.length).inject([[],options]) {|res,i| res.concat(options.combination(i).to_a)}

		choices.each { |props|
			bin2 = props.inject(bin) {|b,o| b | (1 << @bits_pos[o])} 
			addop_ccodes(name, bin2, *args + props)
		}
	end

