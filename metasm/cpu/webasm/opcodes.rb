#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/webasm/main'

module Metasm
class WebAsm
	def addop(name, bin, *args)
		o = Opcode.new name, bin

		args.each { |a|
			if a == :mem
				o.args << :uleb << :memoff
			elsif @valid_props[a]
				o.props[a] = true
			else
				o.args << a
			end
		}

		@opcode_list << o
	end

	def init
		@opcode_list = []
		@valid_props = { :setip => true, :stopexec => true, :saveip => true }

		addop 'unreachable',   0x00, :stopexec
		addop 'nop',           0x01
		addop 'block',         0x02, :blocksig		# arg = signature (block_type)
		addop 'loop',          0x03, :blocksig		# ^
		addop 'if',            0x04, :blocksig, :setip	# ^
		addop 'else',          0x05, :setip, :stopexec
		addop 'end',           0x0b, :stopexec		# end of function (default with no function context)
		addop 'end',           0x0b			# end of if/else/block/loop
		addop 'br',            0x0c, :uleb, :setip, :stopexec	# arg = depth to break up to
		addop 'br_if',         0x0d, :uleb, :setip
		addop 'br_table',      0x0e, :br_table, :setip, :stopexec
		addop 'return',        0x0f, :stopexec
		addop 'call',          0x10, :uleb, :setip, :saveip, :stopexec	# function index
		addop 'call_indirect', 0x11, :uleb, :uleb, :setip, :saveip, :stopexec	# type index for target function signature ; table index where the function indexes come from (fixed 0)

		addop 'drop',   0x1a
		addop 'select', 0x1b

		addop 'get_local',  0x20, :uleb
		addop 'set_local',  0x21, :uleb
		addop 'tee_local',  0x22, :uleb
		addop 'get_global', 0x23, :uleb
		addop 'set_global', 0x24, :uleb

		addop 'i32.load', 0x28, :mem
		addop 'i64.load', 0x29, :mem
		addop 'f32.load', 0x2a, :mem
		addop 'f64.load', 0x2b, :mem
		addop 'i32.load8_s',  0x2c, :mem
		addop 'i32.load8_u',  0x2d, :mem
		addop 'i32.load16_s', 0x2e, :mem
		addop 'i32.load16_u', 0x2f, :mem
		addop 'i64.load8_s',  0x30, :mem
		addop 'i64.load8_u',  0x31, :mem
		addop 'i64.load16_s', 0x32, :mem
		addop 'i64.load16_u', 0x33, :mem
		addop 'i64.load32_s', 0x34, :mem
		addop 'i64.load32_u', 0x35, :mem
		addop 'i32.store',   0x36, :mem
		addop 'i64.store',   0x37, :mem
		addop 'f32.store',   0x38, :mem
		addop 'f64.store',   0x39, :mem
		addop 'i32.store8',  0x3a, :mem
		addop 'i32.store16', 0x3b, :mem
		addop 'i64.store8',  0x3c, :mem
		addop 'i64.store16', 0x3d, :mem
		addop 'i64.store32', 0x3e, :mem
		addop 'current_memory', 0x3f, :uleb	# resv1
		addop 'grow_memory', 0x40, :uleb	# resv1

		addop 'i32.const', 0x41, :sleb
		addop 'i64.const', 0x42, :sleb
		addop 'f32.const', 0x43, :f32
		addop 'f64.const', 0x44, :f64

		addop 'i32.eqz', 0x45	 	 
		addop 'i32.eq', 0x46	 	 
		addop 'i32.ne', 0x47	 	 
		addop 'i32.lt_s', 0x48	 	 
		addop 'i32.lt_u', 0x49	 	 
		addop 'i32.gt_s', 0x4a	 	 
		addop 'i32.gt_u', 0x4b	 	 
		addop 'i32.le_s', 0x4c	 	 
		addop 'i32.le_u', 0x4d	 	 
		addop 'i32.ge_s', 0x4e	 	 
		addop 'i32.ge_u', 0x4f	 	 
		addop 'i64.eqz', 0x50	 	 
		addop 'i64.eq', 0x51	 	 
		addop 'i64.ne', 0x52	 	 
		addop 'i64.lt_s', 0x53	 	 
		addop 'i64.lt_u', 0x54	 	 
		addop 'i64.gt_s', 0x55	 	 
		addop 'i64.gt_u', 0x56	 	 
		addop 'i64.le_s', 0x57	 	 
		addop 'i64.le_u', 0x58	 	 
		addop 'i64.ge_s', 0x59	 	 
		addop 'i64.ge_u', 0x5a	 	 
		addop 'f32.eq', 0x5b	 	 
		addop 'f32.ne', 0x5c	 	 
		addop 'f32.lt', 0x5d	 	 
		addop 'f32.gt', 0x5e	 	 
		addop 'f32.le', 0x5f	 	 
		addop 'f32.ge', 0x60	 	 
		addop 'f64.eq', 0x61	 	 
		addop 'f64.ne', 0x62	 	 
		addop 'f64.lt', 0x63	 	 
		addop 'f64.gt', 0x64	 	 
		addop 'f64.le', 0x65	 	 
		addop 'f64.ge', 0x66	 	 

		addop 'i32.clz', 0x67	 	 
		addop 'i32.ctz', 0x68	 	 
		addop 'i32.popcnt', 0x69	 	 
		addop 'i32.add', 0x6a	 	 
		addop 'i32.sub', 0x6b	 	 
		addop 'i32.mul', 0x6c	 	 
		addop 'i32.div_s', 0x6d	 	 
		addop 'i32.div_u', 0x6e	 	 
		addop 'i32.rem_s', 0x6f	 	 
		addop 'i32.rem_u', 0x70	 	 
		addop 'i32.and', 0x71	 	 
		addop 'i32.or', 0x72	 	 
		addop 'i32.xor', 0x73	 	 
		addop 'i32.shl', 0x74	 	 
		addop 'i32.shr_s', 0x75	 	 
		addop 'i32.shr_u', 0x76	 	 
		addop 'i32.rotl', 0x77	 	 
		addop 'i32.rotr', 0x78	 	 
		addop 'i64.clz', 0x79	 	 
		addop 'i64.ctz', 0x7a	 	 
		addop 'i64.popcnt', 0x7b	 	 
		addop 'i64.add', 0x7c	 	 
		addop 'i64.sub', 0x7d	 	 
		addop 'i64.mul', 0x7e	 	 
		addop 'i64.div_s', 0x7f	 	 
		addop 'i64.div_u', 0x80	 	 
		addop 'i64.rem_s', 0x81	 	 
		addop 'i64.rem_u', 0x82	 	 
		addop 'i64.and', 0x83	 	 
		addop 'i64.or', 0x84	 	 
		addop 'i64.xor', 0x85	 	 
		addop 'i64.shl', 0x86	 	 
		addop 'i64.shr_s', 0x87	 	 
		addop 'i64.shr_u', 0x88	 	 
		addop 'i64.rotl', 0x89	 	 
		addop 'i64.rotr', 0x8a	 	 
		addop 'f32.abs', 0x8b	 	 
		addop 'f32.neg', 0x8c	 	 
		addop 'f32.ceil', 0x8d	 	 
		addop 'f32.floor', 0x8e	 	 
		addop 'f32.trunc', 0x8f	 	 
		addop 'f32.nearest', 0x90	 	 
		addop 'f32.sqrt', 0x91	 	 
		addop 'f32.add', 0x92	 	 
		addop 'f32.sub', 0x93	 	 
		addop 'f32.mul', 0x94	 	 
		addop 'f32.div', 0x95	 	 
		addop 'f32.min', 0x96	 	 
		addop 'f32.max', 0x97	 	 
		addop 'f32.copysign', 0x98	 	 
		addop 'f64.abs', 0x99	 	 
		addop 'f64.neg', 0x9a	 	 
		addop 'f64.ceil', 0x9b	 	 
		addop 'f64.floor', 0x9c	 	 
		addop 'f64.trunc', 0x9d	 	 
		addop 'f64.nearest', 0x9e	 	 
		addop 'f64.sqrt', 0x9f	 	 
		addop 'f64.add', 0xa0	 	 
		addop 'f64.sub', 0xa1	 	 
		addop 'f64.mul', 0xa2	 	 
		addop 'f64.div', 0xa3	 	 
		addop 'f64.min', 0xa4	 	 
		addop 'f64.max', 0xa5	 	 
		addop 'f64.copysign', 0xa6	 	 

		addop 'i32.wrap/i64', 0xa7	 	 
		addop 'i32.trunc_s/f32', 0xa8	 	 
		addop 'i32.trunc_u/f32', 0xa9	 	 
		addop 'i32.trunc_s/f64', 0xaa	 	 
		addop 'i32.trunc_u/f64', 0xab	 	 
		addop 'i64.extend_s/i32', 0xac	 	 
		addop 'i64.extend_u/i32', 0xad	 	 
		addop 'i64.trunc_s/f32', 0xae	 	 
		addop 'i64.trunc_u/f32', 0xaf	 	 
		addop 'i64.trunc_s/f64', 0xb0	 	 
		addop 'i64.trunc_u/f64', 0xb1	 	 
		addop 'f32.convert_s/i32', 0xb2	 	 
		addop 'f32.convert_u/i32', 0xb3	 	 
		addop 'f32.convert_s/i64', 0xb4	 	 
		addop 'f32.convert_u/i64', 0xb5	 	 
		addop 'f32.demote/f64', 0xb6	 	 
		addop 'f64.convert_s/i32', 0xb7	 	 
		addop 'f64.convert_u/i32', 0xb8	 	 
		addop 'f64.convert_s/i64', 0xb9	 	 
		addop 'f64.convert_u/i64', 0xba	 	 
		addop 'f64.promote/f32', 0xbb	 	 

		addop 'i32.reinterpret/f32', 0xbc	 	 
		addop 'i64.reinterpret/f64', 0xbd	 	 
		addop 'f32.reinterpret/i32', 0xbe	 	 
		addop 'f64.reinterpret/i64', 0xbf
	end

end
end
