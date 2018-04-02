#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/ebpf/opcodes'
require 'metasm/decode'

module Metasm
class EBPF
	def build_bin_lookaside
		opcode_list.inject({}) { |h, op| h.update op.bin => op }
	end

	# tries to find the opcode encoded at edata.ptr
	def decode_findopcode(edata)
		return if edata.ptr > edata.data.length-8
		di = DecodedInstruction.new self
		code_off = (@endianness == :little ? 0 : 7)
		code = edata.data[edata.ptr+code_off, 1].unpack('C')[0]
		return di if di.opcode = @bin_lookaside[code]
	end

	def decode_instr_op(edata, di)
		op = di.opcode
		di.instruction.opname = op.name
		di.bin_length = 8
		blob = edata.decode_imm(:u64, @endianness)
		imm = (blob >> 32) & 0xffff_ffff
		imm = Expression.make_signed(imm, 32)
		off = (blob >> 16) & 0xffff
		off = Expression.make_signed(off, 16)
		src = (blob >> 12) & 0xf
		dst = (blob >>  8) & 0xf
		#code = blob & 0xff

		if di.opcode.props[:imm64]
			imm = (imm & 0xffff_ffff) | (edata.decode_imm(:u64, @endianness) & 0xffff_ffff_0000_0000)	# next_imm << 32
			di.bin_length += 8
		end

		op.args.each { |a|
			di.instruction.args << case a
			when :i;    Expression[imm]
			when :r0;   Reg.new(0)
			when :rs;   Reg.new(src)
			when :rd;   Reg.new(dst)
			when :off;  Expression[off]
			when :p_rs_o; Memref.new(Reg.new(src), Expression[off], op.props[:msz])
			when :p_rd_o; Memref.new(Reg.new(dst), Expression[off], op.props[:msz])
			when :p_pkt_i; Pktref.new(nil, Expression[imm], op.props[:msz])
			when :p_pkt_rs_i; Pktref.new(Reg.new(src), Expression[imm], op.props[:msz])
			else raise "unhandled arg #{a}"
			end
		}

		di
	end

	def decode_instr_interpret(di, addr)
		if di.opcode.props[:setip]
			delta = di.instruction.args[-1].reduce + 1
			arg = Expression[addr, :+, 8*delta].reduce
			di.instruction.args[-1] = Expression[arg]
		end

		di
	end

	# populate the @backtrace_binding hash with default values
	def init_backtrace_binding
		@backtrace_binding ||= {}

		bswap = lambda { |val, nbytes|
			case nbytes
			when 1; val
			when 2; Expression[[[val, :&, 0xff], :<<, 8], :|, [[val, :&, 0xff00], :>>, 8]]
			when 4; Expression[[bswap[Expression[val, :&, 0xffff], 2], :<<, 16], :|, bswap[Expression[[val, :>>, 16], :&, 0xffff], 2]]
			when 8; Expression[[bswap[Expression[val, :&, 0xffffffff], 4], :<<, 32], :|, bswap[Expression[[val, :>>, 32], :&, 0xffffffff], 4]]
			end
		}

		opcode_list.map { |ol| ol.basename }.uniq.sort.each { |op|
			binding = case op

			when 'add'; lambda { |di, a0, a1| { a0 => Expression[a0, :+, a1] } }
			when 'sub'; lambda { |di, a0, a1| { a0 => Expression[a0, :-, a1] } }
			when 'mul'; lambda { |di, a0, a1| { a0 => Expression[[a0, :*, a1], :&, 0xffff_ffff_ffff_ffff] } }
			when 'div'; lambda { |di, a0, a1| { a0 => Expression[a0, :/, a1] } }
			when 'or';  lambda { |di, a0, a1| { a0 => Expression[a0, :|, a1] } }
			when 'and'; lambda { |di, a0, a1| { a0 => Expression[a0, :&, a1] } }
			when 'shl'; lambda { |di, a0, a1| { a0 => Expression[[a0, :<<, a1], :&, 0xffff_ffff_ffff_ffff] } }
			when 'shr'; lambda { |di, a0, a1| { a0 => Expression[a0, :>>, a1] } }	# XXX sign
			when 'neg'; lambda { |di, a0|     { a0 => Expression[:-, a0] } }
			when 'mod'; lambda { |di, a0, a1| { a0 => Expression[a0, :%, a1] } }
			when 'xor'; lambda { |di, a0, a1| { a0 => Expression[a0, :^, a1] } }
			when 'mov'; lambda { |di, a0, a1| { a0 => Expression[a1] } }
			when 'sar'; lambda { |di, a0, a1| { a0 => Expression[a0, :>>, a1] } }

			when 'add32'; lambda { |di, a0, a1| { a0 => Expression[[a0, :+, a1], :&, 0xffff_ffff] } }
			when 'sub32'; lambda { |di, a0, a1| { a0 => Expression[[a0, :-, a1], :&, 0xffff_ffff] } }
			when 'mul32'; lambda { |di, a0, a1| { a0 => Expression[[a0, :*, a1], :&, 0xffff_ffff] } }
			when 'div32'; lambda { |di, a0, a1| { a0 => Expression[[a0, :/, a1], :&, 0xffff_ffff] } }
			when 'or32';  lambda { |di, a0, a1| { a0 => Expression[[a0, :|, a1], :&, 0xffff_ffff] } }
			when 'and32'; lambda { |di, a0, a1| { a0 => Expression[[a0, :&, a1], :&, 0xffff_ffff] } }
			when 'shl32'; lambda { |di, a0, a1| { a0 => Expression[[a0, :<<, a1], :&, 0xffff_ffff] } }
			when 'shr32'; lambda { |di, a0, a1| { a0 => Expression[[[a0, :&, 0xffff_ffff], :>>, a1], :&, 0xffff_ffff] } }	# XXX sign
			when 'neg32'; lambda { |di, a0|     { a0 => Expression[:-, [a0, :&, 0xffff_ffff]] } }
			when 'mod32'; lambda { |di, a0, a1| { a0 => Expression[[a0, :%, a1], :&, 0xffff_ffff] } }
			when 'xor32'; lambda { |di, a0, a1| { a0 => Expression[[a0, :^, a1], :&, 0xffff_ffff] } }
			when 'mov32'; lambda { |di, a0, a1| { a0 => Expression[a1, :&, 0xffff_ffff] } }
			when 'sar32'; lambda { |di, a0, a1| { a0 => Expression[[[a0, :&, 0xffff_ffff], :>>, a1], :&, 0xffff_ffff] } }

			when 'be', 'le'; lambda { |di, a0, a1|
				if @endianness.to_s[0] == di.opcode.name[0]
					{}
				else
					{ a1 => bswap[a1, Expression[a0].reduce] }
				end
			}
			when /^ldind|^ldabs|^stind|^stabs/; lambda { |di, a0, a1|
				if @endianness == :big
					{ a0 => Expression[a1] }
				else
					{ a0 => bswap[a1, di.opcode.props[:msz]] }
				end
			}
			when /^ld|^st/; lambda { |di, a0, a1| { a0 => Expression[a1] } }
			when /^xadd/; lambda { |di, a0, a1| { a0 => Expression[a0, :+, a1] } }	# XXX bswap ?

			when 'call'; lambda { |di, *a| { :r0 => Expression::Unknown } }

			when 'jmp', 'jeq', 'jgt', 'jge', 'jset', 'jne', 'jsgt', 'jsge'; lambda { |di, *a| { } }
			end
			@backtrace_binding[op] ||= binding if binding
		}

		@backtrace_binding
	end
end
end
