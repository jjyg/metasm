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
			when :p_rs_o; MemRef.new(Reg.new(src), Expression[off], op.props[:msz])
			when :p_rd_o; MemRef.new(Reg.new(dst), Expression[off], op.props[:msz])
			when :p_pkt_i; PktRef.new(nil, Expression[imm], op.props[:msz])
			when :p_pkt_rs_i; PktRef.new(Reg.new(src), Expression[imm], op.props[:msz])
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

	# hash opcode_name => lambda { |dasm, di, *symbolic_args| instr_binding }
	def backtrace_binding
		@backtrace_binding ||= init_backtrace_binding
	end
	def backtrace_binding=(b) @backtrace_binding = b end

	# populate the @backtrace_binding hash with default values
	def init_backtrace_binding
		@backtrace_binding ||= {}

		opcode_list.map { |ol| ol.basename }.uniq.sort.each { |op|
			binding = case op

			when 'add'; lambda { |di, a0, a1| { a0 => Expression[a0, :+, a1] } }
			when 'sub'; lambda { |di, a0, a1| { a0 => Expression[a0, :-, a1] } }
			when 'mul'; lambda { |di, a0, a1| { a0 => Expression[a0, :*, a1] } }
			when 'div'; lambda { |di, a0, a1| { a0 => Expression[a0, :/, a1] } }
			when 'or';  lambda { |di, a0, a1| { a0 => Expression[a0, :|, a1] } }
			when 'and'; lambda { |di, a0, a1| { a0 => Expression[a0, :&, a1] } }
			when 'shl'; lambda { |di, a0, a1| { a0 => Expression[a0, :<<, a1] } }
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

			when /^ld/; lambda { |di, a0, a1| { a0 => Expression[a1] } }
			when /^st/; lambda { |di, a0, a1| { a0 => Expression[a1] } }
			when /^xadd/; lambda { |di, a0, a1| { a0 => Expression[a0, :+, a1] } }

			when 'call'; lambda { |di, *a| { :r0 => Expression::Unknown } }

			when 'jmp', 'jeq', 'jgt', 'jge', 'jset', 'jne', 'jsgt', 'jsge'; lambda { |di, *a| { } }
			end
			@backtrace_binding[op] ||= binding if binding
		}

		@backtrace_binding
	end

	def get_backtrace_binding(di)
		a = di.instruction.args.map { |arg|
			case arg
			when MemRef, Reg; arg.symbolic(di)
			else arg
			end
		}

		if binding = backtrace_binding[di.opcode.name]
			binding[di, *a]
		else
			puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
			{:incomplete_binding => Expression[1]}
		end
	end

	def get_xrefs_x(dasm, di)
		return [] if not di.opcode.props[:setip]

		if di.instruction.args.length == 4
			di.instruction.args[-2, 2]
		else
			di.instruction.args[-1, 1]
		end
	end

	# updates an instruction's argument replacing an expression with another (eg label renamed)
	def replace_instr_arg_immediate(i, old, new)
		i.args.map! { |a|
			case a
			when Expression; a == old ? new : Expression[a.bind(old => new).reduce]
			else a
			end
		}
	end
end
end
