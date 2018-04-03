#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/webasm/opcodes'
require 'metasm/decode'

module Metasm
class WebAsm
	def build_bin_lookaside
		lookaside = (0..0xff).inject({}) { |h, i| h.update i => [] }
		opcode_list.each { |op|
			lookaside[op.bin] << op
		}
		lookaside
	end

	def decode_uleb(ed, signed=false)
		v = s = 0
		while s < 5*7
			b = ed.read(1).unpack('C').first.to_i
			v |= (b & 0x7f) << s
			s += 7
			break if (b&0x80) == 0
		end
		v = Expression.make_signed(v, s) if signed
		v
	end

	# when starting disassembly, pre-decode all instructions until the final 'end' and fixup the xrefs (if/block/loop...)
	def disassemble_init_context(dasm, addr)
		cache = {}
		stack = []
		loop do
			di = dasm.disassemble_instruction(addr)
			cache[addr] = di
			case di.opcode.name
			when 'if', 'loop', 'block'
				stack << [di]
			when 'else'
				raise "bad else #{stack.last.inspect}" if stack.last.length != 1 or stack.last.last.opcode.name != 'if'
				stack.last.each { |ddi| ddi.misc = { :x => di.next_addr } }	# if points past here
				stack.last.shift	# remove if from list
				stack.last << di
			when 'br', 'br_if'
				# tg = stack[-arg[0]]
				# if loop: set misc[:x]
				# if block: stack[-arg] << di
			when 'br_table'
			when 'end'
				ops = stack.pop
				if not ops
					# stack empty: end of func
					di.opcode = @opcode_list.find { |op| op.name == 'end' and op.props[:stopexec] and not op.props[:setip] }

					break
				elsif ops.first.opcode.name == 'loop'
					# end of loop
					di.opcode = @opcode_list.find { |op| op.name == 'end' and op.props[:stopexec] and op.props[:setip] }
					di.misc = { :x => ops.first.address }
				else
					# end of if/else/block
					di.opcode = @opcode_list.find { |op| op.name == 'end' and not op.props[:stopexec] and not op.props[:setip] }
					ops.each { |ddi| ddi.misc = { :x => di.address } }
				end
			end
			addr = di.next_addr
		end

		{ :di_cache => cache }
	end

	# reuse the instructions from the cache
	def decode_instruction_context(edata, di_addr, ctx)
		if ctx
			ctx[:di_cache][di_addr]
		end or super(edata, di_addr, ctx)
	end

	def decode_findopcode(edata)
		di = DecodedInstruction.new(self)
		val = edata.decode_imm(:u8, @endianness)
		di if di.opcode = bin_lookaside[val].first
	end

	def decode_instr_op(edata, di)
		before_ptr = edata.ptr
		op = di.opcode
		di.instruction.opname = op.name

		op.args.each { |a|
			di.instruction.args << case a
			when :f32; Expression[edata.decode_imm(:u32, @endianness)]
			when :f64; Expression[edata.decode_imm(:u64, @endianness)]
			when :memoff; Memref.new(decode_uleb(edata))
			when :uleb; Expression[decode_uleb(edata)]
			when :sleb; Expression[decode_uleb(edata, true)]
			when :br_table; decode_br_table(edata)
			else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
			end
		}

		di.bin_length = 1 + edata.ptr - before_ptr
		di
	end

	def decode_br_table(edata)
		count = decode_uleb(edata)
		ary = []
		count.times { ary << decode_uleb(edata) }
		default = decode_uleb(edata)
		BrTable.new(ary, default)
	end

	def init_backtrace_binding
		@backtrace_binding ||= {}

		opcode_list.map { |ol| ol.name }.uniq.each { |op|
			@backtrace_binding[op] ||= case op
			when 'nop'; lambda { |di| {} }
			end
		}

		@backtrace_binding
	end

	def get_backtrace_binding(di)
		if binding = backtrace_binding[di.opcode.name]
			binding[di] || {}
		else
			puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
			{:incomplete_binding => Expression[1]}
		end
	end

	def get_xrefs_x(dasm, di)
		return [] if not di.opcode.props[:setip]
		di.misc ? [di.misc[:x]] : []
	end
end
end
