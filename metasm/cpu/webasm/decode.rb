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

	# implement a DecodedInstruction cache because we need to repeatedly decode opcodes to resolve code flow
	def get_di_cache(edata)
		@di_cache ||= {}
		@di_cache[[edata.object_id, edata.ptr]]
	end
	def set_di_cache(edata, di)
		@di_cache ||= {}
		@di_cache[[edata.object_id, edata.ptr - di.bin_length]] = di
	end

	def decode_findopcode(edata)
		di = get_di_cache(edata)
		return di if di

		return if edata.ptr >= edata.length

		di = DecodedInstruction.new(self)
		di.bin_length = 1
		val = edata.decode_imm(:u8, @endianness)
		di if di.opcode = @bin_lookaside[val].first
	end

	def decode_instr_op(edata, di)
		return di if di.instruction.opname	# already cached

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

		di.bin_length += edata.ptr - before_ptr

		return if edata.ptr > edata.length

		set_di_cache(edata, di)

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

		out = []

		case di.opcode.name
		when 'if'
			stack = []
			iter_di(dasm, di) { |ddi|
				case ddi.opcode.name
				when 'if', 'loop', 'block'
					stack << di.opcode.name
				when 'else'
					if stack.empty?
						out << ddi.next_addr
						break
					end
				when 'end'
					if stack.empty?
						out << ddi.next_addr
						break
					else
						stack.pop
					end
				end
			}
		when 'else'
			stack = []
			iter_di(dasm, di) { |ddi|
				case ddi.opcode.name
				when 'if', 'loop', 'block'
					stack << di.opcode.name
				when 'end'
					if stack.empty?
						out << ddi.next_addr
						break
					else
						stack.pop
					end
				end
			}
		end

		out
	end

	def iter_di(dasm, di)
		addr = di.next_addr
		while ddi = dasm.di_at(addr) || dasm.disassemble_instruction(addr)
			addr = ddi.next_addr
			yield ddi
		end
	end
end
end
