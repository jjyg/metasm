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
		while s < 10*7
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
		dasm.misc ||= {}
		dasm.misc[:cpu_context] ||= {}
		cache = dasm.misc[:cpu_context][:di_cache] ||= {}
		addr = dasm.normalize(addr)
		return dasm.misc[:cpu_context] if cache[addr]

		stack = [[]]
		set_misc_x = lambda { |di, tg| di.misc ||= { :x => [] } ; di.misc[:x] |= [tg] }
		while di = dasm.disassemble_instruction(addr)
			cache[addr] = di
			case di.opcode.name
			when 'if', 'loop', 'block'
				stack << [di]
			when 'else'
				raise "bad #{di} #{stack.last.inspect}" if stack.last.empty? or stack.last.last.opcode.name != 'if'
				stack.last.each { |ddi| set_misc_x[ddi, di.next_addr] }	# 'if' points past here
				stack.last[0] = di	# 'else' replace 'if'
			when 'br', 'br_if', 'br_table'
				if di.opcode.name == 'br_table'
					depths = di.instruction.args.first.ary.uniq | [di.instruction.args.first.default]
				else
					depths = [di.instruction.args.first.reduce]
				end
				depths.each { |depth|
					tg = stack[-depth-1] # XXX skip if/else in the stack ?
					raise "bad #{di} (#{stack.length})" if not tg
					if tg.first and tg.first.opcode.name == 'loop'
						set_misc_x[di, tg.first.address]
					else
						tg << di
					end
				}
			when 'end'
				dis = stack.pop
				dis.each { |ddi| set_misc_x[ddi, di.address] if ddi.opcode.name != 'loop' and ddi.opcode.name != 'block' }
				if stack.empty?
					# stack empty: end of func
					di.opcode = @opcode_list.find { |op| op.name == 'end' and op.props[:stopexec] }
					break
				else
					di.opcode = @opcode_list.find { |op| op.name == 'end' and not op.props[:stopexec] }
				end
			end
			addr = di.next_addr
		end

		dasm.misc[:cpu_context]
	end

	# reuse the instructions from the cache
	def decode_instruction_context(dasm, edata, di_addr, ctx)
		ctx ||= disassemble_init_context(dasm, di_addr)
		if not ctx[:di_cache][di_addr]
			di_addr = dasm.normalize(di_addr)
			disassemble_init_context(dasm, di_addr)
		end
		ctx[:di_cache][di_addr]
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
			when :blocksig; BlockSignature.new(decode_uleb(edata, true))
			when :br_table; decode_br_table(edata)
			else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
			end
		}

		di.bin_length = 1 + edata.ptr - before_ptr
		di
	end

	def decode_instr_interpret(di, addr)
		if di.opcode.name == 'call'
			fnr = di.instruction.args.first.reduce
			if @wasm_file and @wasm_file.function_body and f = @wasm_file.function_body[fnr]
				di.instruction.args[0] = Expression[f[:init_offset]]
				di.misc = { :x => [f[:init_offset]] }
			else
				di.misc = { :x => [:default] }
			end
		end
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

		opstack = lambda { |off| Indirection[[:opstack, :+, off], 8] }
		add_opstack = lambda { |delta, hash| { :opstack => Expression[:opstack, :+, delta] }.update hash }
		global = lambda { |di| Indirection['global_%d' % Expression[di.instruction.args.first].reduce, 8] }
		local = lambda { |di| ('local_%d' % Expression[di.instruction.args.first].reduce).to_sym }

		opcode_list.map { |ol| ol.name }.uniq.each { |opname|
			@backtrace_binding[opname] ||= case opname
			when 'call'; lambda { |di, *a|
				{ :callstack => Expression[:callstack, :+, 8], Indirection[:callstack, 8] => Expression[di.next_addr] } }
			when 'end', 'return'; lambda { |di|
				{ :callstack => Expression[:callstack, :-, 8] } if di.opcode.props[:stopexec] }
			when 'nop'; lambda { |di| {} }
			when 'get_global'; lambda { |di| add_opstack[-8, opstack[0] => Expression[global[di]]] }
			when 'set_global'; lambda { |di| add_opstack[ 8, global[di] => Expression[opstack[0]]] }
			when 'get_local'; lambda { |di| add_opstack[-8, opstack[0] => Expression[local[di]]] }
			when 'set_local'; lambda { |di| add_opstack[ 8, local[di] => Expression[opstack[0]]] }
			when 'tee_local'; lambda { |di| add_opstack[ 0, local[di] => Expression[opstack[0]]] }
			when 'i32.const'; lambda { |di| add_opstack[-8, opstack[0] => Expression[di.instruction.args.first.reduce]] }
			when 'i64.const'; lambda { |di| add_opstack[-8, opstack[0] => Expression[di.instruction.args.first.reduce]] }
			when 'i32.add'; lambda { |di| add_opstack[ 8, opstack[0] => Expression[opstack[0], :+, opstack[8]]] }
			when 'i32.and'; lambda { |di| add_opstack[ 8, opstack[0] => Expression[opstack[0], :&, opstack[8]]] }
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
		if di.opcode.props[:stopexec]
			case di.opcode.name
			when 'return', 'end'
				return [Indirection[:callstack, 8]]
			end
		end
		return [] if not di.opcode.props[:setip]

		di.misc ? [di.misc[:x]].flatten : []
	end

	def backtrace_is_function_return(expr, di=nil)
		expr and Expression[expr] == Expression[Indirection[:callstack, 8]]
	end

	def disassembler_default_func
		df = DecodedFunction.new
		ra = Indirection[:callstack, 8]
		df.backtracked_for << BacktraceTrace.new(ra, :default, ra, :x, nil)
		df.backtrace_binding = { :callstack => Expression[:callstack, :-, 8] }
		df
	end

	def backtrace_update_function_binding(dasm, faddr, f, retaddrlist, *wantregs)
		f.backtrace_binding = { :callstack => Expression[:callstack, :-, 8] }
	end
end
end
