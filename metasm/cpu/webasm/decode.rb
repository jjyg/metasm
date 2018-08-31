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

		code_start = addr
		stack = [[]]
		set_misc_x = lambda { |di, tg| di.misc[:x] ||= [] ; di.misc[:x] |= [tg] }
		while di = dasm.disassemble_instruction(addr)
			cache[addr] = di
			di.misc ||= {}
			di.misc[:code_start] = code_start
			case di.opcode.name
			when 'if', 'loop', 'block'
				stack << [di]
			when 'else'
				raise "bad #{di} #{stack.last.inspect}" if stack.last.empty? or stack.last.last.opcode.name != 'if'
				stack.last.each { |ddi| set_misc_x[ddi, di.next_addr] }	# 'if' points past here
				di.misc[:end_of] = stack.last[0]	# store matching 'if'
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
				dis.each { |ddi| set_misc_x[ddi, di.next_addr] if ddi.opcode.name != 'loop' and ddi.opcode.name != 'block' }
				if stack.empty?
					# stack empty: end of func
					di.opcode = @opcode_list.find { |op| op.name == 'end' and op.props[:stopexec] }
					break
				else
					if dis.first
						di.misc[:end_of] = dis.first	# store matching loop/block/if
						if dis.first.opcode.name == 'else'
							di.misc[:end_of] = dis.first.misc[:end_of]	# else patched stack.last, recover original 'if'
						end
					end
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
		case di.opcode.name
		when 'call'
			fnr = di.instruction.args.first.reduce
			di.misc ||= {}
			di.misc[:tg_func_nr] = fnr
			if f = @wasm_file.get_function_nr(fnr)
				tg = f[:init_offset] ? f[:init_offset] : "#{f[:module]}_#{f[:field]}"
				di.instruction.args[0] = Expression[tg]
				di.misc[:x] = [tg]
			else
				di.misc[:x] = [:default]
			end
		when 'call_indirect'
			di.misc ||= {}
			di.misc[:x] = [:default]
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

		typesz = Hash.new(8).update 'i32' => 4, 'f32' => 4
		opstack = lambda { |off, sz| Indirection[Expression[:opstack, :+, off].reduce, sz] }
		add_opstack = lambda { |delta, hash| { :opstack => Expression[:opstack, :+, delta].reduce }.update hash }
		globsz = lambda { |di|
			glob_nr = Expression[di.instruction.args.first].reduce
			g = @wasm_file.get_global_nr(glob_nr)
			g ? typesz[g[:type]] : 8
		}
		global = lambda { |di|
			glob_nr = Expression[di.instruction.args.first].reduce
			g = @wasm_file.get_global_nr(glob_nr)
			n = g && g[:module] ? "#{g[:module]}_#{g[:field]}" : "global_#{glob_nr}"
			Indirection[n, globsz[di]]
		}
		locsz = lambda { |di|
			loc_nr = Expression[di.instruction.args.first].reduce
			ci = @wasm_file.code_info[di.misc[:code_start]]
			next typesz[ci[:params][loc_nr]] if loc_nr < ci[:params].length
			loc_nr -= ci[:params].length
			next typesz[ci[:local_var][loc_nr]] if ci[:local_var][loc_nr]
			8
		}
		local = lambda { |di|
			loc_nr = Expression[di.instruction.args.first].reduce
			Indirection[[:local_base, :+, loc_nr*8], locsz[di]]
		}

		opcode_list.map { |ol| ol.name }.uniq.each { |opname|
			sz = (opname[1, 2] == '32' ? 4 : 8)
			@backtrace_binding[opname] ||= case opname
			when 'call', 'call_indirect'
				lambda { |di|
					stack_off = 0
					if opname == 'call'
						f = @wasm_file.get_function_nr(di.misc[:tg_func_nr])
						proto = f ? f[:type] : {}
						# TODO use local_base
						h = { :callstack => Expression[:callstack, :+, 8], Indirection[:callstack, 8] => Expression[di.next_addr] }
						proto_params_offset = 0
					else
						proto = @wasm_file.type[di.instruction.args.first.reduce]
						h = { :callstack => Expression[:callstack, :+, 8], Indirection[:callstack, 8] => Expression[di.next_addr], 'func_idx' => Expression[opstack[0, 4]] }
						stack_off += 8
						proto_params_offset = 1
					end
					stack_off -= 8*proto[:ret].to_a.length
					stack_off += 8*proto[:params].to_a.length
					h.update :opstack => Expression[:opstack, :+, stack_off]
					proto[:ret].to_a.each_with_index { |rt, i| h.update opstack[8*i, typesz[rt]] => Expression["ret_#{i}"] }
					proto[:params].to_a.each_with_index { |pt, i| h.update "param_#{i}" => Expression[opstack[8*(proto[:params].length-i-1+proto_params_offset), typesz[pt]]] }
					h
				}
			when 'if', 'br_if'; lambda { |di| add_opstack[ 8, :flag => Expression[opstack[0, 8]]] }
			when 'block', 'loop', 'br', 'nop', 'else'; lambda { |di| {} }
			when 'end', 'return'; lambda { |di| di.opcode.props[:stopexec] ? { :callstack => Expression[:callstack, :-, 8] } : {} }
			when 'drop'; lambda { |di| add_opstack[8, {}] }
			when 'select'; lambda { |di| add_opstack[16, opstack[0, 8] => Expression[[opstack[8, 8], :*, [1, :-, opstack[0, 8]]], :|, [opstack[16, 8], :*, opstack[0, 8]]]] }
			when 'get_local'; lambda { |di| add_opstack[-8, opstack[0, locsz[di]] => Expression[local[di]]] }
			when 'set_local'; lambda { |di| add_opstack[ 8, local[di] => Expression[opstack[0, locsz[di]]]] }
			when 'tee_local'; lambda { |di| add_opstack[ 0, local[di] => Expression[opstack[0, locsz[di]]]] }
			when 'get_global'; lambda { |di| add_opstack[-8, opstack[0, globsz[di]] => Expression[global[di]]] }
			when 'set_global'; lambda { |di| add_opstack[ 8, global[di] => Expression[opstack[0, globsz[di]]]] }
			when /\.load(.*)/
				mode = $1; memsz = (mode.include?('32') ? 4 : mode.include?('16') ? 2 : mode.include?('8') ? 1 : sz)
				lambda { |di| add_opstack[ 0, opstack[0, sz] => Expression[Indirection[[opstack[0, 4], :+, [:mem, :+, di.instruction.args[1].off]], memsz]]] }
			when /\.store(.*)/
				mode = $1; memsz = (mode.include?('32') ? 4 : mode.include?('16') ? 2 : mode.include?('8') ? 1 : sz)
				lambda { |di| add_opstack[ 16, Indirection[[opstack[8, 4], :+, [:mem, :+, di.instruction.args[1].off]], memsz] => Expression[opstack[0, sz], :&, (1 << (8*memsz)) - 1]] }
			when /\.const/; lambda { |di| add_opstack[-8, opstack[0, sz] => Expression[di.instruction.args.first.reduce]] }
			when /\.eqz/; lambda { |di| add_opstack[ 0, opstack[0, 8] => Expression[opstack[0, sz], :==, 0]] }
			when /\.eq/;  lambda { |di| add_opstack[ 8, opstack[0, 8] => Expression[opstack[8, sz], :==, opstack[0, sz]]] }
			when /\.ne/;  lambda { |di| add_opstack[ 8, opstack[0, 8] => Expression[opstack[8, sz], :!=, opstack[0, sz]]] }
			when /\.lt/;  lambda { |di| add_opstack[ 8, opstack[0, 8] => Expression[opstack[8, sz], :<,  opstack[0, sz]]] }
			when /\.gt/;  lambda { |di| add_opstack[ 8, opstack[0, 8] => Expression[opstack[8, sz], :>,  opstack[0, sz]]] }
			when /\.le/;  lambda { |di| add_opstack[ 8, opstack[0, 8] => Expression[opstack[8, sz], :<=, opstack[0, sz]]] }
			when /\.ge/;  lambda { |di| add_opstack[ 8, opstack[0, 8] => Expression[opstack[8, sz], :>=, opstack[0, sz]]] }

			when /\.(clz|ctz|popcnt)/; lambda { |di| add_opstack[ 0, :bits => Expression[opstack[0, sz]]] }
			when /\.add/; lambda { |di| add_opstack[ 8, opstack[0, sz] => Expression[opstack[8, sz], :+, opstack[0, sz]]] }
			when /\.sub/; lambda { |di| add_opstack[ 8, opstack[0, sz] => Expression[opstack[8, sz], :-, opstack[0, sz]]] }
			when /\.mul/; lambda { |di| add_opstack[ 8, opstack[0, sz] => Expression[opstack[8, sz], :*, opstack[0, sz]]] }
			when /\.div/; lambda { |di| add_opstack[ 8, opstack[0, sz] => Expression[opstack[8, sz], :/, opstack[0, sz]]] }
			when /\.rem/; lambda { |di| add_opstack[ 8, opstack[0, sz] => Expression[opstack[8, sz], :%, opstack[0, sz]]] }
			when /\.and/; lambda { |di| add_opstack[ 8, opstack[0, sz] => Expression[opstack[8, sz], :&, opstack[0, sz]]] }
			when /\.or/;  lambda { |di| add_opstack[ 8, opstack[0, sz] => Expression[opstack[8, sz], :|, opstack[0, sz]]] }
			when /\.xor/; lambda { |di| add_opstack[ 8, opstack[0, sz] => Expression[opstack[8, sz], :^, opstack[0, sz]]] }
			when /\.shl/; lambda { |di| add_opstack[ 8, opstack[0, sz] => Expression[opstack[8, sz], :<<, opstack[0, sz]]] }
			when /\.shr/; lambda { |di| add_opstack[ 8, opstack[0, sz] => Expression[opstack[8, sz], :>>, opstack[0, sz]]] }
			when /\.rotl/; lambda { |di| add_opstack[ 8, opstack[0, sz] => Expression[[opstack[8, sz], :<<, opstack[0, sz]], :|, [opstack[8, sz], :>>, [8*sz, :-, opstack[0, sz]]]]] }
			when /\.rotr/; lambda { |di| add_opstack[ 8, opstack[0, sz] => Expression[[opstack[8, sz], :>>, opstack[0, sz]], :|, [opstack[8, sz], :<<, [8*sz, :-, opstack[0, sz]]]]] }
			when /f.*\.(abs|neg|ceil|floor|trunc|nearest|sqrt|copysign)/; lambda { |di| add_opstack[0, :incomplete_binding => 1] }
			when /f.*\.(min|max)/; lambda { |di| add_opstack[8, :incomplete_binding => 1] }
			when /i32.wrap/; lambda { |di| add_opstack[ 0, opstack[0, 4] => Expression[opstack[0, 8]]] }
			when /i64.extend/; lambda { |di| add_opstack[ 0, opstack[0, 8] => Expression[opstack[0, 4]]] }
			when /trunc|convert|promote|demote|reinterpret/; lambda { |di| add_opstack[0, :incomplete_binding => 1] }
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

	def fix_fwdemu_binding(di, fbd)
		ori = fbd
		fbd = {}
		ori.each { |k, v|
			if k.kind_of?(Indirection) and not k.target.lexpr.kind_of?(Indirection)
				# dont fixup store8 etc
				fbd[k.bind(:opstack => ori[:opstack]).reduce_rec] = v
			else
				fbd[k] = v
			end
		}
		fbd
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

	def backtrace_is_stack_address(expr)
		([:local_base, :opstack] & Expression[expr].expr_externals).first
	end

	def decode_c_function_prototype(cp, sym, orig=nil)
		disassembler_default_func
	end
end
end
