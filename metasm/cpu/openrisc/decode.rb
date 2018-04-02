#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/openrisc/opcodes'
require 'metasm/decode'

module Metasm
class OpenRisc
	def build_bin_lookaside
		bl = Array.new(255) { [] }
		opcode_list.each { |op|
			((op.bin >> 24) .. ((op.bin | op.bin_mask) >> 24)).each { |b|
				if (b | (op.bin_mask >> 24)) == ((op.bin | op.bin_mask) >> 24)
					bl[b] << op
				end
			}
		}
		bl
	end

	# tries to find the opcode encoded at edata.ptr
	def decode_findopcode(edata)
		return if edata.ptr > edata.data.length-4
		di = DecodedInstruction.new self
		val = edata.decode_imm(:u32, @endianness)
		di.misc = val
		return di if di.opcode = @bin_lookaside[val >> 24].find { |op|
			(op.bin | op.bin_mask) == (val | op.bin_mask)
		}
	end

	def decode_instr_op(edata, di)
		op = di.opcode
		di.instruction.opname = op.name
		di.bin_length = 4
		val = di.misc
		fld = lambda { |f|
			(val >> @fields_off[f]) & @fields_mask[f]
		}
		sign_fld = lambda { |f, sz|
			Expression.make_signed(Expression[fld[f]], sz).reduce
		}
		fld_smoo = lambda {
			Expression[Expression.make_signed((val & 0x7ff) | ((val >> 10) & 0xF800), 16)]
		}

		op.args.each { |a|
			di.instruction.args << case a
			when :rA, :rB, :rD; Reg.new(fld[a])
			when :fA; FpReg.new(fld[:rA])
			when :fB; FpReg.new(fld[:rB])
			when :fD; FpReg.new(fld[:rD])
			when :disp26; Expression[sign_fld[a, 26]]
			when :uimm5, :uimm16; Expression[fld[a]]
			when :simm16; Expression[sign_fld[a, 16]]
			when :rA_simm16; Memref.new(Reg.new(fld[:rA]), Expression[sign_fld[:simm16, 16]], di.opcode.props[:memsz])
			when :rA_smoo; Memref.new(Reg.new(fld[:rA]), fld_smoo[], di.opcode.props[:memsz])
			else raise "unhandled arg #{a}"
			end
		}

		di
	end

	def decode_instr_interpret(di, addr)
		if di.opcode.props[:setip]
			case di.opcode.name
			when 'j', 'jal', 'bf', 'bnf'
				# abs26 is not absolute, duh
				arg = Expression[addr, :+, [di.instruction.args[-1], :<<, 2]].reduce
				di.instruction.args[-1] = Expression[arg]
			end
		end

		di
	end

	# populate the @backtrace_binding hash with default values
	def init_backtrace_binding
		@backtrace_binding ||= {}

		opcode_list.map { |ol| ol.basename }.uniq.sort.each { |op|
			binding = case op
			when 'movhi'; lambda { |di, a0, a1| { a0 => Expression[a1, :<<, 16] } }
			when 'add'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :+, a2] } }
			when 'sub'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :-, a2] } }
			when 'mul'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :*, a2] } }
			when 'div'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :/, a2] } }
			when 'and'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :&, a2] } }
			when 'or';  lambda { |di, a0, a1, a2| { a0 => Expression[a1, :|, a2] } }
			when 'xor'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :^, a2] } }
			when 'shl'; lambda { |di, a0, a1, a2| { a0 => Expression[[a1, :<<, a2], :&, 0xffff_ffff] } }
			when 'shr'; lambda { |di, a0, a1, a2| { a0 => Expression[[a1, :>>, a2], :&, 0xffff_ffff] } }
			when 'sar'; lambda { |di, a0, a1, a2| { a0 => Expression[[[a1, :>>, a2], :|, [[0xffff_ffff, :<<, a2], :*, [a1, :>>, 31]]], :&, 0xffff_ffff] } }
			when 'ror'; lambda { |di, a0, a1, a2| { a0 => Expression[[[a1, :>>, a2], :|, [a1, :<<, [32, :-, a2]]], :&, 0xffff_ffff] } }
			when 'lwz', 'lbz', 'lhz'; lambda { |di, a0, a1| { a0 => Expression[a1] } }
			when 'lbs'; lambda { |di, a0, a1| { a0 => Expression[Expression.make_signed(a1, 8)] } }
			when 'lhs'; lambda { |di, a0, a1| { a0 => Expression[Expression.make_signed(a1, 16)] } }
			when 'sw', 'sh', 'sb';  lambda { |di, a0, a1| { a0 => Expression[a1] } }
			when 'jal', 'jalr'; lambda { |di, a0| { :r9 => Expression[di.next_addr + delay_slot(di)*4] } }
			when 'jr', 'j', 'bf', 'bnf', 'nop'; lambda { |di, *a| {} }
			when 'sfeq'; lambda { |di, a0, a1| { :flag => Expression[a0, :==, a1] } }
			when 'sfne'; lambda { |di, a0, a1| { :flag => Expression[a0, :!=, a1] } }
			when 'sfgtu'; lambda { |di, a0, a1| { :flag => Expression[[a0, :&, 0xffff_ffff], :>, [a1, :&, 0xffff_ffff]] } }
			when 'sfgeu'; lambda { |di, a0, a1| { :flag => Expression[[a0, :&, 0xffff_ffff], :>=, [a1, :&, 0xffff_ffff]] } }
			when 'sfltu'; lambda { |di, a0, a1| { :flag => Expression[[a0, :&, 0xffff_ffff], :<, [a1, :&, 0xffff_ffff]] } }
			when 'sfleu'; lambda { |di, a0, a1| { :flag => Expression[[a0, :&, 0xffff_ffff], :<=, [a1, :&, 0xffff_ffff]] } }
			when 'sfgts'; lambda { |di, a0, a1| { :flag => Expression[Expression.make_signed(a0, 32), :>, Expression.make_signed(a1, 32)] } }
			when 'sfges'; lambda { |di, a0, a1| { :flag => Expression[Expression.make_signed(a0, 32), :>=, Expression.make_signed(a1, 32)] } }
			when 'sflts'; lambda { |di, a0, a1| { :flag => Expression[Expression.make_signed(a0, 32), :<, Expression.make_signed(a1, 32)] } }
			when 'sfles'; lambda { |di, a0, a1| { :flag => Expression[Expression.make_signed(a0, 32), :<=, Expression.make_signed(a1, 32)] } }
			end
			@backtrace_binding[op] ||= binding if binding
		}

		@backtrace_binding
	end

	# returns a DecodedFunction from a parsed C function prototype
	def decode_c_function_prototype(cp, sym, orig=nil)
		sym = cp.toplevel.symbol[sym] if sym.kind_of?(::String)
		df = DecodedFunction.new
		orig ||= Expression[sym.name]

		new_bt = lambda { |expr, rlen|
			df.backtracked_for << BacktraceTrace.new(expr, orig, expr, rlen ? :r : :x, rlen)
		}

		# return instr emulation
		if sym.has_attribute 'noreturn' or sym.has_attribute '__noreturn__'
			df.noreturn = true
		else
			new_bt[:r9, nil]
		end

		[3, 4, 5, 6, 7, 8, 11, 12, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31].each { |r|
			# dirty regs according to ABI
			df.backtrace_binding.update "r#{r}".to_sym => Expression::Unknown
		}

		# scan args for function pointers
		reg_args = [:r3, :r4, :r5, :r6, :r7, :r8]
		sym.type.args.to_a.zip(reg_args).each { |a, ra|
			break if not a or not ra
			if a.type.untypedef.kind_of?(C::Pointer)
				pt = a.type.untypedef.type.untypedef
				if pt.kind_of?(C::Function)
					new_bt[ra, nil]
					df.backtracked_for.last.detached = true
				elsif pt.kind_of?(C::Struct)
					new_bt[ra, cp.typesize[:ptr]]
				else
					new_bt[ra, cp.sizeof(nil, pt)]
				end
			end
		}

		df
	end

	def disassembler_default_func
		df = DecodedFunction.new
		df.backtrace_binding = (1..32).inject({}) { |h, r| h.update "r#{r}".to_sym => Expression["r#{r}".to_sym] }
		[3, 4, 5, 6, 7, 8, 11, 12, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31].each { |r|
			df.backtrace_binding["r#{r}".to_sym] = Expression::Unknown
		}
		df.backtracked_for = [BacktraceTrace.new(Expression[:r9], :default, Expression[:r9], :x)]
		df
	end

	def backtrace_is_function_return(expr, di=nil)
		Expression[expr].reduce_rec == :r9
	end

	def backtrace_is_stack_address(expr)
		Expression[expr].expr_externals.include? :r1
	end
end
end
