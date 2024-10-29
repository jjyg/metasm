#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/python/opcodes'
require 'metasm/decode'

module Metasm
class Python
	def build_bin_lookaside
		opcode_list.inject({}) { |la, op| la.update op.bin => op }
	end

	# coalesce EXTENDED_ARGS opcodes
	def decode_findopcode(edata)
		if di = decode_findopcode_noextendedarg(edata) and di.opcode.name == 'EXTENDED_ARG'
			seq = [di]
			3.times {
				if di = decode_findopcode_noextendedarg(edata) and di.opcode.name == 'EXTENDED_ARG'
					seq << di
				else
					break
				end
			}
			di ||= seq.pop	# EOS
			di.misc ||= {}
			di.misc[:extended_args] = seq
			seq.each { |sdi| di.bin_length += sdi.bin_length }
		end
		di
	end

	def decode_findopcode_noextendedarg(edata)
		di = DecodedInstruction.new(self)

		if @py_version >= 0x03060000
			di.raw_data = edata.decode_imm(:u16, :little)
			di.bin_length = 2
		else
			di.raw_data = edata.decode_imm(:u8, :little)
			di.bin_length = 1

		end

		di if di.opcode = @bin_lookaside[di.raw_data & 0xff]
	end

	def decode_instr_op(edata, di)
		di.instruction.opname = di.opcode.name

		di.opcode.args.each { |a|
			case a
			when :i16, :cmp
				if @py_version >= 0x03060000
					v = 0
					if di.misc and di.misc[:extended_args]
						di.misc[:extended_args].each { |sdi|
							v += sdi.raw_data >> 8
							v <<= 8
						}
					end
					v += di.raw_data >> 8
				else
					v = edata.decode_imm(:i16, @endianness)
					di.bin_length += 2
				end
				v = CMP_OP[v] || v if a == :cmp
				di.instruction.args << Expression[v]
			when :u8
				if @py_version >= 0x03060000
				else
					di.bin_length += 1
					di.instruction.args << Expression[edata.decode_imm(:u8, @endianness)]
				end
			else
				raise "unsupported arg #{a.inspect}"
			end
		}

		return if edata.ptr > edata.length

		di
	end

	def decode_instr_interpret(di, addr)
		case di.opcode.name
		when 'LOAD_CONST'
			if c = prog_code_pyobj(addr)
				cst = @program.to_rb(c[:consts])[di.instruction.args.first.reduce]
				if cst.kind_of?(Hash) and cst[:type] == :code
					di.add_comment cst[:value]
				else
					di.add_comment cst.inspect
				end
			end
		when 'LOAD_NAME', 'LOAD_ATTR', 'LOAD_GLOBAL', 'STORE_NAME', 'IMPORT_NAME', 'LOAD_FAST'
			if c = prog_code_pyobj(addr)
				di.add_comment @program.to_rb(c[:names])[di.instruction.args.first.reduce].inspect
			end
		when 'JUMP_FORWARD', 'FOR_ITER', 'SETUP_FINALLY', 'CALL_FINALLY'
			# relative address
			delta = di.instruction.args.last.reduce
			delta &= ~1 if @py_version >= 0x03060000	# only even addresses
			arg = di.next_addr + delta
			di.instruction.args[-1] = Expression[arg]
		when /CALL/
			# copied from get_xrefs_x ?
		else
			if di.opcode.props[:setip]
				# absolute address
				delta = di.instruction.args.last.reduce
				delta &= ~1 if @py_version >= 0x03060000	# only even addresses
				if c = prog_code_pyobj(di)
					delta += c[:codeoff]
				end
				arg = delta
				di.instruction.args[-1] = Expression[arg]
			end
		end
		di
	end

	def init_backtrace_binding
		@backtrace_binding ||= {}

		opcode_list.each { |op|
			binding = case op
				  when 'nop'; lambda { |*a| {} }
				  end
			@backtrace_binding[op] ||= binding if binding
		}

		@backtrace_binding
	end

	def get_xrefs_x(dasm, di)
		return [] if not di.opcode.props[:setip]
		return [Expression[:unknown]] if di.opcode.name =~ /CALL/ and di.opcode.name != 'CALL_FINALLY'
		# work already done in _interpret
		return di.instruction.args
	end

	def prog_code_pyobj(addr)
		addr = addr.address if addr.kind_of?(DecodedInstruction)
		@last_prog_code ||= nil
		return @last_prog_code if @last_prog_code and @last_prog_code[:codeoff] <= addr and @last_prog_code[:codeoff] + @last_prog_code[:codelen] > addr
		@last_prog_code = @program.pycode_at_off(addr) if @program
	end

	def backtrace_is_function_return(expr, di=nil)
		#Expression[expr].reduce == Expression['wtf']
	end
end
end
