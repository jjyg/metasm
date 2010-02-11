#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/sh4/opcode'
require 'metasm/decode'

module Metasm
class Sh4
	def build_opcode_bin_mask(op)
		op.bin_mask = 0
		op.args.each { |f|
			op.bin_mask |= @fields_mask[f] << @fields_shift[f]
		}
		op.bin_mask = 0xffff ^ op.bin_mask
	end

	def build_bin_lookaside
		lookaside = Hash.new { |h,k| h[k] = []}
		opcode_list.each { |op|
			next if not op.bin.kind_of? Integer
			build_opcode_bin_mask op
			lookaside[op.bin >> 12] << op
		}
		lookaside
	end

	# depending on transfert size mode (sz flag), fmov instructions manipulate single ou double precision values
	# instruction aliasing appears when sz is not handled
	def transfer_size_mode(o)
		return o if o.find { |op| not op.name.include? 'mov' }
		@transfersz == 0 ? o.select { |op| op.name.include? 'fmov.s' } : o.reject { |op| op.name.include? 'fmov.s' }
	end

	# when pr flag is set, floating point instructions are executed as double-precision operations
	# thus registers pair is used (DRn registers)
	def precision_mode(o)
		@fpprecision == o ? o.reject { |op| op.args.include? :drn } : o.select{ |op| op.args.include? :frn }
	end

	def decode_findopcode(edata)
		return if edata.ptr >= edata.data.length

		di = DecodedInstruction.new(self)
		val = edata.decode_imm(:u16, @endianness)
		edata.ptr -= 2
		op = @bin_lookaside[val >> 12].select{|opcode| (val & opcode.bin_mask) == opcode.bin}

		op = transfer_size_mode(op) if op.size == 2
		op = precision_mode(op) if op.size == 2

		if op == nil or op.size != 1
			op.each{|opcode| puts "#{opcode.name} - #{opcode.args} - #{Expression[opcode.bin]} - #{Expression[opcode.bin_mask]}"} if op
			puts "current value: #{Expression[val]}"
			raise "Die with your boots on !"
		else
			op = op.first
		end

		di if di.opcode = op and op
	end

	def decode_instr_op(edata, di)
		before_ptr = edata.ptr
		op = di.opcode
		di.instruction.opname = op.name
		di.opcode.props[:memsz] = op.name =~ /(\.l)|(mova)/ ? 32 : op.name =~ /(\.w)/ ? 16 : 8
		val = edata.decode_imm(:u16, @endianness)

		field_val = lambda{ |f|
			r = (val >> @fields_shift[f]) & @fields_mask[f]
			case f
			when :@rm, :@rn ,:@_rm, :@_rn, :@rm_, :@rn_; r = GPR.new(r)
			when :@disppc
				# The effective address is formed by calculating PC+4,
				# clearing the lowest 2 bits, and adding the zero-extended 8-bit immediate i
				# multiplied by 4 (32-bit)/ 2 (16-bit) / 1 (8-bit).
				curaddr = di.address+4
				curaddr = (curaddr & 0xffff_fffc) if di.opcode.props[:memsz] == 32
				r = Expression[curaddr+r*(di.opcode.props[:memsz]/8)]

			when :@disprm, :@dispr0rn; r = Expression[(r & 0xf) * (di.opcode.props[:memsz]/8)]
			when :@disprmrn; r = Expression[(r & 0xf) * 4]
			when :@dispgbr; r = Expression.make_signed(r, 16)
			when :disp8; r = Expression[((di.address+4))+2*Expression.make_signed(r, 8)]
			when :disp12; r = Expression[((di.address+4))+2*Expression.make_signed(r, 12)]
			when :s8; r = Expression[Expression.make_signed(r, 8)]
			else r
			end
			r
		}

		op.args.each { |a|
			di.instruction.args << case a
			when :r0; GPR.new 0
			when :rm, :rn; GPR.new field_val[a]
			when :rm_bank, :rn_bank; RBANK.new field_val[a]
			when :drm, :drn; DR.new field_val[a]
			when :frm, :frn; FR.new field_val[a]
			when :xdm, :xdn; XDR.new field_val[a]
			when :fvm, :fvn; FVR.new field_val[a]
			when :vbr; VBR.new
			when :gbr; GBR.new
			when :sr; SR.new
			when :ssr; SSR.new
			when :spc; SPC.new
			when :sgr; SGR.new
			when :dbr; DBR.new
			when :mach; MACH.new
			when :macl; MACL.new
			when :pr; PR.new
			when :fpul; FPUL.new
			when :fpscr; FPSCR.new
			when :dbr; DBR.new
			when :pc; PC.new

			when :@rm, :@rn, :@disppc
				Memref.new(field_val[a], nil)
			when :@_rm, :@_rn
				Memref.new(field_val[a], nil, :pre)
			when :@rm_, :@rn_
				Memref.new(field_val[a], nil, :post)
			when :@r0rm
				Memref.new(GPR.new(0), GPR.new(field_val[:rm]))
			when :@r0rn
				Memref.new(GPR.new(0), GPR.new(field_val[:rn]))
			when :@disprm
				Memref.new(field_val[a], GPR.new(field_val[:rm]))
			when :@disprmrn
				Memref.new(field_val[a], GPR.new(field_val[:rn]))

			when :disppc; field_val[:@disppc]
			when :s8, :disp8, :disp12; field_val[a]
			when :i16, :i8, :i5; Expression[field_val[a]]

			else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
			end
		}

		di.bin_length += edata.ptr - before_ptr
		di
	end

	def disassembler_default_func
		df = DecodedFunction.new
		df.backtrace_binding = {}
		15.times{|i| df.backtrace_binding["r#{i}".to_sym] = Expression::Unknown}
		df.backtracked_for = []
		df.btfor_callback = lambda { |dasm, btfor, funcaddr, calladdr|
			if funcaddr != :default
				btfor
			elsif di = dasm.decoded[calladdr] and di.opcode.props[:saveip]
				btfor
			else []
			end
		}
		df
	end

	# interprets a condition code (in an opcode name) as an expression
	def decode_cmp_expr(di, a0, a1)
		case di.opcode.name
		when 'cmp/eq'; Expression[a0, :'==', a1]
		when 'cmp/ge'; Expression[a0, :'>=', a1] # signed
		when 'cmp/gt'; Expression[a0, :'>', a1] # signed
		when 'cmp/hi'; Expression[a0, :'>', a1] # unsigned
		when 'cmp/hs'; Expression[a0, :'>=', a1] # unsigned
		end
	end

	def decode_cmp_cst(di, a0)
		case di.opcode.name
		when 'cmp/pl'; Expression[a0, :'>', 0] # signed
		when 'cmp/pz'; Expression[a0, :'>=', 0] # signed
		end
	end

	def backtrace_binding
		@backtrace_binding ||= init_backtrace_binding
	end

	def opsz(di)
		ret = @size
		ret = 8 if di and di.opcode.name =~ /(\.b)/
			ret = 16 if di and di.opcode.name =~ /(\.w)/
			ret
	end

	def init_backtrace_binding
		@backtrace_binding ||= {}

		mask = lambda { |di| (1 << opsz(di))-1 }  # 32bits => 0xffff_ffff
		sign = lambda { |v, di| Expression[[[v, :&, mask[di]], :>>, opsz(di)-1], :'!=', 0] }

		opcode_list.map { |ol| ol.name }.uniq.each { |op|
			binding = case op

				  when 'ldc', 'ldc.l', 'lds', 'lds.l', 'stc', 'stc.l', 'stc.w', 'stc.b'
					  lambda { |di, a0, a1| { Expression[a1, :&, mask[di]] => Expression[a0, :&, mask[di]] } }

				  when 'mov', 'mov.l', 'mov.w', 'mov.b'
					  lambda { |di, a0, a1| { Expression[a1, :&, mask[di]] => Expression[a0, :&, mask[di]] } }

				  when 'movt'; lambda {|di, a0| {a0 => :t_bit}}

				  when 'exts.b', 'exts.w', 'extu.w'
					  lambda { |di, a0, a1| { a1 => Expression[a0, :&, mask[di]] } }

				  when 'tst'; lambda { |di, a0, a1| { Expression[:t_bit] => Expression[[a0, :^, a1], :==, 0] }}

				  when 'cmp/eq', 'cmp/ge', 'cmp/ge', 'cmp/gt', 'cmp/hi', 'cmp/hs'
					  lambda { |di, a0, a1| { Expression[:t_bit] => decode_cmp_expr(di, a0, a1) }}

				  when 'cmp/pl', 'cmp/pz'
					  lambda { |di, a0| { Expression[:t_bit] => decode_cmp_cst(di, a0) }}

				  when 'tst'; lambda { |di, a0, a1|
					  res = Expression[[a0, :&, mask[di]], :^, [[a1, :&, mask[di]]], :==, 0]
					  ret = {}
					  ret[:t_bit] = res
					  ret
				  }

				  when 'rte'; lambda {|di| {:pc => :spc , :sr => :ssr }}
				  when 'rts'; lambda {|di| {:pc => :pr}}
				  when 'sets'; lambda {|di| {:s_bit => 1}}
				  when 'sett'; lambda {|di| {:t_bit=> 1}}
				  when 'clrs'; lambda {|di| {:s_bit => 0}}
				  when 'clrt'; lambda {|di| {:t_bit => 0}}
				  when 'clrmac'; lambda {|di| {:macl => 0, :mach => 0}}

				  when 'jmp'; lambda { |di, a0| {:pc => a0}}
				  when 'jsr'
					  lambda { |di, a0|
						  ret = {}
						  ret[:pc] = Expression[a0]
						  ret[:pr] = Expression[di.address+2*2]
						  ret
					  }

				  when 'dt'; lambda { |di, a0|
					  res = Expression[a0, :-, 1]
					  ret  ={}
					  ret[:a0] = res
					  ret[:t_bit] = Expression[res, :==, 0]
					  ret
				  }
				  when 'add' ; lambda { |di, a0, a1| { a1 => Expression[a0, :+, a1] } }
				  when 'addc' ; lambda { |di, a0, a1|
					  res = Expression[[a0, :&, mask[di]], :+, [[a1, :&, mask[di]], :+, :t_bit]]
					  ret = {}
					  ret[a1] = Expression[a0, :+, [a1, :+, :t_bit]]
					  ret[:t_bit] = Expression[res, :>, mask[di]]
					  ret

				  }
				  when 'addv' ; lambda { |di, a0, a1|
					  res = Expression[[a0, :&, mask[di]], :+, [[a1, :&, mask[di]]]]
					  ret = {}
					  ret[a1] = Expression[a0, :+, [a1, :+, :t_bit]]
					  ret[:t_bit] = Expression[res, :>, mask[di]]
					  ret
				  }

				  when 'shll16', 'shll8', 'shll2', 'shll' ; lambda { |di, a0|
					  shift = di.opcode.name == 'shll16' ? 16 : di.opcode.name == 'shll8' ? 8 : di.opcode.name == 'shll2' ? 2 : 1
					  { a0 => Expression[a0, :<<, shift] }
				  }
				  when 'shlr16', 'shlr8', 'shlr2','shlr'
					  lambda{|di, a0|
						  shift = di.opcode.name == 'shlr16' ? 16 : di.opcode.name == 'shlr8' ? 8 : di.opcode.name == 'shlr2' ? 2 : 1
						  { a0 => Expression[a0, :>>, shift] }
					  }
				  when 'rotcl'; lambda{|di, a0|
					  ret = {}
					  ret[a0] = Expression[[a0, :<<, 1], :|, :t_bit]
					  ret[:t_bit] = Expression[a0, :>>, [opsz[di], :-, 1]]
					  ret
				  }
				  when 'rotcr'; lambda{|di, a0|
					  ret = {}
					  ret[a0] = Expression[[a0, :>>, 1], :|, :t_bit]
					  ret[:t_bit] = Expression[a0, :&, 1]
					  ret
				  }
				  when 'rotl'; lambda{|di, a0|
					  res = {}
					  shift_bit = [a0, :<<, [opsz[di], :-, 1]]
					  res[a0] = Expression[[a0, :<<, 1], :|, shift_bit]
					  res[:t_bit] = shift_bit
					  res
				  }
				  when 'rotr'; lambda{|di, a0|
					  res = {}
					  shift_bit = [a0, :>>, [opsz[di], :-, 1]]
					  res[a0] = Expression[[a0, :>>, 1], :|, shift_bit]
					  res[:t_bit] = shift_bit
					  res
				  }
				  when 'shal'; lambda{|di, a0|
					  res = {}
					  shift_bit = [a0, :<<, [opsz[di], :-, 1]]
					  res[a0] = Expression[a0, :<<, 1]
					  res[:t_bit] = shift_bit
					  res
				  }
				  when 'shar'; lambda{|di, a0|
					  res = {}
					  shift_bit = Expression[a0, :&, 1]
					  res[a0] = Expression[a0, :>>, 1]
					  res[:t_bit] = shift_bit
					  res
				  }
				  when 'sub'; lambda {|di, a0, a1| { a1 => Expression[a0, :-, a1] }}
				  when 'subc'; lambda {|di, a0, a1| { a1 => Expression[a0, :-, [a1, :-, :t_bit]] }}
				  when 'and', 'and.b';  ; lambda {|di, a0, a1| { a1 => Expression[[a0, :&, mask[di]], :|, [[a1, :&, mask[di]]]] }}
				  when 'or', 'or.b' ; lambda {|di, a0, a1| { a1 => Expression[[a0, :|, mask[di]], :|, [[a1, :&, mask[di]]]] }}
				  when 'xor', 'xor.b' ; lambda {|di, a0, a1| { a1 => Expression[[a0, :|, mask[di]], :^, [[a1, :&, mask[di]]]] }}
				  when 'add', 'addc', 'addv'; ; lambda { |di, a0, a1| { a1 => Expression[a0, :+, a1] }}
				  when 'neg' ; lambda {|di, a0, a1| { a1 => Expression[ mask[di], :-, a0] }}
				  when 'negc' ; lambda {|di, a0, a1| { a1 => Expression[[[mask[di], :-, a0], :-, :t_bit], :&, mask[di]] }}
				  when 'not'; lambda {|di, a0, a1| { a1 => Expression[a0, :^, mask[di]] }}
				  end

			@backtrace_binding[op] ||= binding if binding
		}

		@backtrace_binding
	end

	def get_backtrace_binding(di)
		a = di.instruction.args.map { |arg|
			case arg
			when GPR, XFR, XDR, FVR, DR, FR, XMTRX; arg.symbolic
			when MACH, MACL, PR, FPUL, PC, FPSCR; arg.symbolic
			when SR, SSR, SPC, GBR, VBR, SGR, DBR; arg.symbolic
			when Memref; arg.symbolic(di.address, di.opcode.props[:memsz]/8)
			else arg
			end
		}

		if binding = backtrace_binding[di.opcode.basename]
			bd = binding[di, *a] || {}
		else
			puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
			{:incomplete_binding => Expression[1]}
		end
	end

	def get_xrefs_x(dasm, di)
		return [] if not di.opcode.props[:setip]

		arg = case di.instruction.opname
		      when 'bf', 'bf/s', 'bt', 'bt/s', 'jmp', 'jsr'
			      di.instruction.args.last
		      when 'rts'
			      :pr
		      else di.instruction.args.last
		      end

		arg.kind_of?(Reg) ? [Expression[arg.symbolic]] : [Expression[arg]]
	end

	def backtrace_is_function_return(expr, di=nil)
		expr.reduce_rec == :pr
	end

	def delay_slot(di=nil)
		(di and di.opcode.props[:delay_slot]) ? 1 : 0
	end

end
end
