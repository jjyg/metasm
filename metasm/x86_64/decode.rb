#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/x86_64/opcodes'
require 'metasm/decode'

module Metasm
class X86_64
	class ModRM
		def self.decode(edata, byte, endianness, adsz, opsz, seg=nil, regclass=Reg)
			m = (byte >> 6) & 3
			rm = byte & 7

			if m == 3
				return regclass.new(rm, opsz)
			end

			# mod 0/1/2 m 4 => sib
			# mod 0 m 5 => rip+imm
			# sib: i 4 => no index, b 5 => no base

			s = i = b = imm = nil
			if m == 4	# XXX or 12 ? (ignore REX.B)
				sib = edata.get_byte.to_i

				ii = (sib >> 3) & 7
				if ii != 4
					s = 1 << ((sib >> 6) & 3)
					i = Reg.new(ii, adsz)
				end

				bb = sib & 7
				if bb != 5 or mod != 0	# XXX check with m == 1 or 2
					b = Reg.new(bb, adsz)
				end
			elsif m == 5	# XXX REX.B ?
				b = Reg.new(16, 64) if mod == 0		# XXX mod ? adsz ?
			else
				b = Reg.new(m, adsz)
			end

			case mod
			when 0; itype = :i32 if m == 5
			when 1; itype = :i8
			when 2; itype = :i32
			end
			imm = Expression[edata.decode_imm(itype, endianness)] if itype

			if imm and imm.reduce.kind_of? Integer and imm.reduce < -0x100_0000
				# probably a base address -> unsigned
				imm = Expression[imm.reduce & ((1 << (adsz || 32)) - 1)]
			end

			new adsz, opsz, s, i, b, imm, seg
		end
	end

	def decode_prefix(instr, byte)
		x = super(instr, byte)
		#return if instr.prefix[:rex]	# must be the last prefix	TODO check repetition/out of order
		if byte & 0xf0 == 0x40
			x = instr.prefix[:rex] = byte
			instr.prefix[:rex_b] = 1 if byte & 1 > 0
			instr.prefix[:rex_x] = 1 if byte & 2 > 0
			instr.prefix[:rex_r] = 1 if byte & 4 > 0
			instr.prefix[:rex_w] = 1 if byte & 8 > 0
		end
		x
	end

	def decode_instr_op(edata, di)
		before_ptr = edata.ptr
		op = di.opcode
		di.instruction.opname = op.name
		bseq = edata.read(op.bin.length).unpack('C*')		# decode_findopcode ensures that data >= op.length
		pfx = di.instruction.prefix || {}

		field_val = lambda { |f|
			if fld = op.fields[f]
				(bseq[fld[0]] >> fld[1]) & @fields_mask[f]
			end
		}
		field_val_r = lambda { |f|
			v = field_val[f]
			v |= 0x10 if v and pfx[:rex_r]
			v
		}

		opsz = op.props[:argsz] || (pfx[:rex_w] ? 64 : pfx[:opsz] ? 16 : 32)
		adsz = pfx[:adsz] ? 32 : 64

		op.args.each { |a|
			di.instruction.args << case a
			when :reg;    Reg.new     field_val_r[a], opsz
			when :eeec;   CtrlReg.new field_val_r[a]
			when :eeed;   DbgReg.new  field_val_r[a]
			when :seg2, :seg2A, :seg3, :seg3A; SegReg.new field_val[a]
			#when :regfp;  FpReg.new   field_val[a]
			#when :regmmx; SimdReg.new field_val[a], mmxsz
			when :regxmm; SimdReg.new field_val_r[a], 128

			when :farptr; Farptr.decode edata, @endianness, opsz
			when :i8, :u8, :i16, :u16, :i32, :u32, :i64, :u64; Expression[edata.decode_imm(a, @endianness)]
			when :i		# 64bit constants are sign-extended from :i32
				type = (opsz == 64 ? :i32 : op.props[:unsigned_imm] ? :a32 : :i32)
 				v = edata.decode_imm(type, @endianness)
				v &= 0xffff_ffff_ffff_ffff if opsz == 64 and op.props[:unsigned_imm] and v.kind_of? Integer
				Expression[v]

			when :mrm_imm;  ModRM.decode edata, 5, @endianness, adsz, opsz, pfx[:seg]	# mov eax, [addr] TODO XXX this decodes to rip+imm, also test i32/i64
			when :modrm, :modrmA; ModRM.decode edata, field_val[a], @endianness, adsz, opsz, pfx[:seg]
			#when :modrmmmx; ModRM.decode edata, field_val[:modrm], @endianness, adsz, mmxsz, pfx[:seg], SimdReg
			when :modrmxmm; ModRM.decode edata, field_val[:modrm], @endianness, adsz, 128, pfx[:seg], SimdReg

			when :imm_val1; Expression[1]
			when :imm_val3; Expression[3]
			when :reg_cl;   Reg.new 1, 8
			when :reg_eax;  Reg.new 0, opsz
			when :reg_dx;   Reg.new 2, 16
			#when :regfp0;   FpReg.new nil	# implicit?
			else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
			end
		}

		di.bin_length += edata.ptr - before_ptr

		if op.name == 'movsx' or op.name == 'movzx'
			# TODO ?
			if opsz == 8
				di.instruction.args[1].sz = 8
			else
				di.instruction.args[1].sz = 16
			end
			if pfx[:opsz]
				di.instruction.args[0].sz = 16
			else
				di.instruction.args[0].sz = 32
			end
		end

		pfx.delete :seg
		case r = pfx.delete(:rep)
		when :nz
			if di.opcode.props[:strop]
				pfx[:rep] = 'rep'
			elsif di.opcode.props[:stropz]
				pfx[:rep] = 'repnz'
			end
		when :z
			if di.opcode.props[:strop]
				pfx[:rep] = 'rep'
			elsif di.opcode.props[:stropz]
				pfx[:rep] = 'repz'
			end
		end

		di
	end

	def opsz(di)
		if di.instruction.prefix[:rex_w]; 64
		elsif di.instruction.prefix[:opsz]; 16
		elsif di.opcode.name =~ /^(j|loop|(call|enter|leave|lgdt|lidt|lldt|ltr|pop|push|ret)$)/; 64
		else 32
		end
	end

	# populate the @backtrace_binding hash with default values
	def init_backtrace_binding
		super
		mask = lambda { |di| (1 << opsz(di))-1 }
		sign = lambda { |v, di| Expression[[[v, :&, mask[di]], :>>, opsz(di)-1], :'!=', 0] }

		opcode_list.map { |ol| ol.basename }.uniq.sort.each { |op|
			#binding = case op
			# TODO virtualize :eax :ebx etc so that we get :rax here without needing to copy everything
			#when 'sar', 'shl', 'sal'; lambda { |di, a0, a1| { a0 => Expression[a0, (op[-1] == ?r ? :>> : :<<), [a1, :%, [opsz[di], 32].max]] } } 32 => 64 ?
			#when 'enter'; depth = a1.reduce % 32
			#when 'fstenv', 'fnstenv'	# XXX push i32 ? lastfpuinstr at same offset ?
			#end
			#@backtrace_binding[op] ||= full_binding || binding if full_binding || binding
		}
		@backtrace_binding
	end

	def aoeuaoeuget_backtrace_binding(di)
					val = bd.delete e
					mask <<= shift if shift
					invmask = mask ^ 0xffff_ffff
					val = Expression[val, :<<, shift] if shift
					bd[reg] = Expression[[reg, :&, invmask], :|, [val, :&, mask]]
	end

	# returns true if the expression is an address on the stack
	def backtrace_is_stack_address(expr)
		Expression[expr].expr_externals.include? :rsp
	end
end
end
