#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/x86_64/opcodes'
require 'metasm/decode'

module Metasm
class X86_64
	class ModRM
		def self.decode(edata, byte, endianness, adsz, opsz, seg=nil, regclass=Reg, pfx={})
			m = (byte >> 6) & 3
			rm = byte & 7

			if m == 3
				rm |= 8 if pfx[:rex_b]
				return regclass.new(rm, opsz)
			end

			adsz ||= 64

			# mod 0/1/2 m 4 => sib
			# mod 0 m 5 => rip+imm
			# sib: i 4 => no index, b 5 => no base

			s = i = b = imm = nil
			if rm == 4	# XXX pfx[:rex_b] ?
				sib = edata.get_byte.to_i

				ii = (sib >> 3) & 7
				if ii != 4	# XXX pfx[:rex_x] ?
					ii |= 8 if pfx[:rex_x]
					s = 1 << ((sib >> 6) & 3)
					i = Reg.new(ii, adsz)
				end

				bb = sib & 7
				if bb != 5 or m != 0	# XXX pfx[:rex_b] ?
					bb |= 8 if pfx[:rex_b]
					b = Reg.new(bb, adsz)
				end
			elsif rm == 5 and m == 0	# rip XXX pfx[:rex_b] ?
				b = Reg.new(16, adsz)
				m = 2	# :i32 follows
			else
				rm |= 8 if pfx[:rex_b]
				b = Reg.new(rm, adsz)
			end

			case m
			when 1; itype = :i8
			when 2; itype = :i32
			end
			imm = Expression[edata.decode_imm(itype, endianness)] if itype

			if imm and imm.reduce.kind_of? Integer and imm.reduce < -0x100_0000
				# probably a base address -> unsigned
				imm = Expression[imm.reduce & ((1 << adsz) - 1)]
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
			v |= 8 if v and pfx[:rex_r]
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
			when :regxmm; SimdReg.new field_val_r[a], 128

			when :farptr; Farptr.decode edata, @endianness, opsz
			when :i8, :u8, :i16, :u16, :i32, :u32, :i64, :u64; Expression[edata.decode_imm(a, @endianness)]
			when :i		# 64bit constants are sign-extended from :i32
				type = (opsz == 64 ? op.props[:imm64] ? :a64 : :i32 : op.props[:unsigned_imm] ? :a32 : :i32)
 				v = edata.decode_imm(type, @endianness)
				v &= 0xffff_ffff_ffff_ffff if opsz == 64 and op.props[:unsigned_imm] and v.kind_of? Integer
				Expression[v]

			when :mrm_imm;  ModRM.new(adsz, opsz, nil, nil, nil, Expression[edata.decode_imm("a#{adsz}".to_sym, @endianness)], prx[:seg])	# XXX manuals say :a64, test it
			when :modrm, :modrmA; ModRM.decode edata, field_val[a], @endianness, adsz, opsz, pfx[:seg], Reg, pfx
			when :modrmxmm; ModRM.decode edata, field_val[:modrm], @endianness, adsz, 128, pfx[:seg], SimdReg, pfx

			when :imm_val1; Expression[1]
			when :imm_val3; Expression[3]
			when :reg_cl;   Reg.new 1, 8
			when :reg_eax;  Reg.new 0, opsz
			when :reg_dx;   Reg.new 2, 16
			#when :regfp0;   FpReg.new nil	# implicit?
			else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
			end
		}

		# sil => bh
		di.instruction.args.each { |a| a.val += 12 if a.sz == 8 and not pfx[:rex] and a.val >= 4 and a.val <= 8 }

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
		if di and di.instruction.prefix and di.instruction.prefix[:rex_w]; 64
		elsif di and di.instruction.prefix and di.instruction.prefix[:opsz]; 16
		elsif di and di.opcode.name =~ /^(j|loop|(call|enter|leave|lgdt|lidt|lldt|ltr|pop|push|ret)$)/; 64
		else 32
		end
	end

	def register_symbols
		[:rax, :rcx, :rdx, :rbx, :rsp, :rbp, :rsi, :rdi, :r8, :r9, :r10, :r11, :r12, :r13, :r14, :r15]
	end
end
end
