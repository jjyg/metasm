#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2015 Google
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/mcs51/opcodes'
require 'metasm/decode'

module Metasm
class MCS51

	def build_opcode_bin_mask(op)
		op.bin_mask = Array.new(op.bin.length, 0)
		op.fields.each { |f, (oct, off)|
		  op.bin_mask[oct] |= (@fields_mask[f] << off)
		}
		op.bin_mask.map! { |v| 255 ^ v }
	end

	def build_bin_lookaside
		lookaside = Array.new(256) { [] }
		opcode_list.each { |op|
		  build_opcode_bin_mask op
		  b   = op.bin[0]
		  msk = op.bin_mask[0]
		  for i in b..(b | (255^msk))
		    lookaside[i] << op if i & msk == b & msk
		  end
		}
		lookaside
	end

	def decode_findopcode(edata)
		di = DecodedInstruction.new self
		byte = edata.data[edata.ptr]
		byte = byte.unpack('C').first if byte.kind_of?(::String)
		if not byte
		  return
		end
		return di if di.opcode = @bin_lookaside[byte].find { |op|
		  bseq = edata.data[edata.ptr, op.bin.length].unpack('C*')
		  op.bin.zip(bseq, op.bin_mask).all? { |b1, b2, m| b2 and ((b1 & m) == (b2 & m)) }
		}
	end

	def decode_instr_op(edata, di)
		before_ptr = edata.ptr
		op = di.opcode
		di.instruction.opname = op.name
		bseq = edata.read(op.bin.length).unpack('C*')

		field_val = lambda { |f|
			if fld = op.fields[f]
				(bseq[fld[0]] >> fld[1]) & @fields_mask[f]
			end
		}

		op.args.each { |a|
		  di.instruction.args << case a
		  when :rel8
		    Expression[edata.decode_imm(:i8, @endianness)]
		  when :d8
		    Immediate.new(edata.decode_imm(:u8, @endianness))
		  when :m8
		    Memref.new(edata.decode_imm(:u8, @endianness))
		  when :rd
		    Reg.new(field_val[a])
		  when :r_a
		    Reg.from_str('A')
		  when :r_b
		    Reg.from_str('B')
		  when :r_c
		    Reg.from_str('C')
		  when :addr_11
		    Memref.new(edata.decode_imm(:u8, @endianness))
		  when :addr_16
		    Memref.new(edata.decode_imm(:u16, @endianness))
		  end
		}

		di.bin_length += edata.ptr - before_ptr

		di
	end

	def backtrace_binding(b)
		@backtrace_binding ||= {}
	end

	def get_xrefs_x(b,c)
		[]
	end

end
end
