#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/arm64/opcodes'
require 'metasm/encode'

module Metasm
class ARM64
	def encode_instr_op(program, instr, op)
		base = op.bin

		set_field = lambda { |f, v|
			v = v.reduce if v.kind_of?(Expression)
			case f
			when :i8_12
				base = Expression[base, :|, [[v, :&, 0xf], :|, [[v, :<<, 4], :&, 0xf00]]]
				next
			when :stype; v = [:lsl, :lsr, :asr, :ror].index(v)
			when :bitmask_imm
				# TODO: https://dinfuehr.github.io/blog/encoding-of-immediate-values-on-aarch64/
				raise 'algorithm not implemented yet'
				# n =
				# imms =
				# v =
				next
			when :u; v = [:-, :+].index(v)
			end

			base = Expression[base, :|, [[v, :&, @fields_mask.fetch(f)], :<<, @fields_shift.fetch(f)]]
		}

		op.args.zip(instr.args).each { |sym, arg|
			case sym
			when :rd, :rs, :rn, :rm, :rt
				if arg.is_a?(Reg)
					if arg.sz == 32
						set_field[:sf, 0]
					elsif arg.sz == 64
						set_field[:sf, 1]
					elsif op.fields[:sf]
						set_field[:sf, 1]
					end
					set_field[sym, arg.i]
				elsif arg.is_a?(Expression)
					# TODO: There is an arg.encode implementation available too, which might be usable?
					# Expression.encode_imm(arg.reduce, :i8, @endianness
					# TODO: This is the default behavior in set_field anyways, could probably be condensed
					set_field[sym, arg.reduce]
				else
					raise "unknown sym #{sym} for arg #{arg.inspect}"
				end
			when :il18_5, :rm_lsl_i5, :rm_lsr_i5, :rm_asr_i5, :rm_lsl_i6, :rm_lsr_i6, :rm_asr_i6, :bitmask_imm, :i16_5
				set_field[sym, arg.reduce]
			else
				raise "unknown sym #{sym} for arg #{arg.inspect}"
			end
		}

		Expression[base].encode(:u32, @endianness)
	end
end
end
