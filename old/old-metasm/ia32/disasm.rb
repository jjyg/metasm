require 'metasm/disasm'
require 'metasm/ia32'

module Metasm

class Ia32_ModRM
	@@mrm_sum = {
	    2 => {
		0 => [ [3, 6], [3, 7], [5, 6], [5, 7], [6], [7], [:i2], [3] ],
		1 => [ [3, 6, :i1], [3, 7, :i1], [5, 6, :i1], [5, 7, :i1], [6, :i1], [7, :i1], [5, :i1], [3, :i1] ],
		2 => [ [3, 6, :i2], [3, 7, :i2], [5, 6, :i2], [5, 7, :i2], [6, :i2], [7, :i2], [5, :i2], [3, :i2] ]
	    },
	    4 => {
		0 => [ [0], [1], [2], [3], [:sib], [:i4], [6], [7] ],
		1 => [ [0, :i1], [1, :i1], [2, :i1], [3, :i1], [:sib, :i1], [5, :i1], [6, :i1], [7, :i1] ],
		2 => [ [0, :i4], [1, :i4], [2, :i4], [3, :i4], [:sib, :i4], [5, :i4], [6, :i4], [7, :i4] ]
	    }
	}
	
	def self.decode(instr, mrm, str, argidx)
		m = (mrm >> 6) & 3
		rm = mrm & 7

		if m == 3
			return Ia32_Reg.new(rm, instr.opsz)
		end
		
		sum = @@mrm_sum[instr.adsz][m][rm]
		
		s, i, b, imm = nil
		sum.each { |a|
			case a
			when Integer
				if b
					s, i = 1, Ia32_Reg.new(a, instr.adsz)
				else
					b = Ia32_Reg.new(a, instr.adsz)
				end
			
			when :i1
				imm = Immediate.decode(str, argidx, 1, true)
				argidx += 1
				instr.length += 1
			when :i2
				imm = Immediate.decode(str, argidx, 2, true)
				argidx += 2
				instr.length += 2
			when :i4
				imm = Immediate.decode(str, argidx, instr.adsz, true)
				argidx += instr.adsz
				instr.length += instr.adsz
				
			when :sib
				sib = str[argidx]
				instr.length += 1
				argidx += 1

				ii = ((sib >> 3) & 7)
				if ii != 4
					s = 1 << ((sib >> 6) & 3)
					i = Ia32_Reg.new(ii, instr.adsz)
				end
				
				bb = sib & 7
				if bb == 5 and m == 0
					imm = Immediate.decode(str, argidx, instr.adsz)
					argidx += instr.adsz
					instr.length += instr.adsz
				else
					b = Ia32_Reg.new(bb, instr.adsz)
				end
			end
		}
		
		new s, i, b, imm, instr.opsz
	end
end

class Ia32_Instruction < Instruction
# TODO detect invalid pfx sequence
	def decode_pfx(str, idx)
		byte = str[idx]
		case byte
		when 0x66
			# 4 => 2, 2 => 4
			@opsz = 6 - @opsz
		
		when 0x67
			@adsz = 6 - @adsz
			
		when 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65
			if byte & 0x40 == 0
				v = (byte >> 3) & 3
			else
				v = byte & 7
			end
			@seg = Ia32_SegReg.new(v)

			@jmphint = (byte & 0x10) == 0x10
			
		when 0xF0
			@lock = true
			
		when 0xF2
			@rep = :nz
		when 0xF3
			@rep = :z

		else
			super
		end

		@length += 1
		1
	end
end

class Ia32_Mnemonic < Mnemonic
	@@decode_order = [:w, :s, :argEAX, :argEAXdisp, :reg, :eeec,
		:eeed, :sreg2, :sreg2A, :sreg3, :modrm, :modrmA, :argCL,
		:arg1, :i1, :i2, :i4, :farptr,
		:tttn, :strop, :stropz, :d]

	@@decode_proc[:w] = proc { |instr, v, *x| instr.opsz = 1 if v == 0 }
	@@decode_proc[:s] = proc { |instr, v, *x| instr.imm4s = true if v == 1 }
	@@decode_proc[:d] = proc { |instr, v, *x| instr.args.reverse! if v == 0 }
	
	@@decode_proc[:eeec] = proc { |instr, v, *x| instr.args << Ia32_CtrlReg.new(v) }
	@@decode_proc[:eeed] = proc { |instr, v, *x| instr.args << Ia32_DbgReg.new(v) }
	
	@@decode_proc[:sreg2] = @@decode_proc[:sreg2A] =
	@@decode_proc[:sreg3] = proc { |instr, v, *x| instr.args << Ia32_SegReg.new(v) }
	
	@@decode_proc[:reg] = proc { |instr, v, *x| instr.args << Ia32_Reg.new(v, instr.opsz) }
	
	@@decode_proc[:modrmA] =
	@@decode_proc[:modrm] = proc { |instr, v, str, ibase, argidx|
		instr.args << Ia32_ModRM.decode(instr, v, str, argidx)
	}
	
	@@decode_proc[:arg1] = proc { |instr, *x| instr.args << Immediate.new(1) }
	@@decode_proc[:argCL] = proc { |instr, *x| instr.args << Ia32_Reg.new(1, 1) }
	@@decode_proc[:argEAX] = proc { |instr, *x| instr.args << Ia32_Reg.new(0, instr.opsz) }
	@@decode_proc[:argEAXdisp] = proc { |instr, v, str, ibase, argidx|
		instr.args << Ia32_ModRM.new(nil, nil, nil, Immediate.decode(str, argidx, instr.adsz), instr.opsz)
		instr.length += instr.adsz
		instr.args << Ia32_Reg.new(0, instr.opsz)
	}
	
	@@decode_proc[:i1] = proc { |instr, v, str, ibase, argidx|
		instr.args << Immediate.decode(str, argidx, 1, true)
		instr.length += 1
	}
	@@decode_proc[:i2] = proc { |instr, v, str, ibase, argidx|
		instr.args << Immediate.decode(str, argidx, 2, true)
		instr.length += 2
	}
	@@decode_proc[:i4] = proc { |instr, v, str, ibase, argidx|
		# sz override already handled
		instr.args << Immediate.decode(str, argidx, 4, true)
		instr.length += 4
	}
	@@decode_proc[:farptr] = proc { |instr, v, str, ibase, argidx|
		instr.args << Immediate.decode(str, argidx, 2+instr.adsz, true)
		instr.length += 2+instr.adsz
	}
	
	# b != ae, z = e, np = po, l != ge
	@@decode_proc[:tttn] = proc { |instr, v, *x|
		instr.name += %w{o no b ae z nz be a s ns p np l ge le g}[v]
	}
	@@decode_proc[:strop] =
	@@decode_proc[:stropz] = proc { |instr, *x|
		instr.name += %w{x b w x d x x x q}[instr.opsz]
	}
	
	def bin_match?(str, idx, instr)
		return false if @props[:opsz2] and instr.opsz != 2
		return false if @props[:opsz4] and instr.opsz != 4
		
		return false if x=@fields[:sreg2A] and ((str[idx+x[0]] >> x[1]) & 3) == 1
		return false if x=@fields[:modrmA] and ((str[idx+x[0]] >> x[1]) & 0xC0) == 0xC0
		
		super
	end

	def decode_field(instr, f, str, ibase, argidx)
		if f == :i4
			f = :i1 if instr.imm4s or instr.opsz == 1
			f = :i2 if instr.opsz == 2
		end
		super
	end
end

end
