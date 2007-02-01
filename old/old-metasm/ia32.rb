require 'metasm/metasm'

module Metasm

class Ia32_SegReg < Argument
	@@segs = ['es', 'cs', 'ss', 'ds', 'fs', 'gs']

	attr_reader :v

	def initialize(v)
		raise 'invalid segment selector' if v > @@segs.length
		@v = v
	end

	def to_s(*args)
		@@segs[@v]
	end
end

class Ia32_DbgReg < Argument
	attr_reader :v

	def initialize(v)
		raise "invalid debug register DR#{v}" if v == 4 or v == 5
		@v = v
	end

	def to_s(*args)
		"dr#@v"
	end
end

class Ia32_CtrlReg < Argument
	attr_reader :v

	def initialize(v)
		raise "invalid control register CR#{v}" if v == 1
		@v = v
	end

	def to_s(*args)
		"cr#@v"
	end
end

class Ia32_SimdReg < Argument
	@@regs = {
		8 => (0..7).map { |n| "mmx#{n}" },
		16 => (0..7).map { |n| "xmm#{n}" }
	}
	
	attr_reader :v, :sz
	
	def initialize(v, sz)
		@v, @sz = v, sz
	end

	def to_s(*args)
		@@regs[@sz][@v]
	end
end

class Ia32_FpReg < Argument
	attr_reader :v
	
	def initialize(v)
		@v = v
	end

	def to_s(*args)
		"ST(#@v)"
	end
end

class Ia32_Reg < Argument
	@@regs = {
		 1 => ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh'],
		 2 => ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di'],
		 4 => ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'],
#		 8 => ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
	}

	attr_reader :v, :sz

	def initialize(v, sz=nil)
		@v, @sz = v, sz
	end

	def to_s(arg)
		sz = if @sz
			@sz
		elsif arg.class == Ia32_Instruction
			arg.opsz
		else
			arg
		end
		@@regs[sz][@v]
	end
end

class Ia32_ModRM < Argument
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

	
	attr_reader :s, :i, :b, :imm, :ptsz

	def initialize(s, i, b, imm, ptsz)
		@s, @i, @b, @imm, @ptsz = s, i, b, imm, ptsz
		@imm.signed = false if @imm and not @b
	end

	def to_s(instr)
		s = ''
		
		if not instr.args.find { |arg| arg.class == Ia32_Reg and arg.sz == @ptsz }
			# TODO far with adsz = 2
			s << %w{x byte word x dword x far x qword}[@ptsz] << ' ptr ' 
		end
		
		s << instr.seg.to_s << ?: if instr.seg
		
		s << ?[
		
		s << @b.to_s(self) if @b
		if @i
			s << ' + ' if @b
			s << @s.to_s << ?* if @s != 1
			s << @i.to_s(self)
		end
		if @imm
			s << ' + ' if @b or @i
			s << @imm.to_s
			s.sub! '+ -', '- '
		end

		s << ?]
	end
end

class Ia32_Instruction < Instruction
	attr_accessor :opsz, :adsz, :seg, :imm4s, :lock

	# default mode: 32 bits
	@@opsz = 4
	@@adsz = 4

	def initialize
		super
		@opsz = @@opsz
		@adsz = @@adsz
	end

	def pfx_to_s
		ret = ''
		ret << 'lock ' if @lock
		case @rep
		when :z
			ret << 'rep ' if @mn.props[:strop]
			ret << 'repz ' if @mn.props[:stropz]
		when :nz
			ret << 'repnz ' if @mn.props[:stropz]
		end
		ret
	end
end

class Immediate
	# XXX this sux
	alias oldto_s to_s
	def to_s(sz = @sz)
		if sz.class == Ia32_Instruction
			sz = sz.imm4s ? 1 : sz.opsz
		end
		oldto_s sz
	end
end

class Ia32_Mnemonic < Mnemonic
	@@fields_mask = { :w => 1, :s => 1, :d => 1, :reg => 7, :modrm => 0xc7,
		:modrmA => 0xc7, :eeec => 7, :eeed => 7, :sreg2 => 3,
		:sreg2A => 3, :sreg3 => 7, :tttn => 0xf }
	
	[:i1, :i2, :i4, :farptr, :arg1, :argCL, :argEAX, :argEAXdisp].each { |a|
		@@args_allowed[a] = true
	}
	
	[:strop, :stropz, :opsz1, :opsz2, :opsz4, :diffopsz].each { |p|
		@@props_allowed[p] = true
	}
end

end

load 'metasm/ia32/opcodes.rb'
