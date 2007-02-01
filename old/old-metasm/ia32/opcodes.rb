require 'metasm/ia32'

module Metasm

class Ia32_Mnemonic
	# instruction definition, with shortcuts
	# diffopsz is a special @props defining different opsz for the instruction arguments (an array of opsz)
	def initialize(name, bin, hint = nil, fields = Hash.new, props = Array.new)
	 	@name, @bin, @fields = name, bin, fields
		@props, @metaprops, @args = Hash.new, Hash.new, Hash.new
		
		case hint
		when nil
		
		when :mrm
			@fields[:reg] = [@bin.length, 3]
			@fields[:modrm] = [@bin.length, 0]
			@bin << 0
		when :mrmw
			@fields[:reg] = [@bin.length, 3]
			@fields[:modrm] = [@bin.length, 0]
			@fields[:w] = [@bin.length - 1, 0]
			@bin << 0
		when :mrmA
			@fields[:reg] = [@bin.length, 3]
			@fields[:modrmA] = [@bin.length, 0]
			@bin << 0
		
		when :reg
			@fields[:reg] = [@bin.length-1, 0]
			
		when :str
			@fields[:w] = [0, 0]
			props << :strop
		when :strz
			@fields[:w] = [0, 0]
			props << :stropz
			
		when :stop
			props << :stopexec
			
		when Integer		# mod/m, reg = opcode extension = hint
			@fields[:modrm] = [@bin.length, 0]
			@bin << (hint << 3)
			
		else
			raise SyntaxError.new("invalid hint #{hint} for #{name}")
		end

		props.each { |p|
			if    @@props_allowed[p]
				@props[p] = true
			elsif @@args_allowed[p]
				@args[p] = true
			elsif @@metaprops_allowed[p]
				@metaprops[p] = true
			else
				raise SyntaxError, "invalid prop #{p.inspect} for #{@name}"
			end
		}

		verify
	end	
end

def ia32_opcodemacro_1(name, num)
	Ia32_Mnemonic.add(name, [(num << 3) | 4], nil, { :w => [0, 0] }, [:i4, :argEAX])
	Ia32_Mnemonic.add(name, [num << 3], :mrmw, { :d => [0, 1] })
	Ia32_Mnemonic.add(name, [0x80], num, { :w => [0, 0], :s => [0, 1] }, [:i4])
end


def ia32_opcodemacro_2(name, num)
	Ia32_Mnemonic.add(name, [0x0F, 0xBA], (4 | num), {}, [:i1])
	Ia32_Mnemonic.add(name, [0x0F, 0xA3 | (num << 3) ], :mrm)
end

def ia32_opcodemacro_3(name, num)
	Ia32_Mnemonic.add(name, [0xD0], num, { :w => [0, 0] }, [:arg1])
	Ia32_Mnemonic.add(name, [0xD2], num, { :w => [0, 0] }, [:argCL])
	Ia32_Mnemonic.add(name, [0xC0], num, { :w => [0, 0] }, [:i1])
end

def ia32_opcode_list_386
	Ia32_Mnemonic.add('aaa', [0x37])
	Ia32_Mnemonic.add('aad', [0xD5, 0x0A])
	Ia32_Mnemonic.add('aam', [0xD4, 0x0A])
	Ia32_Mnemonic.add('aas', [0x3F])
	
	ia32_opcodemacro_1('adc', 2)
	ia32_opcodemacro_1('add', 0)
	ia32_opcodemacro_1('and', 4)
	
	Ia32_Mnemonic.add('arpl', [0x63], :mrm)
	Ia32_Mnemonic.add('bound', [0x62], :mrmA)
	Ia32_Mnemonic.add('bsf', [0x0F, 0xBC], :mrm)
	Ia32_Mnemonic.add('bsr', [0x0F, 0xBD], :mrm)
	Ia32_Mnemonic.add('bswap', [0x0F, 0xC8], :reg)
	
	ia32_opcodemacro_2('bt' , 0)
	ia32_opcodemacro_2('btc', 3)
	ia32_opcodemacro_2('btr', 2)
	ia32_opcodemacro_2('bts', 1)
	
	Ia32_Mnemonic.add('call', [0xE8], nil, {}, [:i4, :modip])
	Ia32_Mnemonic.add('call', [0xFF], 2, {}, [:setip])
	Ia32_Mnemonic.add('call', [0x9A], nil, {}, [:farptr])
	Ia32_Mnemonic.add('callf', [0xFF], 3)
	
	Ia32_Mnemonic.add('cbw', [0x98], nil, {}, [:opsz2])
	Ia32_Mnemonic.add('cdq', [0x99])
	Ia32_Mnemonic.add('clc', [0xF8])
	Ia32_Mnemonic.add('cld', [0xFC])
	Ia32_Mnemonic.add('cli', [0xFA])
	Ia32_Mnemonic.add('clts', [0x0F, 0x06])
	Ia32_Mnemonic.add('cmc', [0xF5])
	
	ia32_opcodemacro_1('cmp', 7)
	
	Ia32_Mnemonic.add('cmps', [0xA6], :strz)
	Ia32_Mnemonic.add('cmpxchg', [0x0F, 0xB0], :mrmw)
	Ia32_Mnemonic.add('cpuid', [0x0F, 0xA2])
	Ia32_Mnemonic.add('cwd', [0x99], nil, {}, [:opsz2])
	Ia32_Mnemonic.add('cwde', [0x98])
	Ia32_Mnemonic.add('daa', [0x27])
	Ia32_Mnemonic.add('das', [0x2F])
	Ia32_Mnemonic.add('dec', [0x48], :reg)
	Ia32_Mnemonic.add('dec', [0xFE], 1, { :w => [0, 0] })
	Ia32_Mnemonic.add('div', [0xF6], 6, { :w => [0, 0] })
	Ia32_Mnemonic.add('enter', [0xC8], nil, {}, [:i1, :i2])
	Ia32_Mnemonic.add('hlt', [0xF4])
	Ia32_Mnemonic.add('idiv', [0xF6], 7, { :w => [0, 0] })
	Ia32_Mnemonic.add('imul', [0xF6], 5, { :w => [0, 0] }, [:argEAX])
	Ia32_Mnemonic.add('imul', [0x0F, 0xAF], :mrm)
	Ia32_Mnemonic.add('imul', [0x69], :mrm, { :s => [0, 1] }, [:i4])
	Ia32_Mnemonic.add('in', [0xE4], nil, { :w => [0, 0] }, [:i4])
	Ia32_Mnemonic.add('in', [0xEC], nil, { :w => [0, 0] })
	Ia32_Mnemonic.add('inc', [0x40], :reg)
	Ia32_Mnemonic.add('inc', [0xFE], 0, { :w => [0, 0] })
	Ia32_Mnemonic.add('ins', [0x6C], :str)
	Ia32_Mnemonic.add('int', [0xCD], nil, {}, [:i1])
	Ia32_Mnemonic.add('int3', [0xCC])
	Ia32_Mnemonic.add('into', [0xCE])
	Ia32_Mnemonic.add('invd', [0x0F, 0x08])
	Ia32_Mnemonic.add('invlpg', [0x0F, 0x01], 7)
	Ia32_Mnemonic.add('iret', [0xCF], :stop)
	Ia32_Mnemonic.add('iretd', [0xCF], :stop)
	Ia32_Mnemonic.add('j', [0x70], nil, { :tttn => [0, 0] }, [:modip, :i1])
	Ia32_Mnemonic.add('j', [0x0F, 0x80], nil, { :tttn => [1, 0] }, [:modip, :i4])
	Ia32_Mnemonic.add('jecxz', [0xE3], nil, {}, [:modip, :i1, :opsz4])
	Ia32_Mnemonic.add('jcxz', [0xE3], nil, {}, [:modip, :i1, :opsz2])
	Ia32_Mnemonic.add('jmp', [0xEB], nil, {}, [:modip, :i1, :stopexec])
	Ia32_Mnemonic.add('jmp', [0xE9], nil, {}, [:modip, :i4, :stopexec])
	Ia32_Mnemonic.add('jmp', [0xFF], 4, {}, [:setip, :stopexec])
	Ia32_Mnemonic.add('jmp', [0xEA], nil, {}, [:farptr, :stopexec])
	Ia32_Mnemonic.add('jmpf', [0xFF], 5, {}, [:stopexec])		# reg ?
	Ia32_Mnemonic.add('lahf', [0x9F])
	Ia32_Mnemonic.add('lar', [0x0F, 0x02], :mrm)
	Ia32_Mnemonic.add('lds', [0xC5], :mrmA)
	Ia32_Mnemonic.add('lea', [0x8D], :mrmA)
	Ia32_Mnemonic.add('leave', [0xC9])
	Ia32_Mnemonic.add('les', [0xC4], :mrmA)
	Ia32_Mnemonic.add('lfs', [0x0F, 0xB4], :mrmA)
	Ia32_Mnemonic.add('lgs', [0x0F, 0xB5], :mrmA)
	Ia32_Mnemonic.add('lgdt', [0x0F, 0x01], 2)
	Ia32_Mnemonic.add('lidt', [0x0F, 0x01, 0x18], nil, { :modrmA => [2, 0] })
	Ia32_Mnemonic.add('lldt', [0x0F, 0x00], 2)
	Ia32_Mnemonic.add('lmsw', [0x0F, 0x01], 6)
# pfx	Ia32_Mnemonic.add('lock', [0xF0])
	Ia32_Mnemonic.add('lods', [0xAC], :str)
	Ia32_Mnemonic.add('loop', [0xE2], nil, {}, [:modip, :i1])
	Ia32_Mnemonic.add('loopz', [0xE1], nil, {}, [:modip, :i1])
	Ia32_Mnemonic.add('loope', [0xE1], nil, {}, [:modip, :i1])
	Ia32_Mnemonic.add('loopnz', [0xE0], nil, {}, [:modip, :i1])
	Ia32_Mnemonic.add('loopne', [0xE0], nil, {}, [:modip, :i1])
	Ia32_Mnemonic.add('lsl', [0x0F, 0x03], :mrm)
	Ia32_Mnemonic.add('lss', [0x0F, 0xB2], :mrmA)
	Ia32_Mnemonic.add('ltr', [0x0F, 0x00], 3)
	Ia32_Mnemonic.add('mov', [0x88], :mrmw, { :d => [0, 1] })
	Ia32_Mnemonic.add('mov', [0xA0], nil, { :w => [0, 0], :d => [0, 1] }, [:argEAXdisp])
	Ia32_Mnemonic.add('mov', [0xB0], :reg, { :w => [0, 3] }, [:i4])
	Ia32_Mnemonic.add('mov', [0xC6], 0, { :w => [0, 0] }, [:i4])
	Ia32_Mnemonic.add('mov', [0x0F, 0x20, 0xC0], :reg, { :d => [1, 1], :eeec => [2, 3] })
	Ia32_Mnemonic.add('mov', [0x0F, 0x21, 0xC0], :reg, { :d => [1, 1], :eeed => [2, 3] })
	Ia32_Mnemonic.add('mov', [0x8C], 0, { :d => [0, 1], :sreg3 => [1, 3] })
	Ia32_Mnemonic.add('movs', [0xA4], :str)
	Ia32_Mnemonic.add('movsx', [0x0F, 0xBE], :mrmw).props[:diffopsz] = [4, 2]
	Ia32_Mnemonic.add('movzx', [0x0F, 0xB6], :mrmw).props[:diffopsz] = [4, 2]
	Ia32_Mnemonic.add('mul', [0xF6], 4, { :w => [0, 0] })
	Ia32_Mnemonic.add('neg', [0xF6], 3, { :w => [0, 0] })
	Ia32_Mnemonic.add('nop', [0x90])
	Ia32_Mnemonic.add('not', [0xF6], 2, { :w => [0, 0] })
	
	ia32_opcodemacro_1('or', 1)
	
	Ia32_Mnemonic.add('out', [0xE6], nil, { :w => [0, 0] }, [:i4])
	Ia32_Mnemonic.add('out', [0xEE], nil, { :w => [0, 0] })
	Ia32_Mnemonic.add('outs', [0x6E], :str)
	Ia32_Mnemonic.add('pause', [0xF3, 0x90])
	Ia32_Mnemonic.add('pop', [0x58], :reg)
	Ia32_Mnemonic.add('pop', [0x8F], 0)
	Ia32_Mnemonic.add('pop', [0x07], nil, { :sreg2A => [0, 3] })
	Ia32_Mnemonic.add('pop', [0x0F, 0x81], nil, { :sreg3 => [1, 3] })
	Ia32_Mnemonic.add('popa', [0x61], nil, {}, [:opsz2])
	Ia32_Mnemonic.add('popad', [0x61], nil, {}, [:opsz4])
	Ia32_Mnemonic.add('popf', [0x9D], nil, {}, [:opsz2])
	Ia32_Mnemonic.add('popfd', [0x9D], nil, {}, [:opsz4])
	Ia32_Mnemonic.add('push', [0x50], :reg)
	Ia32_Mnemonic.add('push', [0xFF], 6)
	Ia32_Mnemonic.add('push', [0x68], nil, { :s => [0, 1] }, [:i4])
	Ia32_Mnemonic.add('push', [0x06], nil, { :sreg2 => [0, 3] })
	Ia32_Mnemonic.add('push', [0x0F, 0x80], nil, { :sreg3 => [1, 3] })
	Ia32_Mnemonic.add('pusha', [0x66, 0x60])
	Ia32_Mnemonic.add('pushad', [0x60])
	Ia32_Mnemonic.add('pushf', [0x66, 0x9C])
	Ia32_Mnemonic.add('pushfd', [0x9C])
	
	ia32_opcodemacro_3('rcl', 2)
	ia32_opcodemacro_3('rcr', 3)
	
	Ia32_Mnemonic.add('rdmsr', [0x0F, 0x32])
	Ia32_Mnemonic.add('rdpmc', [0x0F, 0x33])
	Ia32_Mnemonic.add('rdtsc', [0x0F, 0x31])
	Ia32_Mnemonic.add('ret', [0xC3], :stop)
	Ia32_Mnemonic.add('ret', [0xC2], :stop, {}, [:i2])
	Ia32_Mnemonic.add('retf', [0xCB], :stop)
	Ia32_Mnemonic.add('retf', [0xCA], :stop, {}, [:i2])
	
	ia32_opcodemacro_3('rol', 0)
	ia32_opcodemacro_3('ror', 1)
	
	Ia32_Mnemonic.add('rsm', [0x0F, 0xAA])
	Ia32_Mnemonic.add('sahf', [0x9E])
	
	ia32_opcodemacro_3('sar', 7)
	
	ia32_opcodemacro_1('sbb', 3)
	
	Ia32_Mnemonic.add('scas', [0xAE], :strz)
	Ia32_Mnemonic.add('set', [0x0F, 0x90], 0, { :tttn => [1, 0] }, [:opsz1])
	Ia32_Mnemonic.add('sgdt', [0x0F, 0x01, 0x00], nil, { :modrmA => [2, 0] })
	
	ia32_opcodemacro_3('shl', 4)
	ia32_opcodemacro_3('sal', 4)
	
	Ia32_Mnemonic.add('shld', [0x0F, 0xA4], :mrm, {}, [:i1])
	Ia32_Mnemonic.add('shld', [0x0F, 0xA5], :mrm, {}, [:argCL])
	
	ia32_opcodemacro_3('shr', 5)
	
	Ia32_Mnemonic.add('shrd', [0x0F, 0xAC], :mrm, {}, [:i1])
	Ia32_Mnemonic.add('shrd', [0x0F, 0xAD], :mrm, {}, [:argCL])
	Ia32_Mnemonic.add('sidt', [0x0F, 0x01, 0x08], nil, { :modrmA => [2, 0] })
	Ia32_Mnemonic.add('sldt', [0x0F, 0x00], 0)
	Ia32_Mnemonic.add('smsw', [0x0F, 0x01], 4)
	Ia32_Mnemonic.add('stc', [0xF9])
	Ia32_Mnemonic.add('std', [0xFD])
	Ia32_Mnemonic.add('sti', [0xFB])
	Ia32_Mnemonic.add('stos', [0xAA], :str)
	Ia32_Mnemonic.add('str', [0x0F, 0x00], 1)
	
	ia32_opcodemacro_1('sub', 5)
	
	Ia32_Mnemonic.add('test', [0x84], :mrmw)
	Ia32_Mnemonic.add('test', [0xA8], nil, { :w => [0, 0] }, [:argEAX, :i4])
	Ia32_Mnemonic.add('test', [0xF6], 0, { :w => [0, 0] }, [:i4])
	Ia32_Mnemonic.add('ud2', [0x0F, 0x0B])
	Ia32_Mnemonic.add('verr', [0x0F, 0x00], 4)
	Ia32_Mnemonic.add('verw', [0x0F, 0x00], 5)
	Ia32_Mnemonic.add('wait', [0x9B])
	Ia32_Mnemonic.add('wbinvd', [0x0F, 0x09])
	Ia32_Mnemonic.add('wrmsr', [0x0F, 0x30])
	Ia32_Mnemonic.add('xadd', [0x0F, 0xC0], :mrmw)
	Ia32_Mnemonic.add('xchg', [0x90], :reg, {}, [:argEAX])
	Ia32_Mnemonic.add('xchg', [0x86], :mrmw)
	Ia32_Mnemonic.add('xlat', [0xD7])
	
	ia32_opcodemacro_1('xor', 6)

	# undocumented opcodes
	# TODO put it in the right place (486/P6/...)
	Ia32_Mnemonic.add('aad', [0xD5], nil, {}, [:i1])
	Ia32_Mnemonic.add('aam', [0xD4], nil, {}, [:i1])
	Ia32_Mnemonic.add('int1',  [0xF1])
	Ia32_Mnemonic.add('icebp', [0xF1])
	Ia32_Mnemonic.add('loadall', [0x0F, 0x07])
	Ia32_Mnemonic.add('ud2', [0x0F, 0xB9])
	Ia32_Mnemonic.add('umov', [0x0F, 0x10], :mrmw, { :d => [1, 1] })

# pfx  [addrsz = 0x67, lock = 0xf0, opsz = 0x66, repnz = 0xf2, rep/repz = 0xf3
#	cs/nojmp = 0x2E, ds/jmp = 0x3E, es = 0x26, fs = 0x64, gs = 0x65, ss = 0x36 ]
end 


def ia32_opcode_list_387
	# fpu
	# TODO
#	Ia32_Mnemonic.add('f2xm1', [0xD9, 0xF0])
#	Ia32_Mnemonic.add('fabs', [0xD9, 0xF1])
#	Ia32_Mnemonic.add('fadd', [0xD9, 0x00], nil, { 'modrmfpu' => [1, 0], 'd' => [1, 3] })
	
end

def ia32_opcode_list_486
# TODO add new segments (fs/gs)..
	ia32_opcode_list_386
	ia32_opcode_list_387
end

def ia32_opcode_list_pentium
	ia32_opcode_list_486
	Ia32_Mnemonic.add('cmpxchg8b', [0x0F, 0xC7], 1)
	
	# lock cmpxchg8b eax
	# Ia32_Mnemonic.add('f00fbug', [0xF0, 0x0F, 0xC7, 0xC8])
	
#
#	Ia32_Mnemonic.add('emms', [0x0F, 0x77])
#	Ia32_Mnemonic.add('movd', [0x0F, 0x6E, 0], nil, { :modrm => [2, 0], 'd' => [1, 4], 'mmxreg' => [2, 3] })
#	Ia32_Mnemonic.add('movq', [0x0F, 0x6F, 0], nil, { 'modrmmmx' => [2, 0], 'd' => [1, 4], 'mmxreg' => [2, 3] })
end

def ia32_opcode_list_p6
	ia32_opcode_list_pentium
	
	Ia32_Mnemonic.add('cmov', [0x0F, 0x40], :mrm, { :tttn => [1, 0] })
	Ia32_Mnemonic.add('fxrstor', [0x0F, 0xAE], 1, { :modrmA => [2, 0] })
	Ia32_Mnemonic.add('fxsave', [0x0F, 0xAE], 0, { :modrmA => [2, 0] })
	Ia32_Mnemonic.add('sysenter', [0x0F, 0x34])
	Ia32_Mnemonic.add('sysexit', [0x0F, 0x35])
#	Ia32_Mnemonic.add('fcmov', [0xDA, 0xC0], nil, { 'fctttn' => [1, 3], 'fpureg' => [1, 0] })
#	Ia32_Mnemonic.add('fcmovn', [0xDB, 0xC0], nil, { 'fctttn' => [1, 3], 'fpureg' => [1, 0] })
#	Ia32_Mnemonic.add('fcomi', [0xDB, 0xF0], nil, { 'fpureg' => [1, 0] })
end

def ia32_opcode_list_pentium_sse
	ia32_opcode_list_p6
end

def ia32_opcode_list_pentium_sse2
	ia32_opcode_list_pentium_sse
end

def ia32_opcode_list_pentium_sse3
	ia32_opcode_list_pentium_sse2
end

end
