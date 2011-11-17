#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/x86_64/main'
require 'metasm/ia32/opcodes'

module Metasm
class X86_64
	def init_cpu_constants
		super()
		@valid_args.concat [:i32, :u32, :i64, :u64] - @valid_args
	end

	def init_386_common_only
		super()
		# :imm64 => accept a real int64 as :i argument
		# :auto64 => ignore rex_w, always 64-bit op
		# :op32no64 => if write to a 32-bit reg, dont zero the top 32-bits of dest
		@valid_props |= [:imm64, :auto64, :op32no64]
		@opcode_list.delete_if { |o| o.bin[0].to_i & 0xf0 == 0x40 }	# now REX prefix
		@opcode_list.each { |o|
			o.props[:imm64] = true if o.bin == [0xB8]	# mov reg, <true imm64>
			o.props[:auto64] = true if o.name =~ /^(j.*|loop.*|call|enter|leave|push|pop|ret)$/
		}
		addop 'movsxd', [0x63], :mrm
		addop('cdqe', [0x98]) { |o| o.props[:opsz] = 64 }
		addop('cqo',  [0x99]) { |o| o.props[:opsz] = 64 }
	end

	# all x86_64 cpu understand <= sse2 instrs
	def init_x8664_only
		init_386_common_only
		init_386_only
		init_387_only
		init_486_only
		init_pentium_only
		init_p6_only
		init_sse_only
		init_sse2_only

		@opcode_list.delete_if { |o|
			o.args.include?(:seg2) or
			o.args.include?(:seg2A) or
			o.args.include?(:farptr) or
			%w[aaa aad aam aas bound daa das into
			 lds les loadall arpl pusha pushad popa
			 popad].include?(o.name.split('.')[0])
			 # split needed for lds.a32
		}

		@opcode_list.each { |o|
			o.props[:auto64] = true if o.name =~ /^(enter|leave|[sl]gdt|[sl]idt|[sl]ldt|[sl]tr|push|pop)$/
		}

		addop('cmpxchg16b', [0x0F, 0xC7], 1) { |o| o.props[:opsz] = 64 ; o.props[:argsz] = 128 }
		addop('iretq', [0xCF], nil, :stopexec, :setip) { |o| o.props[:opsz] = 64 } ; opcode_list.unshift opcode_list.pop
		addop 'swapgs', [0x0F, 0x01, 0xF8]

		addop('movq',  [0x0F, 0x6E], :mrmmmx, {:d => [1, 4]}) { |o| o.args = [:modrm, :regmmx] ; o.props[:opsz] = o.props[:argsz] = 64 }
		addop('movq',  [0x0F, 0x6E], :mrmxmm, {:d => [1, 4]}) { |o| o.args = [:modrm, :regxmm] ; o.props[:opsz] = o.props[:argsz] = 64 ; o.props[:needpfx] = 0x66 }
	end

	def init_sse3
		init_x8664_only
		init_sse3_only
	end

	def init_sse41_only
		super()
		addop('pextrq', [0x0F, 0x3A, 0x16], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66; o.args[o.args.index(:modrmxmm)] = :modrm; o.props[:opsz] = o.props[:argsz] = 64 }
		addop('pinsrq', [0x0F, 0x3A, 0x22], :mrmxmm, :u8) { |o| o.props[:needpfx] = 0x66; o.args[o.args.index(:modrmxmm)] = :modrm; o.props[:opsz] = o.props[:argsz] = 64 }
	end

	def init_avx_only
		super()
		addop('rdfsbase', [0x0F, 0xAE], 0, :modrmR) { |o| o.props[:needpfx] = 0xF3 }
		addop('rdgsbase', [0x0F, 0xAE], 1, :modrmR) { |o| o.props[:needpfx] = 0xF3 }
		addop('wrfsbase', [0x0F, 0xAE], 2, :modrmR) { |o| o.props[:needpfx] = 0xF3 }
		addop('wrgsbase', [0x0F, 0xAE], 3, :modrmR) { |o| o.props[:needpfx] = 0xF3 }
	end

	def addop_macrostr(name, bin, type)
		super(name, bin, type)
		bin = bin.dup
		bin[0] |= 1
		addop(name+'q', bin) { |o| o.props[:opsz] = 64 ; o.props[type] = true }
	end

	def addop_macroret(name, bin, *args)
		addop(name + '.i64', bin, nil, :stopexec, :setip, *args) { |o| o.props[:opsz] = 64 }
		super(name, bin, *args)
	end

	def addop_post(op)
		if op.fields[:d] or op.fields[:w] or op.fields[:s] or op.args.first == :regfp0
			return super(op)
		end

		dupe = lambda { |o|
			dop = Opcode.new o.name.dup, o.bin.dup
 			dop.fields, dop.props, dop.args = o.fields.dup, o.props.dup, o.args.dup
			dop
		}

		if op.props[:needpfx]
			@opcode_list.unshift op
		else
			@opcode_list << op
		end

		if op.args == [:i] or op.name == 'ret'
			# define opsz-override version for ambiguous opcodes
			op16 = dupe[op]
			op16.name << '.i16'
			op16.props[:opsz] = 16
			@opcode_list << op16
			# push call ret jz  can't 32bit
			op64 = dupe[op]
			op64.name << '.i64'
			op64.props[:opsz] = 64
			@opcode_list << op64
		elsif op.props[:strop] or op.props[:stropz] or op.args.include? :mrm_imm or
				op.args.include? :modrm or op.name =~ /loop|xlat/
			# define adsz-override version for ambiguous opcodes (movsq)
			# XXX loop pfx 67 = rip+ecx, 66/rex ignored
			op32 = dupe[op]
			op32.name << '.a32'
			op32.props[:adsz] = 32
			@opcode_list << op32
			op64 = dupe[op]
			op64.name << '.a64'
			op64.props[:adsz] = 64
			@opcode_list << op64
		end
	end
end
end
