#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ia32/opcodes'
require 'metasm/decode'

module Metasm
	class Ia32
		class ModRM
			def self.decode(edata, byte, endianness, adsz, opsz, seg=nil, regclass=Reg)
				m = (byte >> 6) & 3
				rm = byte & 7

				if m == 3
					return regclass.new(rm, opsz)
				end

				sum = Sum[adsz][m][rm]

				s, i, b, imm = nil
				sum.each { |a|
					case a
					when Integer
						if not b
							b = Reg.new(a, adsz)
						else
							s = 1
							i = Reg.new(a, adsz)
						end

					when :sib
						sib = edata.get_byte.to_i

						ii = ((sib >> 3) & 7)
						if ii != 4
							s = 1 << ((sib >> 6) & 3)
							i = Reg.new(ii, adsz)
						end

						bb = sib & 7
						if bb == 5 and m == 0
							imm = Expression[edata.decode_imm("i#{adsz}".to_sym, endianness)]
					else
						b = Reg.new(bb, adsz)
					end

				when :i8, :i16, :i32
					imm = Expression[edata.decode_imm(a, endianness)]

				end
			}
			
			new adsz, opsz, s, i, b, imm, seg
		end
	end

	class Farptr
		def self.decode(edata, endianness, adsz)
			addr = Expression[edata.decode_imm("u#{adsz}".to_sym, endianness)]
			seg = Expression[edata.decode_imm(:u16, endianness)]
			new seg, addr
		end
	end

	def build_opcode_bin_mask(op)
		# bit = 0 if can be mutated by an field value, 1 if fixed by opcode
		op.bin_mask = Array.new(op.bin.length, 0)
		op.fields.each { |f, (oct, off)|
			op.bin_mask[oct] |= (@fields_mask[f] << off)
		}
		op.bin_mask.map! { |v| 255 ^ v }
	end

	def build_bin_lookaside
		# sets up a hash byte value => list of opcodes that may match
		# opcode.bin_mask is built here
		lookaside = Array.new(256) { [] }
		@opcode_list.each { |op|

			build_opcode_bin_mask op

			b   = op.bin[0]
			msk = op.bin_mask[0]
			
			for i in b..(b | (255^msk))
				next if i & msk != b & msk
				lookaside[i] << op
			end
		}
		lookaside
	end

	def decode_prefix(instr, byte)
		# XXX check multiple occurences ?
		(instr.prefix[:list] ||= []) << byte

		case byte
		when 0x66: instr.prefix[:opsz] = true
		when 0x67: instr.prefix[:adsz] = true
		when 0xF0: instr.prefix[:lock] = true
		when 0xF2: instr.prefix[:rep]  = :nz
		when 0xF3: instr.prefix[:rep]  = :z	# postprocessed by decode_instr
		when 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65
			if byte & 0x40 == 0
				v = (byte >> 3) & 3
			else
				v = byte & 7
			end
			instr.prefix[:seg] = SegReg.new(v)
			
			instr.prefix[:jmphint] = ((byte & 0x10) == 0x10)	
		else
			return false
		end
		true
	end

	# tries to find the opcode encoded at edata.ptr
	# if no match, tries to match a prefix (update di.instruction.prefix)
	# on match, edata.ptr points to the first byte of the opcode (after prefixes)
	def decode_findopcode(edata)
		di = DecodedInstruction.new self
		while edata.ptr < edata.data.length
			return di if di.opcode = @bin_lookaside[edata.data[edata.ptr]].find { |op|
				# fetch the relevant bytes from edata
				bseq = edata.data[edata.ptr, op.bin.length].unpack('C*')

				# check against full opcode mask
				op.bin.zip(bseq, op.bin_mask).all? { |b1, b2, m| b2 and ((b1 & m) == (b2 & m)) } and
				# check special cases
				!(
				  # fail if any of those is true
				  (fld = op.fields[:seg2A]  and (bseq[fld[0]] >> fld[1]) & @fields_mask[:seg2A] == 1) or
				  (fld = op.fields[:seg3A]  and (bseq[fld[0]] >> fld[1]) & @fields_mask[:seg3A] < 4) or
				  (fld = op.fields[:modrmA] and (bseq[fld[0]] >> fld[1]) & 0xC0 == 0xC0) or
				  (sz  = op.props[:opsz]    and ((di.instruction.prefix[:opsz] and @size != 48-sz) or
					(not di.instruction.prefix[:opsz] and @size != sz))) or
				  (pfx = op.props[:needpfx] and not (di.instruction.prefix[:list] || []).include? pfx)
				 )
			}

			break if not decode_prefix(di.instruction, edata.get_byte)
			di.bin_length += 1
		end
	end

	def decode_instr_op(edata, di)
		before_ptr = edata.ptr
		op = di.opcode
		di.instruction.opname = op.name
		bseq = edata.read(op.bin.length).unpack('C*')		# decode_findopcode ensures that data >= op.length

		field_val = proc { |f|
			if fld = op.fields[f]
				(bseq[fld[0]] >> fld[1]) & @fields_mask[f]
			end
		}

		if field_val[:w] == 0
			opsz = 8
		elsif di.instruction.prefix[:opsz]
			opsz = 48 - @size
		else
			opsz = @size
		end

		if di.instruction.prefix[:adsz]
			adsz = 48 - @size
		else
			adsz = @size
		end
		
		op.args.each { |a|
			di.instruction.args << case a
			when :reg:    Reg.new     field_val[a], opsz
			when :eeec:   CtrlReg.new field_val[a]
			when :eeed:   DbgReg.new  field_val[a]
			when :seg2, :seg2A, :seg3, :seg3A: SegReg.new field_val[a]
			when :regfp:  FpReg.new   field_val[a]
			when :regmmx: SimdReg.new field_val[a], 64
			when :regxmm: SimdReg.new field_val[a], 128

			when :farptr: Farptr.decode edata, @endianness, adsz
			when :i8, :u8, :u16: Expression[edata.decode_imm(a, @endianness)]
			when :i: Expression[edata.decode_imm("i#{opsz}".to_sym, @endianness)]

			when :mrm_imm:  ModRM.decode edata, (adsz == 16 ? 6 : 5), @endianness, adsz, opsz, di.instruction.prefix[:seg]
			when :modrm, :modrmA: ModRM.decode edata, field_val[a], @endianness, adsz, (op.props[:argsz] || opsz), di.instruction.prefix[:seg]
			when :modrmmmx: ModRM.decode edata, field_val[a], @endianness, adsz, 64, di.instruction.prefix[:seg], SimdReg
			when :modrmxmm: ModRM.decode edata, field_val[a], @endianness, adsz,128, di.instruction.prefix[:seg], SimdReg

			when :imm_val1: Expression[1]
			when :imm_val3: Expression[3]
			when :reg_cl:   Reg.new 1, 8
			when :reg_eax:  Reg.new 0, opsz
			when :reg_dx:   Reg.new 2, 16
			when :regfp0:   FpReg.new nil	# implicit?
			else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
			end
		}

		di.bin_length += edata.ptr - before_ptr

		if op.name == 'movsx' or op.name == 'movzx'
			if opsz == 8
				di.instruction.args[1].sz = 8
			else
				di.instruction.args[1].sz = 16
			end
			if di.instruction.prefix[:opsz]
				di.instruction.args[0].sz = 48 - @size
			else
				di.instruction.args[0].sz = @size
			end
		end

		di.instruction.prefix.delete :opsz
		di.instruction.prefix.delete :adsz
		di.instruction.prefix.delete :seg
		case r = di.instruction.prefix.delete(:rep)
		when :nz
			if di.opcode.props[:strop]
				di.instruction.prefix[:rep] = 'rep'
			elsif di.opcode.props[:stropz]
				di.instruction.prefix[:rep] = 'repnz'
			end
		when :z
			if di.opcode.props[:stropz]
				di.instruction.prefix[:rep] = 'repz'
			end
		end

		di
	end

	# converts relative jump/call offsets to absolute addresses
	# adds the eip delta to the offset +off+ of the instruction (may be an Expression) + its bin_length
	# do not call twice on the same di !
	def decode_instr_interpret(di, addr)
		if di.opcode.props[:setip] and di.instruction.args.last.kind_of? Expression and di.instruction.opname[0, 3] != 'ret'
			delta = di.instruction.args.last.reduce
			arg = Expression[[addr, :+, di.bin_length], :+, delta].reduce
			di.instruction.args[-1] = Expression[arg]
		end

		di
	end

	def backtrace_binding(di)
		a = di.instruction.args.map { |arg|
			case arg
			when ModRM, Reg: arg.symbolic
			else arg
			end
		}

		case op = di.opcode.name
		when 'mov', 'movsx', 'movzx': { a[0] => Expression[a[1]] }
		when 'lea': { a[0] => a[1].target }
		when 'xchg': { a[0] => Expression[a[1]], a[1] => Expression[a[0]] }
		when 'add', 'sub', 'or', 'xor', 'and'
			op = { 'add' => :+, 'sub' => :-, 'or' => :|, 'and' => :&, 'xor' => :^ }[op]
			ret = Expression[a[0], op, a[1]]
			# optimises :eax ^ :eax => 0, avoids unnecessary r/w xrefs
			# avoid hiding memory accesses (may cause an exception)
			ret = Expression[ret.reduce] if not a[0].kind_of? Indirection
			{ a[0] => ret }
		when 'inc': { a[0] => Expression[a[0], :+, 1] }
		when 'dec': { a[0] => Expression[a[0], :-, 1] }
		when 'not': { a[0] => Expression[a[0], :^, (1 << (di.instruction.args.first.sz || @size)) - 1] }
		when 'neg': { a[0] => Expression[:-, a[0]] }
		when 'rol', 'ror', 'rcl', 'rcr': { a[0] => Expression[a[0], (op[-1] == ?r ? :>> : :<<), a[1]] } # XXX
		when 'sar', 'shl', 'sal': { a[0] => Expression[a[0], (op[-1] == ?r ? :>> : :<<), a[1]] }
		when 'push'
			# XXX order operations ? (eg push esp)
			{ :esp => Expression[:esp, :-, @size/8],
			  Indirection.new(Expression[:esp], @size/8) => Expression[a[0]] }
		when 'pop'
			{ :esp => Expression[:esp, :+, @size/8],
			  a[0] => Indirection.new(Expression[:esp], @size/8) }
		when 'call'
			eoff = Expression[di.block.address, :+, di.block_offset + di.bin_length]
			{ :esp => Expression[:esp, :-, @size/8],
			  Indirection.new(Expression[:esp], @size/8) => Expression[eoff.reduce] }
		when 'ret': { :esp => Expression[:esp, :+, [@size/8, :+, a[0] || 0]] }
		when 'stosd', 'stosw', 'stosb'
			if di.instruction.prefix[:rep]
				# XXX backtrace ecx ?
				{ :edi => Expression[:unknown], :ecx => Expression[:unknown] }
			else
				sz = { ?b => 1, ?w => 2, ?d => 4 }[op[-1]]
				{ Indirection.new(Expression[:edi], "u#{sz*8}".to_sym) => Expression[:eax], :edi => Expression[:edi, :+, sz] }
			end
		when 'loop': { :ecx => Expression[:ecx, :-, 1] }
		when 'enter'
			depth = a[1].reduce % 32
			b = { Indirection.new(Expression[:esp], @size/8) => Expression[:ebp], :ebp => Expression[:esp, :-, @size/8],
					:esp => Expression[:esp, :-, a[0].reduce + ((@size/8) * depth)] }
			(1..depth).each { |i| # XXX test me !
				b[Indirection.new(Expression[:esp, :-, i*@size/8], @size/8)] = Indirection.new(Expression[:ebp, :-, i*@size/8], @size/8) }
			b
		when 'leave': { :ebp => Indirection.new(Expression[:ebp], @size/8), :esp => Expression[:ebp, :+, @size/8] }
		when 'aaa': { :eax => Expression[:unknown] }
		else
			if %[nop cmp test jmp jz jnz js jns jo jno jg jge jb jbe ja jae jl jle].include? op	# etc etc
				# XXX eflags !
				{}
			else
				puts "unhandled instruction to backtrace: #{di.instruction}" if $VERBOSE
				# assume nothing except the arg list is modified
				(a.grep(Indirection) + a.grep(::Symbol)).inject({}) { |h, s| h.update s => Expression[:unknown] }
			end
		end

	end

	def get_xrefs_x(dasm, di)
		return [] if not di.opcode.props[:setip]

		return [Indirection.new(Expression[:esp], @size/8)] if di.opcode.name == 'ret'

		case tg = di.instruction.args.first
		when ModRM, Reg
			tg.sz ||= @size if tg.kind_of? ModRM
			[Expression[tg.symbolic]]
		when Expression, ::Integer
			[Expression[tg]]
		when Farptr
			puts "far pointer unhandled at #{di.address} #{di.instruction}" if $VERBOSE
			[]
		else raise "internal error: ia32 bad setip arg in #{di.instruction} #{tg.inspect}"
		end
	end

	# checks if expr is a valid return expression matching the :saveip instruction
	def is_function_return(di, expr)
		expr = expr.reduce
		expr = expr.rexpr if expr.kind_of? Expression and not expr.lexpr and expr.op == :+
		di.opcode.props[:saveip] and expr.kind_of? Indirection and expr.len == @size/8 and expr.target == Expression[:esp]
	end

	# updates the function backtrace_binding
	# XXX will fail if different functions share the same epilog - TODO unoptimize -> duplicate those ?
	def update_function_backtrace(dasm, faddr, f, retaddr)
		b = f.backtrace_binding
		[:eax, :ebx, :ecx, :edx, :esi, :edi, :ebp, :esp].each { |r|
			next if b[r] == Expression[:unknown]
			# TODO recheck
			# include_start ?
			# ret 42 ?
			# ...
			bt = dasm.backtrace(Expression[r], retaddr, true, false, nil, nil, nil, faddr)	# XXX is_subfunc
			if bt.length != 1 or (b[r] and bt.first != b[r])
				b[r] = Expression[:unknown]
			else
				b[r] = bt.first
			end
		}
	end

	# updates an instruction's argument replacing an expression with another (eg label renamed)
	def replace_instr_arg_immediate(i, old, new)
		i.args.map! { |a|
			case a
			when Expression: a == old ? new : Expression[a.bind(old => new).reduce]
			when ModRM
				a.imm = (a.imm == old ? new : Expression[a.imm.bind(old => new).reduce]) if a.imm
				a
			else a
			end
		}
	end
end
end
