#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'test/unit'
require_relative '../metasm'

class TestX86_64 < Test::Unit::TestCase
	@@cpu = Metasm::X86_64.new
	def assemble(src, cpu=@@cpu)
		Metasm::Shellcode.assemble(cpu, src).encode_string
	end

	def test_user
		assert_equal(Metasm::X86_64, Metasm::Ia32.new(64).class)
	end

	def bin(s)
		if s.respond_to?(:force_encoding)
			s.force_encoding('BINARY')
		else
			s
		end
	end

	def test_basic
		assert_equal(bin("\x90"), assemble("nop"))
		assert_equal(bin("\x50"), assemble("push rax"))
		assert_equal(bin("\x41\x50"), assemble("push r8"))
		assert_equal(bin("\x6a\x02"), assemble("push 2"))
		assert_equal(bin("\x68\x8e\0\0\0"), assemble("push 142"))
		assert_equal(bin("\x48\xbb\xef\xcd\xab\x89\x67\x45\x23\x01"), assemble("mov rbx, 0123456789abcdefh"))
		assert_equal(bin("\x8d\x05\x0c\0\0\0"), assemble("lea eax, [rip+12]"))
		assert_equal(bin("\x8d\x04\x25\x0c\0\0\0"), assemble("lea eax, [12]"))
		assert_equal(bin("\x48\x81\xE3\xFF\xF0\xFF\xFF"), assemble("and rbx, 0xffffffff_fffff0ff"))
	end

	def test_err
		assert_raise(Metasm::ParseError) { assemble("add eax") }
		assert_raise(Metasm::ParseError) { assemble("add add, ebx") }
		assert_raise(Metasm::ParseError) { assemble("add 42, ebx") }
		assert_raise(Metasm::ParseError) { assemble("add [bx]") }
		assert_raise(Metasm::ParseError) { assemble("add [eip+4*eax]") }
		assert_raise(Metasm::ParseError) { assemble("add ah, r8b") }
		assert_raise(Metasm::EncodeError) { assemble("and rbx, 0x1_ffffffff_ffffffff") }
		assert_raise(Metasm::EncodeError) { assemble("mov rbx, 011123456789abcdefh") }
	end

	def disassemble(bin, cpu=@@cpu)
		Metasm::Shellcode.disassemble(cpu, bin)
	end

	def test_dasm
		d = disassemble(bin("\x90"))
		assert_equal(Metasm::DecodedInstruction, d.decoded[0].class)
		assert_equal('nop', d.decoded[0].opcode.name)
	end

	def test_rex
		assert_equal(bin("\xfe\xc0"), assemble("inc al"))
		assert_equal(bin("\xfe\xc4"), assemble("inc ah"))
		assert_equal(bin("\x40\xfe\xc4"), assemble("inc spl"))
		assert_equal(bin("\x41\xfe\xc4"), assemble("inc r12b"))
		op = lambda { |s| i = disassemble(s).decoded[0].instruction ; i.to_s ; i.args.last.to_s }
		assert_equal('al', op[bin("\xfe\xc0")])
		assert_equal('ah', op[bin("\xfe\xc4")])
		assert_equal('spl', op[bin("\x40\xfe\xc4")])
		assert_equal('r12b', op[bin("\x41\xfe\xc4")])
		assert_equal('[rip-6+12h]', op[bin("\x8d\x05\x0c\0\0\0")])
	end

	def test_opsz
		assert_equal(bin("\x66\x98"), assemble("cbw"))
		assert_equal(bin("\x98"), assemble("cwde"))
		assert_equal(bin("\x48\x98"), assemble("cdqe"))

		assert_equal(bin("\x0f\xc7\x08"), assemble("cmpxchg8b [rax]"))
		assert_equal(bin("\x48\x0f\xc7\x08"), assemble("cmpxchg16b [rax]"))

		assert_equal(nil, disassemble(bin("\x66\x0f\xc7\x08")).decoded[0])
		assert_equal('cmpxchg8b', disassemble(bin("\x47\x0f\xc7\x08")).decoded[0].opcode.name)
		assert_equal('cmpxchg16b', disassemble(bin("\x48\x0f\xc7\x08")).decoded[0].opcode.name)
	end

	def test_avx
		assert_equal('vmpsadbw ymm12, ymm14, ymm2, 3', disassemble(bin("\xc4\x63\x0d\x42\xe2\x03")).decoded[0].instruction.to_s)
		assert_equal(bin("\xc4\x63\x0d\x42\xe2\x03"), assemble('vmpsadbw ymm12, ymm14, ymm2, 3'))
		assert_equal(bin("\xc5\x31\x63\xc2"), assemble('vpacksswb xmm8, xmm9, xmm2'))
		assert_equal(bin("\xc4\x41\x31\x63\xc2"), assemble('vpacksswb xmm8, xmm9, xmm10'))
		assert_equal(bin("\xc5\x31\x63\x04\x5a"), assemble('vpacksswb xmm8, xmm9, [rdx+2*rbx]'))
		assert_equal(bin("\xc4\x01\x31\x63\x04\x5a"), assemble('vpacksswb xmm8, xmm9, [r10+2*r11]'))
		assert_equal(bin("\xc4\x22\x99\x92\x14\x1a"), assemble('vgatherdpd xmm10, qword ptr [rdx+xmm11], xmm12'))
		assert_equal('vgatherdpd xmm10, qword ptr [rdx+xmm11], xmm12', disassemble(bin("\xc4\x22\x99\x92\x14\x1a")).decoded[0].instruction.to_s)
	end

	def test_lol
		# x64 nop weirdnesses
		assert_equal(bin("\x87\xc0"), assemble('xchg eax, eax'))
		assert_equal('xchg r8, rax', disassemble(bin("\x49\x90")).decoded[0].instruction.to_s)
	end

	def test_C_size
		assert_nothing_raised {
			Metasm::Shellcode.compile_c(@@cpu, "void main(void) { int i=5670, j=8907 ; i = i*j; }").encode_string
		}
	end

end
