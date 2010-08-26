#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'test/unit'
require 'metasm'

class TestPreproc < Test::Unit::TestCase
	def asm_dasm(src)
		@cpu ||= Metasm::Ia32.new
		raw = Metasm::Shellcode.assemble(src, @cpu).encode_string
		dasm = Metasm::Shellcode.decode(raw, @cpu).disassembler
		dasm.disassemble_fast(0)
		dasm
	end

	def test_compose_bt_binding
		d = asm_dasm <<EOS
mov eax, 1
mov ebx, 2
EOS
		di0, di1 = d.decoded[0].block.list
		assert_equal({:eax => Metasm::Expression[1], :ebx => Metasm::Expression[2]}, d.compose_bt_binding(di0, di1))

		d = asm_dasm <<EOS
mov eax, 1
push eax
EOS
		di0, di1 = d.decoded[0].block.list
		assert_equal({:eax => Metasm::Expression[1], Metasm::Indirection[:esp, 4] => Metasm::Expression[1], :esp => Metasm::Expression[:esp, :+, -4]}, d.compose_bt_binding(di0, di1))

		d = asm_dasm <<EOS
push 1
push 2
EOS
		di0, di1 = d.decoded[0].block.list
		assert_equal({:esp => Metasm::Expression[:esp, :+, -8], Metasm::Indirection[:esp, 4] => Metasm::Expression[2], Metasm::Indirection[[:esp, :+, 4], 4] => Metasm::Expression[1] }, d.compose_bt_binding(di0, di1))
	end
end

