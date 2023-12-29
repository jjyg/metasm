# frozen_string_literal: true

#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'test/unit'
require 'metasm'

class TestAarch64 < Test::Unit::TestCase
  def assemble_aarch64(src, cpu = Metasm::AArch64.new)
    Metasm::Shellcode.assemble(cpu, src).encode_string
  end

  def assemble_x64(src, cpu = Metasm::X86_64.new)
    Metasm::Shellcode.assemble(cpu, src).encode_string
  end

  def assert_equal(a, b)
    super(b, a)
  end

  def bin(s)
    if s.respond_to?(:force_encoding)
      s.force_encoding('BINARY')
    else
      s
    end
  end

  def assert_binary_equal(actual, expected)
    assert_equal(
      actual.bytes.map { |x| "\\x#{x.to_s(16).rjust(2, '0')}" }.join,
      expected.bytes.map { |x| "\\x#{x.to_s(16).rjust(2, '0')}" }.join
    )
  end

  def test_nop
    assert_equal(assemble_aarch64('nop'), bin("\x1f\x20\x03\xd5"))
  end

  data(
    'mov x0, x0' => "\xe0\x03\x00\xaa",
    'mov x0, x1' => "\xe0\x03\x01\xaa",
    'mov x0, x2' => "\xe0\x03\x02\xaa",
    'mov x0, x3' => "\xe0\x03\x03\xaa",
    'mov x0, x4' => "\xe0\x03\x04\xaa",
    'mov x0, x5' => "\xe0\x03\x05\xaa",
    'mov x0, x6' => "\xe0\x03\x06\xaa",
    'mov x0, x7' => "\xe0\x03\x07\xaa",
    'mov x0, x8' => "\xe0\x03\x08\xaa",
    'mov x0, x9' => "\xe0\x03\x09\xaa",
    'mov x0, x10' => "\xe0\x03\x0a\xaa",
    'mov x0, x11' => "\xe0\x03\x0b\xaa",
    'mov x0, x12' => "\xe0\x03\x0c\xaa",
    'mov x0, x13' => "\xe0\x03\x0d\xaa",
    'mov x0, x14' => "\xe0\x03\x0e\xaa",
    'mov x0, x15' => "\xe0\x03\x0f\xaa",
    'mov x0, x16' => "\xe0\x03\x10\xaa",
    'mov x0, x17' => "\xe0\x03\x11\xaa",
    'mov x0, x18' => "\xe0\x03\x12\xaa",
    'mov x0, x19' => "\xe0\x03\x13\xaa",
    'mov x0, x20' => "\xe0\x03\x14\xaa",
    'mov x0, x21' => "\xe0\x03\x15\xaa",
    'mov x0, x22' => "\xe0\x03\x16\xaa",
    'mov x0, x23' => "\xe0\x03\x17\xaa",
    'mov x0, x24' => "\xe0\x03\x18\xaa",
    'mov x0, x25' => "\xe0\x03\x19\xaa",
    'mov x0, x26' => "\xe0\x03\x1a\xaa",
    'mov x0, x27' => "\xe0\x03\x1b\xaa",
    'mov x0, x28' => "\xe0\x03\x1c\xaa",
    'mov x0, x29' => "\xe0\x03\x1d\xaa",
    'mov x0, x30' => "\xe0\x03\x1e\xaa",

    'mov x1, x0' => "\xe1\x03\x00\xaa",
    'mov x2, x0' => "\xe2\x03\x00\xaa",
    'mov x3, x0' => "\xe3\x03\x00\xaa",
    'mov x4, x0' => "\xe4\x03\x00\xaa",
    'mov x5, x0' => "\xe5\x03\x00\xaa",
    'mov x6, x0' => "\xe6\x03\x00\xaa",
    'mov x7, x0' => "\xe7\x03\x00\xaa",
    'mov x8, x0' => "\xe8\x03\x00\xaa",
    'mov x9, x0' => "\xe9\x03\x00\xaa",
    'mov x10, x0' => "\xea\x03\x00\xaa",
    'mov x11, x0' => "\xeb\x03\x00\xaa",
    'mov x12, x0' => "\xec\x03\x00\xaa",
    'mov x13, x0' => "\xed\x03\x00\xaa",
    'mov x14, x0' => "\xee\x03\x00\xaa",
    'mov x15, x0' => "\xef\x03\x00\xaa",
    'mov x16, x0' => "\xf0\x03\x00\xaa",
    'mov x17, x0' => "\xf1\x03\x00\xaa",
    'mov x18, x0' => "\xf2\x03\x00\xaa",
    'mov x19, x0' => "\xf3\x03\x00\xaa",
    'mov x20, x0' => "\xf4\x03\x00\xaa",
    'mov x21, x0' => "\xf5\x03\x00\xaa",
    'mov x22, x0' => "\xf6\x03\x00\xaa",
    'mov x23, x0' => "\xf7\x03\x00\xaa",
    'mov x24, x0' => "\xf8\x03\x00\xaa",
    'mov x25, x0' => "\xf9\x03\x00\xaa",
    'mov x26, x0' => "\xfa\x03\x00\xaa",
    'mov x27, x0' => "\xfb\x03\x00\xaa",
    'mov x28, x0' => "\xfc\x03\x00\xaa",
    'mov x29, x0' => "\xfd\x03\x00\xaa",
    'mov x30, x0' => "\xfe\x03\x00\xaa",

    'mov w0, w0' => "\xe0\x03\x00\x2a",
    'mov w0, w1' => "\xe0\x03\x01\x2a",
    'mov w1, w0' => "\xe1\x03\x00\x2a"
  )
  def test_mov_registers(expected)
    assert_binary_equal(assemble_aarch64(data_label), bin(expected))
  end

  # data(
  # 	"mov x0, xzr" => "\xe0\x03\x1f\xaa",
  # 	"mov x1, xzr" => "\xe1\x03\x1f\xaa",
  #
  # 	"mov w0, wzr" => "\xe0\x03\x1f\x2a",
  # 	"mov w1, wzr" => "\xe1\x03\x1f\x2a",
  # )
  # def test_registers_zr(expected)
  # 	assert_binary_equal(assemble_aarch64(data_label), bin(expected))
  # end

  # data(
  # 	"mov x0, sp" => "\xe0\x03\x00\x91",
  # 	"mov x1, sp" => "\xe1\x03\x00\x91",
  # 	"mov w0, wsp" => "\xe0\x03\x00\x11",
  # 	"mov w1, wsp" => "\xe1\x03\x00\x11",
  # )
  # def test_registers_sp(expected)
  #   # pend 'not yet implemented'
  # 	assert_binary_equal(assemble_aarch64(data_label), bin(expected))
  # end

  # data(
  #   "mov x0, #0" => "\x00\x00\x80\xd2",
  #   # "mov x0, #1" => "\x20\x00\x80\xd2",
  #   # "mov x0, #2" => "\x40\x00\x80\xd2",
  #   # "mov x0, #3" => "\x60\x00\x80\xd2",
  #   # "mov x0, #255" => "\xe0\x1f\x80\xd2"
  #   # "mov x0, # 0xFF" => "\x00\x20\x80\xd2"
  # 	# "mov x0, #0xFF" => "\x00\x20\x80\xd2"
  # )
  # def test_mov_imm(expected)
  # 	assert_binary_equal(assemble_aarch64(data_label), bin(expected))
  # end

  data(
    'movz x0, #0' => "\x00\x00\x80\xd2",
    'movz x0, #1' => "\x20\x00\x80\xd2",
    'movz x0, #2' => "\x40\x00\x80\xd2",
    'movz x0, #3' => "\x60\x00\x80\xd2",
    'movz x0, #255' => "\xe0\x1f\x80\xd2",
    'movz x0, # 0xFF' => "\xe0\x1f\x80\xd2",
    'movz x0, #0xFF' => "\xe0\x1f\x80\xd2",
    'movz x1, #0' => "\x01\x00\x80\xd2",
    'movz x1, #1' => "\x21\x00\x80\xd2"
  )
  def test_movz_imm(expected)
    assert_binary_equal(assemble_aarch64(data_label), bin(expected))
  end

  data(
    'movk x0, #0' => "\x00\x00\x80\xf2",
    'movk x0, #1' => "\x20\x00\x80\xf2"
    # 	"movk x1, #1" => "\x21\x00\x80\xf2",
    # 	"movk x0, #1, lsl #16" => "\x20\x00\xa0\xf2",
    # 	"movk x0, #1, lsl #32" => "\x20\x00\xc0\xf2"
  )
  def test_movk_imm(expected)
    assert_binary_equal(assemble_aarch64(data_label), bin(expected))
  end

  # data(
  # 	"and x0, x0, #1" => "\x00\x00\x40\x92",
  # 	# "and x0, x1, #1" => "\x20\x00\x40\x92",
  # 	# "and x1, x0, #1" => "\x01\x00\x40\x92",
  # 	# "and x1, x0, #2" => "\x01\x00\x7f\x92",
  # )
  # def test_and(expected)
  # 	assert_binary_equal(assemble_aarch64(data_label), bin(expected))
  # end

  # data(
  # 	"cmp x0, x0" => "\x1f\x00\x00\xeb",
  # 	"cmp x0, x1" => "\x1f\x00\x01\xeb",
  # 	"cmp x1, x0" => "\x3f\x00\x00\xeb",
  # 	"cmp x1, x1" => "\x3f\x00\x01\xeb",

  # 	"cmp w0, w0" => "\x1f\x00\x00\x6b",
  # 	"cmp w0, w1" => "\x1f\x00\x01\x6b",
  # 	"cmp w1, w0" => "\x3f\x00\x00\x6b",
  # 	"cmp w1, w1" => "\x3f\x00\x01\x6b",
  # )
  # def test_cmp(expected)
  # 	# pend 'not yet implemented'
  # 	assert_binary_equal(assemble_aarch64(data_label), bin(expected))
  # end

  # data(
  # 	"str x0, [x0]" => "\x00\x00\x00\xf9",
  # 	"str x0, [x1]" => "\x20\x00\x00\xf9",
  # 	"str x1, [x0]" => "\x01\x00\x00\xf9",
  # 	"str x1, [sp]" => "\xe1\x03\x00\xf9",
  # 	"str x1, [sp, #-8]" => "\xe1\x83\x1f\xf8",
  # )
  # def test_str(expected)
  #   # pend 'not yet implemented'
  # 	assert_binary_equal(assemble_aarch64(data_label), bin(expected))
  # end

  data(
    'svc #0' => "\x01\x00\x00\xd4",
    'svc #1' => "\x21\x00\x00\xd4"
  )
  def test_svc(expected)
    assert_binary_equal(assemble_aarch64(data_label), bin(expected))
  end

  data(
    'brk #0' => "\x00\x00\x20\xd4",
    'brk #1' => "\x20\x00\x20\xd4"
  )
  def test_brk(expected)
    assert_binary_equal(assemble_aarch64(data_label), bin(expected))
  end
end
