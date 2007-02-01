#!/usr/bin/env ruby

# usage: test.rb < source.asm

require 'metasm/ia32/parse'
require 'metasm/ia32/encode'

cpu = Metasm::Ia32.new
prog = Metasm::Program.new cpu

prog.parse <<EOS
.text
and eax, 0x800
nop
align 16

bar:
db #{ARGV.shift || 42} dup(3 dup('x'), 'y')
foo:
EOS

prog.sections.first.encode
edata = prog.sections.first.encoded
edata.fixup
edata.fill
p edata.reloc
data = edata.data

require 'enumerator'
o = -16
data.unpack('C*').each_slice(16) { |s|
	print '%04x  ' % (o += 16)
	print s.map { |b| '%02x' % b }.join(' ').ljust(3*16-1) + '  '
	print s.pack('C*').unpack('L*').map { |bb| '%08x' % bb }.join(' ').ljust(9*4-1) + '  '
	puts  s.pack('C*').tr('^a-z0-9A-Z', '.')
}
