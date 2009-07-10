#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# shows the compilation phase step by step: c, simplified c, asm

require 'metasm'

pic = ARGV.delete '--pic'

src = ARGV.empty? ? <<EOS : ARGF.read
void foo(int);
void bla()
{
	int i = 10;
	while (--i)
		foo(i);
}
EOS

cp = Metasm::C::Parser.parse src
puts cp, '', ' ----', ''
cp.precompile
puts cp, '', ' ----', ''

cp = Metasm::C::Parser.parse src
cpu = Metasm::Ia32.new
cpu.generate_PIC = false unless pic
puts cpu.new_ccompiler(cp).compile
