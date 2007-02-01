#!/usr/bin/ruby

require 'metasm/parse'

l = Metasm::AssemblyLexer.new <<EOS

in macro x
foo:
bar
endm

out macro x
out1
in(x)
out3
endm

x1 x2
out(42)
x3 x4
EOS

until l.eos?
	p l.readtok
end

p l.macros['out'].body

