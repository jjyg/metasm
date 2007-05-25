#!/usr/bin/ruby

require 'metasm-shell'

puts <<EOS.encode(0).decode
mov ebx, 0x12345678
mov eax, ((toto + 12) ^ 0x12345678)
xor eax, ebx
sub eax, 12
push eax
ret
nop
toto:
mov eax, 28h
EOS
