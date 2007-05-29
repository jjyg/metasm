#!/usr/bin/ruby

require 'metasm-shell'

puts <<EOS.encode(0).decode

; calcule l'adresse du saut
mov ebx, 0x12345678
mov eax, ((toto + 12) ^ 0x12345678)
xor eax, ebx
sub eax, 12

; saute
push eax
ret

; code mort
nop

; cible du saut
toto:
mov eax, 28h

EOS
