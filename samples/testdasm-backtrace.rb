#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory



require 'metasm-shell'

# String.cpu.make_call_return	# assume call does not stop_exec

puts <<EOS.encode(0).decode

; calcule l'adresse du saut
mov ebx, 0x12345678
mov eax, ((toto + 12) ^ 0x12345678)
xor eax, ebx
sub eax, 12

; saute
call eax

; code mort
add eax, 42
; die, you vile reverser !
db 0e9h

; cible du saut
toto:
mov eax, 28h

EOS
