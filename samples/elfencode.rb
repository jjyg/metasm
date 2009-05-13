#!/usr/bin/env ruby

#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2008 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm'
$execlass = Metasm::ELF
load File.join(File.dirname(__FILE__), 'exeencode.rb')

__END__
.pt_gnu_stack rw
.text
.entrypoint
push bla
push fmt
call printf
push 0
call exit

.data
bla db "world", 0
fmt db "Hello, %s !\n", 0
