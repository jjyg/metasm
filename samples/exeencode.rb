#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this sample shows how to compile an ELF file
# use --exe PE to compile a PE
# use --cpu MIPS, --16, --be to change the CPU
# either from C or ASM source
#

require 'metasm'
require 'optparse'

execlass ||= Metasm::ELF
cpu ||= Metasm::Ia32.new

outfilename = 'a.out'
type = nil
OptionParser.new { |opt|
	opt.on('-o file') { |f| outfilename = f }
	opt.on('--c') { type = 'c' }
	opt.on('--asm') { type = 'asm' }
	opt.on('-v', '-W') { $VERBOSE=true }
	opt.on('-d') { $DEBUG=$VERBOSE=true }
	opt.on('-e class', '--exe class') { |c| execlass = Metasm.const_get(c) }
	opt.on('--cpu cpu') { |c| cpu = Metasm.const_get(c).new }
	# must come after --cpu in commandline
	opt.on('--16') { cpu.size = 16 }
	opt.on('--le') { cpu.endianness = :little }
	opt.on('--be') { cpu.endianness = :big }
}.parse!

if file = ARGV.shift
	src = File.read(file)
	type ||= 'c' if file =~ /\.c$/
else
	src = DATA.read	# the text after __END__
end

if type == 'c'
	elf = execlass.compile_c(cpu, src)
else
	elf = execlass.assemble(cpu, src)
end
elf.encode_file(outfilename)

__END__
.interp '/lib/ld-linux.so.2'
.pt_gnu_stack rw

.data
toto db "world", 0
fmt db "Hello, %s !\n", 0

.text
.entrypoint
 call metasm_intern_geteip
 mov esi, eax
 lea eax, [esi-metasm_intern_geteip+toto]
 push eax
 lea eax, [esi-metasm_intern_geteip+fmt]
 push eax
 call printf
 add esp, 8

 push 28h
 call _exit
 add esp, 4
 ret

metasm_intern_geteip:
 call 1f
1:
 pop eax
 add eax, metasm_intern_geteip - 1b
 ret

