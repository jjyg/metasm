#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this sample shows how to compile an executable file from source
# use --exe PE to compile a PE/ELF/MachO etc
# use --cpu MIPS/--16/--be to change the CPU
# the arg is a source file (c or asm) (some arch may not yet support C compiling)
# defaults to encoding a shellcode, use --exe to override (or the scripts samples/{elf,pe}encode)
# to compile a shellcode to a cstring, use --cstring
#

require 'metasm'
require 'optparse'

$execlass ||= Metasm::Shellcode
$cpu ||= Metasm::Ia32.new

outfilename = 'a.out'
type = nil
etype = :bin
macros = {}
OptionParser.new { |opt|
	opt.on('-o file', 'output filename') { |f| outfilename = f }
	opt.on('--c', 'parse source as a C file') { type = 'c' }
	opt.on('--asm', 'parse asm as an ASM file') { type = 'asm' }
	opt.on('--stdin', 'parse source on stdin') { ARGV << '-' }
	opt.on('-v', '-W', 'verbose') { $VERBOSE=true }
	opt.on('-d', 'debug') { $DEBUG=$VERBOSE=true }
	opt.on('-D var=val', 'define a preprocessor macro') { |v| v0, v1 = v.split('=', 2) ; macros[v0] = v1 }
	opt.on('--cstring', 'encode output as a C string to stdout') { $to_cstring = true }
	opt.on('--string', 'encode output as a string to stdout') { $to_string = true }
	opt.on('-e class', '--exe class', 'use a specific ExeFormat class') { |c| $execlass = Metasm.const_get(c) }
	opt.on('--cpu cpu', 'use a specific CPU class') { |c| $cpu = Metasm.const_get(c).new }
	# must come after --cpu in commandline
	opt.on('--16', 'set cpu in 16bit mode') { $cpu.size = 16 }
	opt.on('--le', 'set cpu in little-endian mode') { $cpu.endianness = :little }
	opt.on('--be', 'set cpu in big-endian mode') { $cpu.endianness = :big }
	opt.on('-fno-pic', 'generate position-dependant code') { $cpu.generate_PIC = false }
	opt.on('--shared', 'generate shared library') { etype = :lib }
}.parse!

if file = ARGV.shift
	type ||= 'c' if file =~ /\.c$/
	src = macros.map { |k, v| "#define #{k} #{v}\n" }.join
	if file == '-'
		src << $stdin.read
	else
		src << File.read(file)
	end
else
	src = DATA.read	# the text after __END__
end

if type == 'c'
	exe = $execlass.compile_c($cpu, src, file)
else
	exe = $execlass.assemble($cpu, src, file)
end

if $to_string
	p exe.encode_string
elsif $to_cstring
	str = exe.encode_string
	var = File.basename(file)[/^\w+/] || 'sc'	# derive varname from filename
	puts "unsigned char #{var}[#{str.length}] = ", str.scan(/.{1,19}/m).map { |l|
		'"' + l.unpack('C*').map { |c| '\\x%02x' % c }.join + '"'
	}.join("\n") + ';'
else
	exe.encode_file(outfilename, etype)
end

__END__
#include <asm/unistd.h>
jmp getip
gotip:
mov eax, __NR_write
mov ebx, 1
pop ecx
mov edx, strend-str
int 80h

mov eax, __NR_exit
mov ebx, 1
int 80h

getip:
call gotip

str db "Hello, world!", 0xa
strend:
