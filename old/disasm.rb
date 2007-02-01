#!/usr/bin/ruby

# TODO
# get rid of the other scripts
# handle the cpu spec

file = ARGV[0]
fd = File.open(file)
bla = fd.read 4
goodscript = 
if bla == "\x7fELF"
	puts 'ELF'
	'dasm_elf_x86.rb'
elsif bla[0..1] == "MZ"
	fd.seek(0x3c)
	bla = fd.read 4
	off = 0
	bla.reverse.each_byte { |b| off <<= 8 ; off |= b }
	fd.seek(off) rescue nil
	bla = fd.read 4
	if bla == "PE\0\0"
		puts 'PE'
		'dasm_pe_x86.rb'
	else
		puts 'MZ - unsupported !'
		'dasm_raw_x86.rb'
	end
else
	puts 'binary'
	'dasm_raw_x86.rb'
end
fd.close

exec goodscript, *ARGV
