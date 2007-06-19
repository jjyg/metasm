#!/usr/bin/env ruby

# usage: test.rb < source.asm

require 'metasm'


dump = ARGV.delete '--dump'

source = ARGF.read

cpu = Metasm::Ia32.new
shellcode = Metasm::Shellcode.assemble(cpu, source).encode_string
shellstring = shellcode.unpack('C*').map { |b| '\\x%02x' % b }.join

if dump
	puts shellstring
	exit
end

File.open('test-testraw.c', 'w') { |fd|
	fd.puts <<EOS
unsigned char sc[] = "#{shellstring}";
int main(void)
{
	((void (*)())sc)();
	return 42;
}
EOS
}

system 'gcc -W -Wall -o test-testraw test-testraw.c'
system 'chpax -psm test-testraw'

puts "running"
system './test-testraw'
puts "done"
#File.unlink 'test-testraw'
File.unlink 'test-testraw.c'
