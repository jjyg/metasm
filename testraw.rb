#!/usr/bin/env ruby

# usage: test.rb < source.asm

require 'metasm/ia32/parse'
require 'metasm/ia32/encode'
require 'metasm/exe_format/raw'

module Metasm
class Instruction
	def inspect() "#<Instruction:%08x #{@opname.inspect} #{@args.inspect}>" % object_id end
	alias to_s inspect
end
class Opcode
	def inspect() "#<Opcode:%08x @name=#{@name.inspect}>" % object_id end
end
class CPU
	def inspect() "#<CPU:%08x>" % object_id end
end
class Program
	def inspect() "#<Program:%08x>" % object_id end
end
end





cpu = Metasm::Ia32.new
prog = Metasm::Program.new cpu

dump = ARGV.delete '--dump'

prog.parse ARGF.read

prog.encode

shellcode = Metasm::Raw.encode prog
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
