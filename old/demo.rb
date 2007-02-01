#!/usr/bin/ruby -d

puts 'Welcome to the Metasm Circus'


require 'strscan'
require 'metasm/ia32'

cpu = Metasm::Ia32.new

ss1 = StringScanner.new 'nop'
ss2 = StringScanner.new "\x90"
ss3 = StringScanner.new 'inc dword [fs:eax + 4*ebx]'
ss4 = StringScanner.new "\x85\x15\x28\x28\x28\x29"

puts

# parse
i = cpu.parse ss1

# render
puts i

# encode
ec = i.encode
puts ec.unpack('C*').map { |b| '%.2x' % b }.join(' ')

puts

# decode
i = cpu.decode ss2
puts i

puts

i = cpu.parse ss3
puts i

# encode does not handle fs override yet, and the modrm need to be fixed up

puts

i = cpu.decode ss4
puts i
