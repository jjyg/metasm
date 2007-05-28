#!/usr/bin/env ruby

require 'enumerator'
o = -16
lastl = []
lastdpl = false
File.open(ARGV.first, 'rb') { |fd| fd.read }.unpack('C*').each_slice(16) { |s|
	o += 16
	if s != lastl
		lastdpl = false
		print '%04x  ' % o
		print s.map { |b| '%02x' % b }.join(' ').ljust(3*16-1) + '  '
		print s.pack('C*').unpack('L*').map { |bb| '%08x' % bb }.join(' ').ljust(9*4-1) + '  '
		puts  s.map { |c| (32..126).include?(c) ? c : ?. }.pack('C*')
	elsif not lastdpl
		lastdpl = true
		puts '*'
	end
	lastl = s
}

