#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory



require 'enumerator'

class IO
def hexdump(fmt=nil)
	ctx = {:noend => true}
	while buf = read(512) and not buf.empty?
		buf.hexdump(fmt, ctx)
	end
	ctx.delete :noend
	''.hexdump(fmt, ctx)
end
end

class String
def hexdump(fmt=nil, ctx={})
	fmt ||= ['c', 'd', 'a']
	ctx[:pos] ||= 0
	ctx[:lastline] ||= []
	ctx[:lastdup]
	unpack('C*').each_slice(16) { |s|
		if s != ctx[:lastline]
			ctx[:lastdup] = false
			print '%04x  ' % ctx[:pos]
			print s.map { |b| '%02x' % b }.join(' ').ljust(3*16-1) + '  ' if fmt.include? 'c'
			print s.pack('C*').unpack('L*').map { |bb| '%08x' % bb }.join(' ').ljust(9*4-1) + '  ' if fmt.include? 'd'
			print s.map { |c| (32..126).include?(c) ? c : ?. }.pack('C*') if fmt.include? 'a'
			puts
		elsif not ctx[:lastdup]
			ctx[:lastdup] = true
			puts '*'
		end
		ctx[:lastline] = s
		ctx[:pos] += s.length
	}
	puts '%04x' % ctx[:pos] if not ctx[:noend]
end
end

if $0 == __FILE__
	(fmt ||= [] << 'c' << 'a') if ARGV.delete '-C'
	(fmt ||= [] << 'd' << 'a') if ARGV.delete '-d'
	(fmt ||= [] << 'c' << 'd' << 'a') if ARGV.delete '-a'
	File.open(ARGV.first, 'rb').hexdump(fmt)
end
