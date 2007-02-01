#!/usr/bin/ruby

require 'libpe'

if not ARGV[0]
	puts 'give a PE (.exe/.dll) as arg'
	exit
end

begin
	require 'mmap'
	pe = PE.new File.mmap(ARGV[0])
rescue LoadError
	pe = PE.new File.read(ARGV[0])
end

i = pe.imports
if i
	i.each { |k, v|
		puts "lib #{k}"
		v.imports.each { |ii|
			puts "imp #{ii.name}"
		}
		puts
	}
end

e = pe.exports
if e
	e.exports.each { |ee|
		puts "exp #{ee.name}#{' -> '+ee.forwarder.to_s if ee.forwarder}"
	}
end

