#!/usr/bin/env ruby
require 'metasm/ia32/parse'
require 'metasm/ia32/encode'
require 'metasm/ia32/decode'
require 'metasm/ia32/render'
require 'enumerator'

class String
	@@cpu = Metasm::Ia32.new

	def encode_edata
		p = Metasm::Program.new @@cpu
		p.parse self
		p.encode
		p.sections.first.encoded
	end

	def encode
		ed = encode_edata
		ed.fill
		ed.data
	end

	# eip is the address of the entrypoint
	# base_addr is the address of the first byte of the string
	def decode_blocks(eip=0, base_addr=0)
		p = Metasm::Program.new @@cpu
		s = Metasm::Section.new p, nil
		s.encoded << self
		s.base = base_addr
		p.sections << s
		p.desasm eip
		p
	end

	def decode(eip=0, base_addr=0)
		res = []
		lastaddr = base_addr
		p = decode_blocks(eip, base_addr)
		p.block.sort.each { |addr, block|
			if addr > lastaddr
				res << s.encoded.data[lastaddr-s.base, addr-lastaddr].unpack('C*').map { |c| '%02xh' % c }.enum_slice(16).map { |e| 'db ' + e.join(', ') + "\n" }.join
			end
			if p.block[addr] and not p.block[addr].from.empty?
				res << "; Xrefs: #{p.block[addr].from.map { |f| '%08X' % f }.join(', ')}"
			end
			p.sections.first.encoded.export.each { |e, off|
				res << "#{e}:" if off == addr - p.sections.first.base and e !~ /^metasmintern/
			}
			block.list.each { |di|
				res << ( di.instruction.to_s.ljust(12) + ' ; ' +
					('%08X  ' % addr) +
					p.sections.first.encoded.data[addr-p.sections.first.base, di.bin_length].unpack('C*').map { |c| '%02x' % c }.join )
				addr += di.bin_length
			}
			res << ''
			lastaddr = addr
		}
		addr = base_addr + length
		if addr > lastaddr
			res << s.encoded.data[lastaddr-s.base, addr-lastaddr].unpack('C*').map { |c| '%02xh' % c }.enum_slice(16).map { |e| 'db ' + e.join(', ') + "\n" }.join
		end
		res.join("\n")
	end
end

# get in interactive assembler mode
def asm
	puts 'type "exit" or "quit" to quit', 'use ";" for newline', ''
	while (print "asm> " ; $stdout.flush ; l = gets)
		break if %w[quit exit].include? l.chomp
	
		begin
			data = l.gsub(';', "\n").encode
			puts '"' + data.unpack('C*').map { |c| '\\x%02x' % c }.join + '"'
		rescue Metasm::Exception => e
			puts "Error: #{e.class} #{e.message}"
		end
	end

	puts
end

if __FILE__ == $0
	asm
end
