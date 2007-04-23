require 'metasm/ia32/decode'
require 'metasm/ia32/render'
require 'metasm/exe_format/elf_decode.rb'

class Metasm::CPU ; def inspect ; 'cpu' end end

pgm = Metasm::ELF.decode(File.read(ARGV.shift)).segments_to_program

#pgm.cpu.make_call_return rescue nil

if ARGV.empty?
	puts pgm.sections.map { |s| s.encoded.export.keys }.flatten.sort
end
ARGV.each { |exp|
	addr = nil
	begin
		addr = Integer(exp)
	rescue ArgumentError
		addr = pgm.export[exp] || exp
	end
	begin
		pgm.desasm addr
	rescue Interrupt
		puts "interrupted, skipping"
	end
}

pgm.block.to_a.sort.each { |addr, block|
	s = pgm.sections.find { |s| s.base <= addr and s.base + s.encoded.virtsize > addr }
	if pgm.block[addr]
		puts "; Xrefs: " + pgm.block[addr].from.map { |f| '%08X' % f }.join(', ')
	end

	s.encoded.export.each { |e, off| puts "#{e}:" if off == addr - s.base and e !~ /^metasmintern/ }
	block.list.each { |di|
		print '%08X ' % addr
		print s.encoded.data[addr-s.base, di.bin_length].unpack('C*').map { |c| '%02x' % c }.join.ljust(16) + ' '
		print di.instruction
		puts

		addr += di.bin_length
	}
	puts
}

