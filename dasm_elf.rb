require 'metasm/ia32/decode'
require 'metasm/ia32/render'
require 'metasm/exe_format/elf.rb'

if ARGV.empty?
	ARGV << '/lib/libc.so.6' << 'ispunct'
end

class Metasm::CPU ; def inspect ; 'cpu' end end

pgm, opts = Metasm::ELF.decode File.read(ARGV.shift)
pgm.cpu.make_call_return rescue nil
([opts['entrypoint']].compact + ARGV).each { |exp|
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

pgm.block.sort.each { |addr, block|
	s = pgm.sections.find { |s| s.base <= addr and s.base + s.encoded.virtsize > addr }
	if pgm.block[addr]
		puts "; Xrefs: " + pgm.block[addr].from.map { |f| '%08x' % f }.join(', ')
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

