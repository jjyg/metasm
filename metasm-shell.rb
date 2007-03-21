#require 'metasm/cpus'
require 'metasm/ia32/parse'
require 'metasm/ia32/encode'

cpu = Metasm::Ia32.new

puts 'type "exit" or "quit" to quit'
while (print "> " ; $stdout.flush ; l = gets)
	exit if %w[quit exit].include? l.chomp
	p = Metasm::Program.new cpu
	begin
		p.parse l
		p.encode
		ed = p.sections.first.encoded
		ed.fill
		puts '"' + ed.data.unpack('C*').map { |c| '\\x%02x' % c }.join + '"'
		ed.reloc.each { |o, r|
			puts "reloc #{r.target} type #{r.type} endianness #{r.endianness} starting at offset #{o}"
			r.target.externals.each { |e|
				puts "label #{e} at offset #{ed.export[e]}" if ed.export[e]
			}
		}
	rescue Metasm::Exception => e
		puts "Error: #{e.class} #{e.message}"
	end
end
puts
