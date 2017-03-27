#!/usr/bin/ruby

require 'xml'

xml = Xml.parse_file(ARGV.shift || 'openrisc-insn.html')

# [name, bin, args]
addop = []
# arg => [flds]
valid_args = {}
# field => [bitoff, bitmask]
fields = {}

xml.each('ul') { |ul|
	syntax = nil
	bits = []
	vals = []
	trno = 0
	ul.each('li') { |li|
		if li.children[0] == 'syntax:'
			# <li>syntax:<tt><font>l.add $rd, $ra, $rb</font></tt></li>
			syntax = li.children[1].children[0].children[0]
		end
	}
	next if not syntax
	ul.each('tr') { |tr|
		case trno
		when 0; tr.each('td') { |td| bits << td.children[0].split.map { |b| b.to_i } }
		when 2; tr.each('td') { |td| vals << td.children.map { |v| v =~ /^0x/ ? v.to_i(16) : v.gsub('-', '') }.first }
		end
		trno += 1
	}

	iname = syntax.split[0].sub(/^l\./, '')
	iargs = syntax.split[1].to_s.split(',').map { |a| a.gsub(/[${}-]/, '').gsub(/(\w+)\((\w+)\)/, '\2_\1') }
	bin = bits.zip(vals).inject(0) { |b, (bt, bv)| bv.kind_of?(Integer) ? b | (bv << bt.last) : b }
	addop << [iname, bin]

	flds = bits.zip(vals).inject({}) { |h, (bt, bv)|
		next h if bv.kind_of?(Integer)
		blen = bt.first + 1 - bt.last
		h.update bv => [bt.last, (1 << blen) - 1]
	}
	flds.each { |n, (o, m)|
		if not fields[n]
			fields[n] = [o, m]
		elsif fields[n] != [o, m]
			puts "# fields mismatch in #{iname} #{n}"
		end
	}

	addop.last << iargs

	iargs.each { |a|
		a.split('_').each { |f|
			if not flds.delete(f)
				puts "# no field #{f} for arg #{a} in #{iname}"
			end
		}
		valid_args[a] ||= a.split('_')
	}
	flds.each_key { |f|
		puts "# no arg using #{f} in #{iname}"
		a_i = "#{f}_ign"
		valid_args[a_i] ||= [f]
		addop.last.last << a_i
	}
}

puts "\tdef init_cpu"
puts "\t\t@opcode_list = []"
puts "\t\t@valid_args = { #{valid_args.map { |a, f| ":#{a} => [#{f.map { |ff| ':' + ff }.join(', ')}]" }.join(', ')} }"
puts "\t\t@fields_off = { #{fields.map { |k, v| ":#{k} => #{v[0]}" }.join(', ')} }"
puts "\t\t@fields_mask = { #{fields.map { |k, v| ":#{k} => #{'0x%02X' % v[1]}" }.join(', ')} }"
puts
addop.each { |op|
	puts "\t\taddop '#{op[0]}', #{'0x%08X' % op[1]}#{op[2].map { |a| ", :#{a}" }.join('')}"
}
puts "\tend"
