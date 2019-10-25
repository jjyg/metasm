require 'idaclient'

# retrieve all opcodes from the current IDB, and display some stats
ida = IdaClient.new

cnt = Hash.new(0)
ida.batch {
	ida.each_segment { |s_start, s_end, s_name|
		ida.each_head(s_start, s_end) { |head|
			ida.get_op_mnemonic(head) { |mn|
				cnt[mn] += 1 if mn
			}
		}
	}
}

puts "Found #{cnt.values.inject(:+)} instructions, top 10:"
puts cnt.sort_by { |op, c| -c }[0, 10].map { |op, c| "\t#{c}\t#{op}" }
