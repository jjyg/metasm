require 'idaclient'

# script to move the IDA cursor to the next labeled statement

ida = IdaClient.new
ida.batch {
	# retrieve the current cursor position in IDA
	ida.get_cursor_pos { |cp|
		# get the end of the segment where the cursor is
		ida.get_segment_end(cp) { |s_end|
			# get all labeled addresses from the cursor to the end of the segment
			ida.get_named_addrs(cp+1, s_end) { |addrs|
				# move the IDA cursor to the next label, or to the end of the segment
				ida.set_cursor_pos(addrs.first || s_end)
			}
		}
	}
}
