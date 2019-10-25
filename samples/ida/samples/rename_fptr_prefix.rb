require 'idaclient'

# read a table of function pointers starting under the cursor in IDA
# rename all entries starting with 'sub_' to '<prefix>_'
# stops at the first non-pointer

prefix = ARGV.shift or abort "usage: rename_prefix <prefix>"

ida = IdaClient.new

# retrieve the current IDA cpu word size (in bits)
dwsz = ida.get_cpuinfo[:size]

# address of the pointer in the IDA window
off = ida.get_cursor_pos

loop do
	# read one pointer from the current address
	ptr = case dwsz
	      when 16; ida.get_word(off)
	      when 32; ida.get_dword(off)
	      when 64; ida.get_qword(off)
	      end
	break if ptr == 0

	# check if it points to a named location
	break if not l = ida.get_label(ptr)

	# advance to the next pointer
	off += dwsz/8

	puts "#{'%x' % off} #{l}"

	if l =~ /^sub_(.*)/
		suffix = $1
		# rename it
		ida.set_label(ptr, "#{prefix}_#{suffix}")
	end
end
