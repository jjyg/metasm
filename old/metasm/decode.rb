require 'metasm/main'

module Metasm

# raised if the binary string presented does not match any known Opcode
class InvalidOpcode
	def initialize(str)
		@dump = (0..7).map { |i| '%.2X' % str[i].to_i }.join
	end
	
	def to_s
		'Invalid opcode: ' + @dump
	end
end

class CPU
	def bin_lookaside
		@bin_lookaside ||= build_bin_lookaside
	end
end

class Opcode
	# returns something similar to bin, with unknown bits (which depend on a field value) set to 0
	def bin_mask
		@bin_mask ||= build_bin_mask
	end
end

class Immediate
	def self.decode(ss, len=@@defsz, opt={})
		opt.update({ :signed => false, :endianness => @@endianness }.update(opt))
		
		val = 0
		case opt[:endianness]
		when :little : (len/8).times { |i| val |= (ss.get_byte[0] << (8*i)) rescue 0 }
		when :big    : (len/8).times { val <<= 8 ; val |= ss.get_byte[0] rescue 0 }
		else raise SyntaxError, "Unsupported endianness #{opt[:endianness]}"
		end

		# the new is responsible for dropping the superfluous bits (i.e. if len == 6)
		new val, len, opt[:signed]
	end
end

module Fixlen
class Opcode
	def build_bin_mask
		@bin_mask = 0
		@cpu.fields_mask.each { |k, v|
			next unless f = @fields[k]
			@bin_mask |= (v << f)
		}
		@bin_mask ^= (1 << @cpu.size) - 1
	end
end
end

module Varlen
class CPU
	# lookaside table containing every opcode that may match a binary value: key X points to an array containing all opcode whose 1st byte can take the value X (uses bin_mask)
	def build_bin_lookaside
		la = Array.new(256) { [] }
		opcode_list.each { |o|
			b = o.bin[0]
			msk = o.bin_mask[0]
			
			# this is useless
			if msk & 0xf == 0xf
				msk = (msk >> 4) | 0xf0
				mo = 4
			else
				mo = 0
			end
			
			for i in 0..(255-msk)
				next if i & msk != 0
				la[b | (i << mo)] << o
			end
		}
		la
	end
	
	def decode(ss)
		i = instruction.new(self)
		i.decode(ss)
		i
	end
end

class Opcode
	def build_bin_mask
		@bin_mask = Array.new(@bin.length, 0)

		@cpu.fields_mask.each { |k, v|
			next unless f = @fields[k]
			@bin_mask[f[0]] |= (v << f[1])
		}

		@bin_mask.map! { |v| 255 ^ v }
	end
end

class Instruction
	# waits a stringscanner pointing at the beginning of the encoded instruction
	def decode(ss)
		until @op = bin_find(ss)
			decode_pfx ss
		end

		@name = @op.name
		do_decode ss
	end
	
	private
	# find the good opcode matching the binary string
	def bin_find(ss)
		@bin_find_peek_len ||= @cpu.opcode_list.map { |o| o.bin.length }.max
		bseq = ss.peek(@bin_find_peek_len).unpack('C*')
		@cpu.bin_lookaside[bseq[0]].find { |@op|
			dec_valid_op?(bseq) and @op.bin.zip(@op.bin_mask, bseq).all? { |b, m, s| s & m == b }
		}
	end

	# is the opcode valid for matching bseq ? (knowing the current @pfxlist)
	def dec_valid_op?(bseq)
		true
	end

	# Interprets the binary +str+ to decode a prefix for the current (unknown) instruction
	def decode_pfx(ss)
		ss.pos -= 1
		raise InvalidOpcode.new(ss.peek(8))
	end

	# retrieve the value of a field given the binary string and the field name
	def fieldval(bseq, fname)
		f = @op.fields[fname]
		(bseq[f.first] >> f.last) & @cpu.fields_mask[fname]
	end

	# do the decoding of fields and arguments
	def do_decode(ss)
		bin = ss.peek(@op.bin.length).unpack('C*')
		ss.pos += @op.bin.length
		# decode fields
	end
end
end

end # module
