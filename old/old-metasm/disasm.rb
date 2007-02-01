require 'metasm/metasm'

module Metasm

# Exception raised when an opcode cannot be decoded
class InvalidOpcode < RuntimeError
	def initialize(str, idx)
		@o = []
		4.times { |i| @o << str[idx+i] }
	end
	
	def message
		'Invalid opcode %.2X%.2X%.2X%.2X' % @o
	end
end

# Describes an instruction of a processor
class Mnemonic
	# field-indexed hash of procs able to decode their field from the binary string
	# its arguments are [instruction, field value, opcode global string,
	#  current instruction offset in the string, current argument offset in the string]
	@@decode_proc  = {}
	# array of fields name, to specify the order of decoding
	@@decode_order = []
	
	# +mask+ is the binary mask covering all the possible fields values ([0x0F, 0x01])
	def mask
		@mask or (
		@mask = Array.new(@bin.length, 0)

		k = v = f = nil
		@@fields_mask.each { |k, v|
			next unless f = @fields[k]
			@mask[f[0]] |= (v << f[1])
		}
	
		@mask.map! { |v| 255 - v }
		)
	end

	# checks if the binary +str[idx]+ corresponds to us - can use +instr+ for
	# context (prefix). If no mnemonic matches, str[idx] is considered a prefix
	# and passed to +instr+ by the caller, and we'll eventually get back here
	def bin_match?(str, idx, instr)
		for i in 0...@bin.length
			return false if (str[idx+i] & mask[i]) != @bin[i]
		end
		true
	end
	
	# +str[idx]+ matches us: decode it now in +instr+
	def decode(str, idx, instr)
		instr.mn = self
		instr.name = @name
		ibase = idx + instr.length
		instr.length += @bin.length
		for f in @@decode_order
			next unless @fields[f] or @args[f] or @props[f]
			decode_field(instr, f, str, ibase, idx+instr.length)
		end
		instr
	end

	# decode the field +f+ from the opcode starting at +str[ibase]+
	# (prefix bytes are before ibase)
	# the next binary argument starts at +argidx+
	# if the field consumes an argument, it must increase instr.length accordingly
	def decode_field(instr, f, str, ibase, argidx)
		fld = @fields[f]
		v = (str[ibase + fld[0]] >> fld[1]) & @@fields_mask[f] if fld
		@@decode_proc[f].call(instr, v, str, ibase, argidx)
	end
end

class Instruction
	# the data at +str[idx]+ does not correspond to any Mnemonic,
	# so it may be an instruction prefix
	# this function returns the size of the prefix found, and must raise an
	# error if the opcode is invalid (just use +super+ in a subclass)
	def decode_pfx(str, idx)
		raise InvalidOpcode.new(str, idx)
	end
end

class Immediate
	def self.decode(str, idx, len, signed=false)
		v = 0
		case @@endianness
		when :big
			len.times { |i| v |= (str[idx+i] << (8*i)) }
		when :little
			len.times { |i| v <<= 8 ; v |= str[idx+i] }
		else
			raise SyntaxError.new('Unsupported endianness')
		end
		new v, len, signed
	end
end

class Disassembler < Metasm
	def initialize(*args)
		super
		init_opcodes_split
	end

	# creates a 256-entry list, l[x] is the list of all the mnemonics accepting x as first byte
	# this is done to avoid trying to match all the mnemonics against an octet string
	def init_opcodes_split
		msk, m, mo, b, i = nil
		@opcodes_split = Array.new(256){[]}
		@mnemonic.list.each { |m|
			b = m.bin[0]
			msk = m.mask[0]

			# hair-tracted, completely useless optimisation
			if msk & 0xf == 0xf
				msk = (msk >> 4) | 0xf0
				mo = 4
			else
				mo = 0
			end
			
			for i in 0..(255-msk)
				next if i & msk != 0
				@opcodes_split[b|(i << mo)] << m
			end
		}
# @opcodes_split.each_with_index { |o, i| puts(("%.2x: #{o.length} - " % i) + o.map{ |m| m.name }.join(', ')) }
	end

	# decodes one instruction from the binary string +str+ starting at +idx+
	# returns an @instr_class or raises InvalidOpcode
	def decode(str, idx = 0)
		instr = @instr_class.new
		m = nil
		loop do
			idx += instr.length
			@opcodes_split[str[idx]].each { |m|
				next unless m.bin_match?(str, idx, instr)
				
				# found it !
				m.decode(str, idx, instr)
				return instr
			}
			
			# not found, may be a prefix
			instr.decode_pfx(str, idx)
		end
	end
end

end # module
