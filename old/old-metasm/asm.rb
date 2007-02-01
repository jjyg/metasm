require 'metasm/metasm'

module Metasm

# Exception raised when an insctruction cannot be parsed/encoded
class InvalidInstruction < RuntimeError
	def initialize(str)
		@s = str
	end
	
	def message
		"Invalid instruction #{@s.inspect}"
	end
end

class Mnemonic
	def parse_match?(name, args, instr)
	end

	@@encode_order = []
	def parse(name, args, instr)
		@@encode_order.each { |f|
			next unless @fields[f] or @args[f] or @props[f]
			encode_field(instr, f)
		}
	end
end

class Instruction
	# returns the string with the prefixes stripped ?
	def parse_pfx(str)
		raise InvalidInstruction.new(str)
	end
end

class Immediate
	def encode(str, sz = @sz)
		v = @val
		# neg handled correctly ?
		# v = ((1 << (8*sz)) + v) if v < 0
		case @@endianness
		when :big
			sz.times { |i| str << (v & 255) ; v >>= 8 }
		when :little
			sz.times { |i| str << ((v >> 8*i) & 255) }
		else
			raise SyntaxError.new('Unsupported endianness')
		end
	end
end

class Assembler < Metasm
	def initialize(*args)
		super
		init_names_split
	end

	# creates a hash associating a fist letter to an array of possible Mnemonic
	def init_names_split
		@names_split = Hash.new { |h, k| h[k] = [] }
		@mnemonics.each { |m| @names_split[m.name[0]] << m }
	end

	# parses a line of text against known instructions
	# returns an @instr_class or raises InvalidInstruction
	# 
	# uses @names_split with 1st letter only to handle things like jnz/jbe..
	# may be used for GAS AT&T syntax as well
	def parse(str)
		instr = @instr_class.new
		strnopfx = instr.parse_pfx(str)
		name, args = parse_args(strnopfx)
		@names_split[name[0]].each { |m|
			next unless m.parse_match?(name, args, instr)

			m.parse(name, args, instr)
			return instr
		}
		raise InvalidInstruction, str
	end

	# name is the first space-delimited word
	# args is the list of coma-delimited words following it
	def parse_args(str)
		name, args = str.split(/\s+/, 1)
		args = args.split(/\s*,\s*/)
		return name, args
	end
end

end # module
