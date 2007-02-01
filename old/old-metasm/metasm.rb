module Metasm

# Describes an instruction of a processor
class Mnemonic
	# list of fields and mask (field => 0x3 means that field uses 2 bits)
	@@fields_mask       = {}
	# list of possible arguments not encoded within within the mnemonic (immediate8...)
	@@args_allowed      = {}
	# list of possible properties for the mnemonic (this instruction is only valid in 16bit  mode...)
	@@props_allowed     = {}
	# list of possible metaproperties for the mnemonic (to guide the emulator)
	@@metaprops_allowed = { :setip => true, :modip => true, :stopexec => true }

	# maintain a list of all the instruction per class (one class per processor)
	@@mnemonic_list = Hash.new
	def self.mnemonic_list
		@@mnemonic_list[self] ||= []
	end
	def self.add(*args, &block)
		mnemonic_list.push(new(*args, &block)).last
	end
	
	# +name+ is the name of the opcode ('and'...)
	# +bin+ is base byte sequence ([0x40, 0x22])
	attr_reader :name, :bin

	# +fields+ is a hash whose key = fieldname and value = [byte number, bit offset]
	attr_reader :fields, :args, :props, :metaprops

	# sanity check: ensures all +fields+ and +props+ are defined
	def verify
		{	@props => @@props_allowed,
			@metaprops => @@metaprops_allowed,
			@args => @@args_allowed,
			@fields => @@fields_mask
		}.each { |k, v|
			a = k.keys - v.keys
			if a.length > 0
				raise SyntaxError, "invalid vars #{a.inspect} in #@name"
			end
		}
		true
	end
end

class Instruction
	# +mn+ is this instructions's Mnemonic
	# +name+ is its name (may be different of mn's, ie 'movsd')
	# +args+ is the array of its decoded arguments
	# +length+ is the binary length of the instruction (including prefix and args)
	attr_accessor :mn, :name, :args, :length

	# XXX this should be put in the display (Line or something)
	attr_accessor :comment

	def initialize
		@args = []
		@length = 0
		@comment = nil
		@name = 'error'
	end

	def comment_to_s
		" ; #{@comment}"
	end
	
	def pfx_to_s
		''
	end
	
	# XXX booo
	def to_s
begin
		s = pfx_to_s + @name + @args.map{ |a| ' ' + a.to_s(self) }.join(',')
		@comment ? s.ljust(24) + comment_to_s : s
rescue Object
puts "PANIC : #$! : " + inspect
end
	end
end

class Argument
end

class Immediate < Argument
	@@endianness = :big
	@@defsz = 4
	
	attr_accessor :sz, :signed

	def initialize(val, sz = @@defsz, signed = false)
		@sz  = sz
		@signed = signed 
		@val = (signed and val < 0) ? -val : val
	end

	# allow 3  + im
	# XXX   im +  3 ...
	def coerce(n) ; to_i.coerce(n) end
	
	def to_i
		if @signed and (@val & (1 << (8*@sz - 1))) != 0 	# high bit set ?
			-((1 << (8*@sz)) - @val)
		else
			@val
		end
	end

	def to_s(sz = @sz)
		if to_i < 0
			"-%.#{2*sz}x" % -to_i
		else
			"%.#{2*sz}x" % to_i
		end
	end
end

class MnemonicList
	def initialize
		@list = []
		@bin_split = Array.new(256) { [] }
	end
	
#	def method_missing(m, *a, &b)
#		@list.send(m, *a, &b)
#	end
	
	def << e
		@list << e
		update_bin_split e
		self
	end

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
