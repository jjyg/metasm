#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm
class OpenRisc < CPU
	class Reg
		attr_accessor :v
		def initialize(v)
			@v = v
		end

		def symbolic(di=nil)
			if @v != 0 or not di or di.instruction.args[0].object_id == self.object_id
				"r#@v".to_sym
			else
				# r0 is always 0, but we still return :r0 when writing to it (ie its the 1st instr arg)
				Expression[0]
			end
		end
	end

	class FpReg
		attr_accessor :v
		def initialize(v)
			@v = v
		end

		def symbolic(di=nil) ; "f#@v".to_sym ; end
	end

	class Memref
		attr_accessor :base, :offset, :msz

		def initialize(base, offset, msz)
			@base = base
			@offset = offset
			@msz = msz
		end

		def symbolic(di)
			p = Expression[@base.symbolic] if base
			p = Expression[p, :+, @offset] if offset
			Indirection[p.reduce, @msz, (di.address if di)]
		end
	end

	def initialize(family = :latest, endianness = :big, delay_slot = 1)
		super()
		@endianness = endianness
		@size = 32
		@family = family
		@delay_slot = delay_slot
	end

	def init_opcode_list
		send("init_#@family")
		@opcode_list
	end

	def delay_slot(di=nil)
		@delay_slot
	end
end
end

