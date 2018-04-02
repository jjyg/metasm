#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm
class BPF < CPU
	class Reg
		attr_accessor :v
		def initialize(v)
			@v = v
		end

		def symbolic(di=nil) ; @v ; end
	end

	class Memref
		attr_accessor :base, :offset, :msz

		def memtype
			:mem
		end

		def initialize(base, offset, msz)
			@base = base
			@offset = offset
			@msz = msz
		end

		def symbolic(di=nil)
			p = Expression[memtype]
			p = Expression[p, :+, @base.symbolic] if base
			p = Expression[p, :+, @offset] if offset
			Indirection[p, @msz, (di.address if di)]
		end
	end

	class Pktref < Memref
		def memtype
			:pkt
		end
	end

	def initialize(family = :latest)
		super()
		@endianness = :big
		@size = 32
		@family = family
	end

	def init_opcode_list
		send("init_#@family")
		@opcode_list
	end
end
end

