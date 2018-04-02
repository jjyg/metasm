#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/main'

module Metasm

class WebAsm < CPU
	def initialize(endianness = :little)
		super()
		@endianness = endianness
		@size = 32
	end

	class Memref
		attr_accessor :off

		def initialize(off)
			@off = Expression[off]
		end

		def symbolic(di=nil)
			sz = 32
			Indirection[@off, sz, (di.address if di)]
		end

		include Renderable

		def render
			['[', @off, ']']
		end

	end

	class BrTable
		attr_accessor :ary, :default
		def initialize(ary, default)
			@ary = ary
			@default = default
		end

		include Renderable
		def render
			out = ['[']
			@ary.each { |a| out << a << ', ' }
			out.pop if out.length > 1
			out << ']' << ' or ' << @default
		end
	end

	def init_opcode_list
		init
	end

	def dbg_register_list
		@dbg_register_list ||= []
	end
end
end
