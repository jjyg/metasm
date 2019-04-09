#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/main'

module Metasm
class Dwarf < CPU
	def initialize(*args)
		super()
		@size = args.grep(Integer).first || 64
		@endianness = args.delete(:little) || args.delete(:big) || :little
	end

	class Reg
		attr_accessor :i

		def initialize(i)
			@i = i
		end

		def symbolic(di=nil)
			"r#@i".to_sym
		end

		include Renderable
		def render
			["r#@i"]
		end
	end

	def init_opcode_list
		init
	end
end
end
