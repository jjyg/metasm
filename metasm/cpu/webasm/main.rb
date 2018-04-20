#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/main'

module Metasm

class WebAsm < CPU
	attr_accessor :wasm_file
	def initialize(*args)
		super()
		@size = args.grep(Integer).first || 64
		@wasm_file = args.grep(ExeFormat).first
		@endianness = args.delete(:little) || args.delete(:big) || (@wasm_file ? @wasm_file.endianness : :little)
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

	class BlockSignature
		attr_accessor :id

		def initialize(id)
			@id = id
		end

		def symbolic(di=nil)
			Expression[@id]
		end

		include Renderable
		def render
			[WasmFile::TYPE.fetch(@id, Expression[@id])]
		end
	end

	def init_opcode_list
		init
	end
end
end
