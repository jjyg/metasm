require 'metasm/main'

module Metasm

module Renderable
	def to_s
		render.join ' '
	end
end


class Instruction
	include Renderable
	def render
		[@prefix.inspect] + [@opname] + @args
	end
end

class Expression
	include Renderable
	def render
		['(', @lexpr, @op, @rexpr, ')']
	end
end
end
