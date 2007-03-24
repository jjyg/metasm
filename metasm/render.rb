require 'metasm/main'

module Metasm

module Renderable
	def to_s
		render.join
	end
end


class Instruction
	include Renderable
	def render
		@cpu.render_instruction(self)
	end
end

class CPU
	def render_instruction(i)
		r = []
		r << @opname
		if not @args.empty?
			r << ' '
			@args.each { |a|
				r << a << ', '
			}
			r.pop
		end
		r
	end
end

class Expression
	include Renderable
	def render
		if @op == :+ and not @lexpr
			[@rexpr]
		else
			['(', @lexpr, @op, @rexpr, ')']
		end
	end
end

class Indirection
	include Renderable
	def render
		[@type.inspect, ' ptr [', @target, ']']
	end
end
end
