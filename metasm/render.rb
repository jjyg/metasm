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
		l = @lexpr
		r = @rexpr
		l = '%xh' % l if l.kind_of? Integer
		r = '%xh' % r if r.kind_of? Integer
		if @op == :+ and not l
			[r]
		else
			['(', l, @op, r, ')']
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
