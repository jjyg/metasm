require 'metasm/main'

module Metasm

# a Renderable element has a method #render that returns an array of [String or Renderable]
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
	# renders an instruction
	# may use instruction-global properties to render an argument (eg specify pointer size if not implicit)
	def render_instruction(i)
		r = []
		r << @opname
		r << ' '
		@args.each { |a| r << a << ', ' }
		r.pop
		r
	end

	# ease debugging in irb
	def inspect
		"#<#{self.class}:#{'%x' % object_id} @size=#{@size.inspect} @endianness=#{@endianness.inspect} ... >"
	end
end

class Expression
	include Renderable
	def render
		l, r = [@lexpr, @rexpr].map { |e|
			if e.kind_of? Integer
				if e < 0
					neg = true
					e = -e
				end
				e = '%xh' % e
				e = '0' << e unless (?0..?9).include? e[0]
				e = '-' << e if neg
			end
			e
		}
		['(', l, @op, r, ')'].compact
	end
end

class Indirection
	include Renderable
	def render
		[@type.inspect, ' ptr [', @target, ']']
	end
end
end
