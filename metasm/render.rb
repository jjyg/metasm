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
	# renders an instruction
	# may use instruction-global properties to render an argument (size specification if not implicit)
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

	# ease debugging in irb
	def inspect
		"#<#{self.class}:#{'%x' % object_id} @size=#{@size.inspect} @endianness=#{@endianness.inspect} ... >"
	end
end

class Expression
	include Renderable
	def render
		l = @lexpr
		r = @rexpr
		if l.kind_of? Integer
			if l < 0
				nl = true
				l = -l
			end
			l = '%xh' % l
			l = '0' << l unless (?0..?9).include? l[0]
			l = '-' << l if nl
		end
		if r.kind_of? Integer
			if r < 0
				nr = true
				r = -r
			end
			r = '%xh' % r
			r = '0' << r unless (?0..?9).include? r[0]
			r = '-' << r if nr
		end
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
