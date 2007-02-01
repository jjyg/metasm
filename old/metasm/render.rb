require 'metasm/main'

module Metasm

module Renderable
	def to_s
		res = ''
		r = render
		res << r[:pre].to_s
		res << r[:content].map { |c| c.to_s }.join(r[:join].to_s) if r[:content]
		res << r[:post].to_s
	end
end


class Instruction
	include Renderable
	def render
		{:pre => @opname + ' ',
		 :join => ', ',
		 :content => @args}
	end
end

class Expression
	include Renderable
	def render
		{:join => " #@op ",
		 :content => [@lexpr, @rexpr].compact
		}
	end
end
end
