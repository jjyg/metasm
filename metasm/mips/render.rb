require 'metasm/mips/opcodes'
require 'metasm/render'

module Metasm
class MIPS
	class Reg
		include Renderable
		def render ; [self.class.i_to_s[@val]] end
	end
	class FpReg
		include Renderable
		def render ; [self.class.i_to_s[@val]] end
	end
	class Memref
		include Renderable
		def render ; [@offset, '(', @base, ')'] end
	end

	def render_instruction(i)
		r = []
		r << i.opname
		if not i.args.empty?
			r << ' '
			if (a = i.args.first).kind_of? Expression and a.op == :- and a.lexpr.kind_of? String and a.rexpr.kind_of? String and opcode_list_byname[i.opname].first.props[:setip] 
				# jmp foo is stored as jmp foo - bar ; bar:
				r << a.lexpr
			else
				i.args.each { |a|
					r << a << ', '
				}
				r.pop
			end
		end
		r
	end
end
end
