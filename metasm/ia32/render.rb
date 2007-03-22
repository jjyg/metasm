require 'metasm/ia32/opcodes'
require 'metasm/render'

# XXX move context in another file ?
module Metasm
class Ia32
	class Argument
		include Renderable

		@simple_list.each { |c| c.class_eval {
			def render ; [self.class.i_to_s[@val]] end
		} }
		@double_list.each { |c| c.class_eval {
			def render ; [self.class.i_to_s[@sz][@val]] end
			def context ; {'set sz' => proc { |s| @sz = s }} end
		} }
	end

	class Farptr
		def render
			[@seg, ':', @addr]
		end
	end

	class ModRM
		def qualifier(sz)
			{
			 8 => 'byte',
			16 => 'word',
			32 => 'dword',
			64 => 'qword'
			}.fetch(sz) { |k| "_#{sz}bits" }
		end

		def render
			r = []
			# is 'dword ptr' needed ?
#			if not instr or not instr.args.grep(Reg).find {|a| a.sz == @sz}
			r << ( qualifier(@sz) << ' ptr ' )
#			end
			r << @seg << ':' if @seg

			e = nil
			e = Expression[e, :+, (@s == 1 ? @i : [@s, :*, @i])] if @s
			e = Expression[e, :+, @b] if @b
			e = Expression[e, :+, @imm] if @imm
			r << '[' << e << ']'
		end

		def context
			return @direct.context if @direct

			{'set targetsz' => proc {|s| @sz = s},
			 'set seg' => proc {|s| @seg = Seg.new s}
			}
		end
	end

	# XXX this class do not exist, Metasm::Instruction is used
	# use some cpu-forwarding for render/ctx
	class Instruction
		def render
			pfx = ''
			pfx << 'lock ' if @pfx[:lock]
			pfx << "#{@pfx[:rep]} " if @pfx[:rep]
			
			{:pre => pfx << @opname << ' ', :content => @args, :join => ', '}
		end

		def context
			h = {}
			if @pfx[:rep]
				h['toogle repz'] = proc {@pfx[:rep] = {:repnz => :repz, :repz => :repnz}[@pfx[:rep]] } if @op.props[:stropz]
				h['rm rep']      = proc {@pfx.delete :rep}
			else
				h['set rep']     = proc {@pfx[:rep] = :z} if @op.props[:strop] or @op.props[:stropz]
			end
			if @pfx[:seg]
				h['rm seg'] = proc {@pfx.delete :seg}
			end

			h['toggle lock'] = proc {@pfx[:lock] = !@pfx[:lock]}
			h
		end
	end
end
end
