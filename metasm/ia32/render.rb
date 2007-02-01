require 'metasm/ia32/opcodes'
require 'metasm/render'

# Rendering:
# each renderable element must answer to #render with a hash
# the hash's key are :pre (start of the string), :post (end of the string)
# :content (array of subelements, which will be rendered recursively) and :join
# those must be strings or nil.
# They should also answer to :context with a hash, whose keys are labels
# and values are procs called for this label. The proc's arity is checked to see if
# further user input is needed. The proc changes the current object.
# Protocol to change the current object need has to be created (Immediate => symbol/expression)
#

# XXX move context in another file ?
module Metasm
class Ia32
	class Argument
		include Renderable

		@simple_list.each { |c| c.class_eval {
			def render ; {:pre => self.class.i_to_s[@val]} end
		} }
		@double_list.each { |c| c.class_eval {
			def render ; {:pre => self.class.i_to_s[@sz][@val]} end
			def context ; {'set sz' => proc { |s| @sz = s }} end
		} }
	end

	class Farptr
		def render
			{:content => [@seg, @addr], :join => ':'}
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
			pre = ''
			# is 'dword ptr' needed ?
#			if not instr or not instr.args.grep(Reg).find {|a| a.sz == @sz}
				pre << qualifier(@sz) << ' ptr ' 
#			end
			if @seg
				# XXX do this cleanly ? (ie not call to_s in render)
				pre << @seg.to_s << ?:
			end
			pre << ?[
			# @i must come first in :content with this
			pre << "#@s*" if @s and @s != 1

			{:pre => pre, :post => ']', :join => ' + ',
			 :content => [@i, @b, @imm].compact}
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
