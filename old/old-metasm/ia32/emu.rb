require 'metasm/ia32'
require 'metasm/program'

module Metasm

class Immediate
	def eval
		val
	end
end

class Argument
	def eval
		nil
	end
end

class Ia32_Program < Program

	#
	# we know where we are, so we can deduce things from the condition of the block we come from
	# if it ends in jz/jg/..
	#
	
	# hard hat area
	#
	# 	push 420000h
	# 	call [esp]
	#
	# 	mov eax, esp
	# 	sub eax, 4
	# 	push 420000h
	# 	call [eax]
	#
	# 	anybody with a théorie de la relativité ?
	#
	
	# return all the possible values for arg in the instruction from block ending at voff
	def eval_backtrace(instr, arg, voff, block)
		e = arg.eval
		return [e] if e
		
		if arg.class == Ia32_ModRM
		end
		
		v = block.offset
		if v == voff
			# backtrace multiple from
			ret = []
			block.from.each { |b|
				ret.concat eval_backtrace(arg, b.offset + b.length, b)
			}
			return ret
		end
		
		i = nil
		block.instrs.each { |i|
			v += i.length
			break if v == voff
		}
		puts "trying to eval_backtrace #{arg.to_s instr} from #{i}"
		[]
	end

        # return true if end of block
        # voff points AFTER the current instruction
        def emule(instr, voff, block)
                p = instr.mn.metaprops
                if p[:setip] or p[:modip]
                        e = [instr.args[0].eval]
			if not e[0]
				# TODO mark this block as backtracing (if another codepath leads there, backtrace again)
				e = eval_backtrace(instr, instr.args[0], voff - instr.length, block)
			end
			
                        e.each { |off|
                                off += voff if p[:modip]
                                block.to << off
                                @voffsets << [off, voff-instr.length, block.offset]

				(instr.comment ||= '') << (' %8x' % off)
                        }
			
			# if instr.name == 'call' and @blocks[e].callee or not p[:stopexec]
                        if not p[:stopexec]
                                block.to << voff
                                @voffsets << [voff, voff-instr.length, block.offset]
                        end
                        true
			
                elsif p[:stopexec]
			# if e.name == 'ret'
			# 	e = eval_backtrace([esp])
			# 	if e == block.currentcall.retaddr
			# 		block.callee = (instr.args[0] or 0)	# stack lifting: similar to (value+1) * pop
			# 	end
			# end
                        true
                else
                        false
                end
	end
end

alias oldia32_opcode_list_386 ia32_opcode_list_386
def ia32_opcode_list_386(*args)
	oldia32_opcode_list_386(*args).each { |m| m.metaprops[:stopexec] = true if m.name == 'call' }
end

end
