#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm debugger plugin
# adds a 'trace_func' method to the debugger
# the methods sets a breakpoint at the beginning of a function, and logs the execution of the instruction blocks
# does not descend in subfunctions

# setup the initial breakpoint at func start
def trace_func(addr)
	counter = 0
	bp = bpx(addr) { |h|
		counter += 1
		id = [addr, counter]
		trace_func_newtrace(id)
		trace_func_block(id)
		continue if h[:pre_state] == 'continue'
	}
	bp.action.call({}) if addr == pc
end

# we hit the beginning of a block we want to trace
def trace_func_block(id)
	blockaddr = pc
	if b = trace_get_block(blockaddr)
		trace_func_add_block(id, blockaddr)
		if b.list.length == 1
			trace_func_blockend(id, blockaddr)
		else
			bpx(b.list.last.address, true) { |h|
				finished = trace_func_blockend(id, blockaddr)
				continue if h[:pre_state] == 'continue' and not finished
			}
		end
	else
		# invalid opcode ?
		trace_func_blockend(id, blockaddr)
	end
end

# we are at the end of a traced block, find whats next
def trace_func_blockend(id, blockaddr)
	if di = disassembler.di_at(pc)
		if @cpu.dbg_end_stepout(self, di.address, di)
			# function ends there
			trace_func_finish(id)
			return true
		elsif di.opcode.props[:saveip]
			# call to a subfunction
			bpx(di.next_addr, true) { |h|
				trace_func_block(id)
				continue if h[:pre_state] == 'continue'
			}
		else
			singlestep	# XXX would need a callback on singlestep completion (to avoid multithread/exception)
			wait_target
			di.block.add_to_normal pc
			trace_func_block(id)
			if ndi = disassembler.di_at(pc)
				ndi.block.add_from_normal di.address
			end
		end
	else
		# XXX should link in the dasm somehow
		singlestep
		wait_target
		trace_func_block(id)
	end
	false
end

def trace_get_block(addr)
	disassembler.disassemble_fast(addr)
	if di = disassembler.di_at(addr)
		di.block
	end
end

################################################################################################
# you can redefine the following functions in another plugin to handle trace events differently

def trace_func_newtrace(id)
	@trace_func_counter ||= {}
	@trace_func_counter[id] = 0

	puts "start tracing #{Expression[id[0]]}"

	# setup a bg_color_callback on the disassembler
	if not defined? @trace_func_dasmcolor
		@trace_func_dasmcolor = true
		return if not disassembler.gui
		oldcb = disassembler.gui.bg_color_callback
		disassembler.gui.bg_color_callback = lambda { |addr|
			if oldcb and c = oldcb[addr]
				c
			elsif di = disassembler.di_at(addr) and di.block.list.first.comment.to_s =~ /functrace/
				'ff0'
			end
		}
	end
end

def trace_func_add_block(id, blockaddr)
	@trace_func_counter[id] += 1
	if di = disassembler.di_at(blockaddr)
		di.add_comment "functrace #{@trace_func_counter[id]}"
	end
end

def trace_func_finish(id)
	puts "finished tracing #{Expression[id[0]]}"
end

if gui
	gui.new_command('trace_func', 'trace execution inside a target function') { |arg| trace_func arg }
	gui.new_command('trace_now', 'trace til the end of the current function') { trace_func pc ; gui.wrap_run { continue } }
end
