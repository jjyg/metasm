#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# this sample script fixes a bug in some GTK libs (eg debian) where at some point
# when you close a window an invalid memory dereference is done, which crashes the
# whole metasm GUI
# 
# bug backtrace:
# 0f79e6173h libgobject-2.0.so.0!g_type_check_instance+23
# 0f79e3e38h libgobject-2.0.so.0!g_signal_handlers_disconnect_matched+28
# 0f70004c3h libgtk-x11-2.0.so.0!gtk_accel_label_set_accel_closure+c3
# 0f70006d3h libgtk-x11-2.0.so.0!gtk_accel_label_set_accel_widget+b3
# ...
#

require 'metasm'

include Metasm

if not pr = OS.current.find_process(ARGV.first)
	abort "cant find target"
end

dbg = pr.debugger

dbg.continue
puts "monitoring.." if $VERBOSE
dbg.wait_target

while dbg.state == :stopped
	puts "target #{dbg.state} #{dbg.info}" if $VERBOSE
	eax = dbg.get_reg_value(:eax)
	if eax > 0 and eax < 4096 and di = dbg.di_at(dbg.pc) and di.to_s =~ /\[eax\]/
		bt = dbg.stacktrace(2)
		dbg.disassembler.disassemble_fast_deep(bt[1][0]-5)
		di = dbg.disassembler.decoded[dbg.pc]
		if from = dbg.disassembler.decoded[di.block.from_normal.first] and from.block.list[-2].to_s =~ /test eax, eax/
			puts "fix almost null deref #{di} (eax=#{eax})" if $VERBOSE
			dbg.set_reg_value(:eax, 0)
			dbg.set_reg_value(:eip, from.block.list[-2].address)
		end
	end
	dbg.continue
	puts "target running" if $VERBOSE
	dbg.wait_target
end

puts "target terminated" if $VERBOSE
