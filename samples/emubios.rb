#!/usr/bin/ruby

# Sample to show the EmuDebugger working on X86 16bit realmode code (eg hard disk MBR)

require 'metasm'
include Metasm

# use global vars for read_sector()
$dasm = $dbg = nil

$rawname = ARGV.shift || 'mbr.bin'
cpu = Ia32.new(16)
# add register tracking for the segment registers
cpu.dbg_register_list << :cs << :ds << :es << :fs << :gs << :ss
$dasm = dasm = Shellcode.new(Ia32.new(16), 0).disassembler
dasm.backtrace_maxblocks_data = -1

# initial memory
dasm.add_section(EncodedData.new("\x00"*0x40000), 0)

# read one sector from the drive to memory, invalidate already disassembled instruction from the address range
def read_sector(addr, fileoff, len)
	e, o = $dasm.get_section_at(addr)
	$dasm.decoded.keys.grep(addr..(addr+len)).each { |k| $dasm.decoded.delete k }
	raw_chunk = File.open($rawname, 'rb') { |fd| fd.pos = fileoff ; fd.read len } || ''
	raw_chunk << 0.chr until raw_chunk.length >= len
	e[e.ptr, len] = raw_chunk
	$dbg.invalidate if $dbg
end

# load as BIOS MBR code
read_sector(0x7c00, 0, 0x200)

# buffer used for int 16h read keyboard
$stdin_buf = "moo\r\n"

$dbg = dbg = Metasm::EmuDebugger.new(dasm)
dbg.set_reg_value(:eip, 0x7c00)
dbg.set_reg_value(:esp, 0x7c00)

# reset trace file
File.open('emudbg.trace', 'w') {}
def trace(thing)
	File.open('emudbg.trace', 'a') { |fd| fd.puts thing }
end
def puts_trace(str)
	trace str
	puts str
end

# custom emulation of various instrs for realmode-specific behavior
# this is a very bad realmode emulator
# eg segment selectors are mostly ignored except for a few specific cases described here
# seems to work for the few crackme i worked on !
dbg.callback_emulate_di = lambda { |di|
	puts di if $VERBOSE
	trace di
	case di.opcode.name
	when 'jmp'
		tg = di.instruction.args.first
		if di.address == dbg.resolve(tg)
			# break from simulation on ebfe
			puts "EB FE !"
			dbg.bpx(di.address)
			break true
		elsif tg.kind_of?(Ia32::Farptr)
			# handle far jumps
			dbg.pc = dbg.resolve(Expression[[tg.seg, :<<, 4], :+, tg.addr])
			break true
		end
	when 'retf.i16'
		# XXX really ss:esp, but we'd need to fix push/pop etc too, so keep to 0:esp for now
		w1 = dbg.memory_read_int(:esp, 2)
		dbg.set_reg_value(:esp, dbg.resolve(Expression[:esp, :+, 2]))
		w2 = dbg.memory_read_int(:esp, 2)
		dbg.set_reg_value(:esp, dbg.resolve(Expression[:esp, :+, 2]))
		dbg.set_reg_value(:cs, w2)
		dbg.pc = dbg.resolve(Expression[[w2, :<<, 4], :+, w1])
		break true
	when 'ret'
		w1 = dbg.memory_read_int(:esp, 2)
		dbg.set_reg_value(:esp, dbg.resolve(Expression[:esp, :+, 2]))
		dbg.pc = dbg.resolve(Expression[[:cs, :<<, 4], :+, w1])
		break true
	when 'lodsb'
		# read from ds:si instead of 0:esi
		# XXX rep
		dbg.set_reg_value(:eax, dbg.resolve(Expression[[:eax, :&, 0xffffff00], :|, Indirection[[[:ds, :<<, 4], :+, [:esi, :&, 0xffff]], 1]]))
		dbg.set_reg_value(:esi, dbg.resolve(Expression[[:esi, :&, 0xffff0000], :|, [[:esi, :&, 0xffff], :+, 1]]))
		dbg.pc += di.bin_length
		true
	when 'lodsd'
		# read from ds:si instead of 0:esi
		# XXX rep
		dbg.set_reg_value(:eax, dbg.resolve(Expression[Indirection[[[:ds, :<<, 4], :+, [:esi, :&, 0xffff]], 4]]))
		dbg.set_reg_value(:esi, dbg.resolve(Expression[[:esi, :&, 0xffff0000], :|, [[:esi, :&, 0xffff], :+, 4]]))
		dbg.pc += di.bin_length
		true
	when 'stosd'
		# write to es:di instead of 0:edi
		# XXX rep
		dbg.memory_write_int(Expression[[:es, :<<, 4], :+, [:edi, :&, 0xffff]], :eax, 4)
		dbg.set_reg_value(:edi, dbg.resolve(Expression[[:edi, :&, 0xffff0000], :|, [[:edi, :&, 0xffff], :+, 4]]))
		dbg.pc += di.bin_length
		true
	when /movs([bwdq])/
		sz = { 'b' => 1, 'w' => 2, 'd' => 4, 'q' => 8 }[$1]
		# XXX repz
		if di.instruction.prefix[:rep]
			count = dbg[:ecx] & 0xffff
		else
			count = 1
		end
		count.times {
			val = dbg.resolve(Expression[Indirection[[[:ds, :<<, 4], :+, [:esi, :&, 0xffff]], sz]])
			dbg.memory_write_int(Expression[[:es, :<<, 4], :+, [:edi, :&, 0xffff]], val, sz)
			dbg[:esi] = (dbg[:esi] + sz) & 0xffff
			dbg[:edi] = (dbg[:edi] + sz) & 0xffff
			dbg[:ecx] -= 1 if di.instruction.prefix[:rep]
		}
		dbg.pc += di.bin_length
		true
	when 'les'
		dst = di.instruction.args[0].symbolic(di)
		dst = dst.externals.first if dst.kind_of?(Expression)
		src = di.instruction.args[1].symbolic(di)
		dbg.set_reg_value(dst, dbg.resolve(Indirection[[[:es, :<<, 4], :+, src.pointer], 2]))
		dbg.pc += di.bin_length
		true
	when 'div'
		op = di.instruction.args[0].symbolic(di)
		sz = op.kind_of?(Expression) ? { 0xff => 1, 0xffff => 2 }[op.rexpr] : 4
		dv = dbg.resolve(op)
		case sz
		when 1
			dv2 = dbg[:eax] & 0xffff
			dbg[:eax] = ((dv2 / dv) & 0xff) | (((dv2 % dv) & 0xff) << 8)
		when 2
			dv2 = ((dbg[:edx] & 0xffff) << 16) | (dbg[:eax] & 0xffff)
			dbg[:eax] = (dv2 / dv) & 0xffff
			dbg[:edx] = (dv2 % dv) & 0xffff
		when 4
			dv2 = (dbg[:edx] << 32) | dbg[:eax]
			dbg[:eax] = (dv2 / dv)
			dbg[:edx] = (dv2 % dv)
		end
		dbg.pc += di.bin_length
		true
	when 'loop'
		# movzx ecx, cx
		dbg.set_reg_value(:ecx, dbg.resolve(Expression[:ecx, :&, 0xffff]))
		false
	when 'int'
		intnr = di.instruction.args.first.reduce
		eax = dbg[:eax]
		ah = (eax >> 8) & 0xff
		al = eax & 0xff
		case intnr
		when 0x10
			# print screen interrupt
			$screenbuf ||= []
			$screenx ||= 0
			$screeny ||= 0
			case ah
			when 0x00
				$screenbuf = []
				$screenx = 0
				$screeny = 0
			when 0x02
				dh = (dbg[:edx] >> 8) & 0xff
				dl = dbg[:edx] & 0xff
				puts_trace "movc(#{dh}, #{dl})"
				puts $screenbuf
				$screenx = dl
				$screeny = dh
			when 0x0e
				puts_trace "putc(#{[al].pack('C*').inspect})"
				$screenbuf << '' until $screenbuf.length > $screeny
				$screenbuf[$screeny] << '.' until $screenbuf[$screeny].length > $screenx
				$screenbuf[$screeny][$screenx, 1] = [al].pack('C*')
				$screenx += 1
			else
				puts_trace "unk int #{'%02xh' % intnr} #{'%02x' % ah}"
			end
		when 0x13
			# read disk interrupt
			drive_nr = dbg[:edx] & 0xff
			case ah
			when 0x00
				dbg.unset_flag(:c)
				puts_trace "reset_disk_drive #{'%x' % drive_nr}"
			when 0x02
				sect_cnt = al
				sect_c = ((dbg[:ecx] >> 8) & 0xff) | ((dbg[:ecx] << 2) & 0x300)
				sect_h = (dbg[:edx] >> 8) & 0xff
				sect_s = (dbg[:ecx] & 0x3f)
				sect_lba = (sect_c * 16 + sect_h) * 63 + sect_s - 1
				sect_drv = dbg[:edx] & 0xff
				dst_addr = dbg[:es] * 16 + dbg[:ebx]
				puts_trace "read #{sect_cnt} sect at #{'%03X:%02X:%02X' % [sect_c, sect_h, sect_s]} (#{'0x%X' % sect_lba}) to #{'0x%X' % dst_addr} drv #{'%x' % drive_nr}"
				read_sector(dst_addr, sect_lba * 512, sect_cnt * 512)
			when 0x08
				dbg.unset_flag(:c)
				dbg[:eax] = 0		# ah = return code
				dbg[:ebx] = 0		# bl = drive type
				dbg[:ecx] = 0x1010	# ch = cyl_max, cl >> 6 = cyl_max_hi, cl & 3f = sector_per_track
				dbg[:edx] = 0x1001	# dh = head_max, dl = nr_of_drives
				puts_trace "read_drive_parameters #{'%x' % drive_nr}"
			when 0x41
				dbg.unset_flag(:c)
				dbg[:ebx] = 0xaa55
				dbg[:ecx] = 1		# 1: device access through packet structure (cf 42), 2: lock & eject, 4: enhanced drive support
				puts_trace "drive_check_extension_present #{'%x' % drive_nr}"
			when 0x42
				sect_cnt = dbg.memory_read_int(Expression[[:ds, :<<, 4], :+, [[:esi, :+, 2], :&, 0xffff]], 2)
				dst_addr = dbg.memory_read_int(Expression[[:ds, :<<, 4], :+, [[:esi, :+, 4], :&, 0xffff]], 2)
				dst_seg  = dbg.memory_read_int(Expression[[:ds, :<<, 4], :+, [[:esi, :+, 6], :&, 0xffff]], 2)
				sect_lba = dbg.memory_read_int(Expression[[:ds, :<<, 4], :+, [[:esi, :+, 8], :&, 0xffff]], 8)
				dst_addr += dst_seg << 4
				puts_trace "read extended #{sect_cnt} sect at #{'0x%X' % sect_lba} to #{'0x%X' % dst_addr} drv #{'%x' % drive_nr}"
				read_sector(dst_addr, sect_lba * 512, sect_cnt * 512)
			else
				puts_trace "unk int #{'%02xh' % intnr} #{'%02x' % ah}"
			end
		when 0x16
			# read keyboard interrupt
			case ah
			when 0x00
				al = $stdin_buf.unpack('C').first || 0
				$stdin_buf[0, 1] = ''
				dbg[:eax] = al
				puts_trace "getc => #{[al].pack('C*').inspect}"
			else
				puts_trace "unk int #{'%02xh' % intnr} #{'%02x' % ah}"
			end
		else
			puts_trace "unk int #{'%02xh' % intnr} #{'%02x' % ah}"
		end
		dbg.pc += di.bin_length
		true
	end
}

# Start the GUI
Gui::DbgWindow.new.display(dbg)
# some pretty settings for the initial view
dbg.gui.run_command('wd 16')
dbg.gui.run_command('wp 6')
dbg.gui.parent.code.toggle_view(:graph)

Gui.main
