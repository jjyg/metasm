#!/usr/bin/ruby

# Demo of using the EmuDebugger to work on the SSTIC2017 challenge (EBPF program)

require 'metasm'
include Metasm
require 'zlib'

bpf_prog = "eNrlWk9sVEUYn7f7nq8lxS5QpDZEinSxIUEKASnEhNYGQYS0WGsBY8LBUA4YKq"  <<
"Dl8UICQRLkQFbBSLiUFpH2BJ7KbTi2F7NHDx4w8cCRI6mQdWa+b/6+t/voAhdtsp2dN/PNfN/8" <<
"vvl+38xb+gYRfzMhlJ3s08Q+Q6TskwZCutj3FaL+u78E2wvsQxugP29/ndcbtXyH6D/rbwsIaf" <<
"UIeVKpVAj+NbdCOcL651g5zMr3WbnqOjyPbzwSfUP2nKs24+HztifieStTIk/0H52EMszBPBfZ" <<
"d0/MD4KBmIWQCMcZ8j637B1hdrSzcgzLoYbf/ALqJ55jOVDC+dDuaFrrucJoH2btFTHOlL+X1w" <<
"nWya/+kCFHf0C9mV5vCfsewnNch5CN08afX54Vz3vO4TosKif6vW21/yHaowkYr6dg68315RDs" <<
"Ltn2RxMg14/4cNzO9h7Zx7+f6Pty5xetV3wYF+Yf8XB9sBzyLvv7h7/9QNhb4fZe8uN9sM586e" <<
"MzgJ/G83Emno8ZnvQW1vOA74wPdY5zTugza9l5R8xfqYwQ1A/LeBHMH595WfM+XNC83O7cS7S7" <<
"NYT5pHxADvm1/fozvyhwGvK9Gv6t/XWn/zHX62d4vgtxHBhFfXEe0w+5XgPnkv6WTx1/mx9b+2" <<
"Wrf5DXQ6yHW/ydfJ3v4D5jz7cb8+txuvyzuL5eHXFiBvXUfgn7YLkTN+RzU582C9eFzbsc41OE" <<
"88eXYV+p+FB1f99PtK+z2h8k2jdZ7ei3ozZOEmdu11qjPV50r+K2v2u130y0v2e1z6o4yeNcj4" <<
"yj32OJ6zvsAZ7SL/uRT+iPUI6x9eOq0rzeF2W2nsN5kCvmc6QR4yl/HggWs/tTp3+A/edE/9dU" <<
"PJ5mde7e47w/+tkMk+M91uc9y1/oVdQvj7zYgfb4IEeLOH+A+gY4f5AX+o6wfnzjhvzfM67HYh" <<
"jXkKOOXODIlZ5q/WcC7W9C/xzK5VLk5lmc2Yk4HUK/u4b2+MATdAvag/PTTXr8sjO+sCcAnLje" <<
"vIOyx5CjaXqZcnOGPTmN37iFX4ocA45+ksSF+5O0U9nRg+MStANxjteVxDoUibanSY7PAFL2GP" <<
"LUkOdygSvHAErY46M96CdFP01uXtuD+5nHc55j0c2On21J97O47Trw3rpLYJfhdwXpd0xC6meO" <<
"Y/vdCuU/Wm6uItchmrTjxFgIuSG9gHoibvQ7bX/ZsD+agLjG10Hox/q3IO584QMCiaopT631aw" <<
"L9LLnS04A0w7qTdD+SehfzjypJ+6aVfQH5G3jc13FVjIP8VWzIp80/L3FS+RIzrpvbcTI9jsV7" <<
"plAfXIcQ9mEIfFsORLZty9O0fWHLzQUEvkj9TfnxbPlpegr696+291dSf7meEI95PF8p1q8pIW" <<
"fr7Yl5AxJYcczsn6onjh8CX5ToTyjnxuFWvX8Ej6ypov+h+5b+0k+V/msy+MR3+MRHPnHiseKT" <<
"NZ6Nywq9fwoGT/JzUsXYT0n+y6v19uV6mHxyIcNfDDmLT3IZ/m7KcT5BvjbXW/BI5NhxMtuOBm" <<
"mHySMns+1QciaP5HV+IuzAPLMYpshxHkG/i7ePVlxc2uvEpUn56bMF4aLkTB7JZ+Oi5eYNe45W" <<
"XHw668SnoOwpLwgfLTe3IHy03LRhz+EEPl114tOi48izheCj5TjfPD8+hty8tucAnAOmII9X5z" <<
"ivNm+8Mr5orJMv0J+iO3A+6D+N4yyrnb9zngS+KCT6p+qN/UMIo6WAgMJ0uX2uo4PZeeRKlecx" <<
"Htkvz30D4F9f2+cU6Rc8vxR88o3237Lhv/Gec5h/nYbyBuBaDKucV4b1ONTaBxnnlQDtwnyN3w" <<
"MIfhl2zisXiZVHjWG+Q7c5+6Vb+2/Z8N+4DfDkflyTbwx5msUbJt80ZPO9xTeYF9ODaA/eb9E+" <<
"J+/clY4Pjy8y32yQeZvJN7uq4aHzPSWXdm6pluebcpxv8Hwk8Vc8c9Wx41p6/mzmzU0q/zR45l" <<
"q1vFnro+RMnvH0PY6wA/2j2Jgmx3hmYxKPTiN+KDtOZdtRUHYY/HIq2w4tZ/CLn8EvlhzjF8zb" <<
"4z3dFReXrjpxsc8zz4+LfZ5x7KmBS9o5JN7TBfxyC+6BRvB8HG+H+lhQm2eiX2Zf7fnkBfkmbu" <<
"ux7Ovvk7yK9+uDVfL+G51ol6/O/SsN3KMJOEcr+wbT7ZP9EueZsE4ewvnjM+1oF9zTNC+TduG9" <<
"DcYp6dfRNOKJeS3t1e8bhN2evO/YDfp6YLeMjxTPX9HNS2g3nKPNcagxjuxf9MAOPg7nKS0fqv" <<
"0n+MqJizzOvGbMt77Xs9Ytmizhew20f7XE+5H1voPnSQXj3lCet6qdV5Uf55BXcg6PXc3wY0PO" <<
"4rF8xv405TiPrZF4wv6KJtFO5JF4Hdp5E/04p+9FW408ScWjlmrxKEjlO8n/8v2OwrslPT5F02" <<
"V1X1OTBxu1v4wb/iL9JMGDSg+0H/Mwmc/J+2L53kmum7K7o05+7KiTH/2M+1aXH1UcRjwn4b6n" <<
"Ge97TVw7F4RrBm+2vCBv1sAvnTencF/CfVBzCn5ddeKXyqMdL8ijNfBL49Fo8r6FG3/fJ3hzac" <<
"b9uIe85Tl8uTTjftyW03yJccaUH8+Wn5Z+Jd/73nXwSfDEDbxHxvs9yafcDxqNfI+//1xp8qSX" <<
"zhdFD84zUk7dP2Nd5s+mfKr/4XxIEyWq4iXgw/fQWuN9oRzvHVZGx46P3n1T/x7BfB861HibfP" <<
"Tp4GA0cQ73KZzfmpfKdRt16ked+mGnfsCpP3DqA04d4uvdpfoce+TE8a92oP6S/5Lv4a+Q3X3t" <<
"fdEEnNPk7y2iid1Ovcepdzv1Lqfe6dTbnTr6UWv6+2d6Hp5vWIK/L2A4rb/94WX1nhT9cQfGgw" <<
"1Yrtpoy2X1k+fyRHv3wsb5z/Q7/3z9hrxdpHfv3naZ3zefsvPe5haHl1V9yqnfc+oPnfp9p45+" <<
"jnX+/qUd7yXajXzT9Ju/Lh3786X7TV+V9s3/U7/pfb5+y73FZFPXxq0yT5e/83lZv7Oh+DsCfK" <<
"2T+L2FvJ8IyLV/ePkvDyQvEw=="

raw = Zlib::Inflate.inflate(bpf_prog.unpack('m*').first)
dasm = Shellcode.decode(raw, EBPF.new(:latest, :little)).disassembler
dasm.backtrace_maxblocks_data = -1

dasm.callback_newinstr = lambda { |di|
	if di.opcode.name == 'call'
		case di.instruction.args.first.reduce
		when 1; di.instruction.args[0] = ExpressionString.new(Expression[1], "bpf_map_lookup_elem")
		when 2; di.instruction.args[0] = ExpressionString.new(Expression[1], "bpf_map_update_elem")
		end
	end
	di
}
# EmuDebugger needs an already disassembled binary
dasm.disassemble(0)

#Gui::DasmWindow.new.display(dasm)

# EmuDebugger has no memory except what is described in the binary
# We must manually add sections to the disassembler to 'map' the stack and working heap
stack = EncodedData.new("\x00" * 0x1000)
dasm.add_section(stack, 0x8000)

# ebpf works on network packets
eth = "\x11\x11\x11\x11\x11\x11\x22\x22\x22\x22\x22\x22\x08\x00"
ip = "\x45\x00\x00\x2c\x00\x00\x11\x11\x22\x11\x33\x33\x44\x44\x44\x44\x55\x55\x55\x55"
udp = "\x00\x00\x05\x39\x22\x22\x33\x33"
pld = "LUM{BvWQEdCrMfA}"
# forge the needed network headers
ip[2, 2]  = [ip.length + udp.length + pld.length].pack('n')
udp[4, 2] = [udp.length + pld.length].pack('n')
pkt = EncodedData.new(eth + ip + udp + pld)
dasm.add_section(pkt, 0x9000)

# Initialize the emulator
dbg = Metasm::EmuDebugger.new(dasm)
# Set the initial state of the registers
dbg.set_reg_value(:r10, 0x8900)
# :packet is a special register used internally by some opcodes of the EBPF cpu (packet data store/load)
dbg.set_reg_value(:packet, 0x9000)

# This section emulates the kernel API for shared bpf maps
$bpf_map = { 0 => 0 }
dbg.callback_emulate_di = lambda { |di|
        case di.opcode.name
        when 'call'
                case di.instruction.args.to_s
                when /map_lookup/
                        key = dbg.resolve('dword ptr [r2]')
                        puts "bpf_map_lookup(#{dbg[:r1]}, #{key}) => #{$bpf_map[key].inspect}"
                        if $bpf_map[key]
                                dbg[:r0] = dbg[:r2]
                                dbg.memory_write_int(:r2, $bpf_map[key], 4)
                        else
                                dbg[:r0] = 0
                        end
                when /map_update/
                        key = dbg.resolve('dword ptr [r2]')
                        val = dbg.resolve('dword ptr [r3]')
                        puts "bpf_map_update(#{dbg[:r1]}, #{key}, #{val})"
                        $bpf_map[key] = val
                end
                dbg.pc += di.bin_length
                true
        end
}

# Start the GUI
Gui::DbgWindow.new.display(dbg)
# some pretty settings for the initial view
dbg.gui.run_command('wd 6')
dbg.gui.run_command('wp 6')
dbg.gui.run_command('d :packet')
dbg.gui.parent.code.toggle_view(:graph)

Gui.main
