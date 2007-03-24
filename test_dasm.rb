require 'metasm/ia32/parse'
require 'metasm/ia32/encode'
require 'metasm/ia32/decode'
require 'metasm/ia32/render'
require 'metasm/exe_format/raw'

class Metasm::CPU ; def inspect ; 'cpu' end end	# help debug

cpu = Metasm::Ia32.new
encpgm = Metasm::Program.new cpu
encpgm.parse DATA.read
encpgm.encode

sc = Metasm::Raw.encode encpgm, 'entrypoint' => (ARGV.first || 'proc1')

pgm = Metasm::Raw.decode cpu, sc

pgm.sections.first.encoded.export.update encpgm.sections.first.encoded.export
pgm.sections.first.encoded.export.delete_if { |k, v| k =~ /^metasmintern_/ }

pgm.desasm 0

puts '', '-'*20, ''

pgm.block.sort.each { |addr, block|
	s = pgm.sections.find { |s| s.base <= addr and s.base + s.encoded.virtsize > addr }
	if pgm.block[addr]
		puts "; Xrefs: " + pgm.block[addr].from.map { |f| '%08x' % f }.join(', ')
	end

	s.encoded.export.each { |e, off| puts "#{e}:" if off == addr - s.base and e !~ /^metasmintern/ }
	block.list.each { |di|
		print '%08X ' % addr
		print s.encoded.data[addr-s.base, di.bin_length].unpack('C*').map { |c| '%02x' % c }.join.ljust(16) + ' '
		print di.instruction
		puts

		addr += di.bin_length
	}
	puts
}

__END__
addr_0:
 call entrypoint
 jmp eof

; basic proc
proc1:
 push eax
 pop eax
 ret

; push foo ret style jump
proc2:
 push bla - addr_0
 ret
 nop
bla:
 ret
 
; subproc
proc3:
 call proc3_1
 ret

proc3_1:
 ret

; subproc with arguments and retn
proc4:
 push 42
 push 28
 call proc4_1
 ret

proc4_1:
 ret 8

; frame pointer
proc5:
 push ebp
 mov ebp, esp
 sub esp, 28
 add eax, 42
 mov esp, ebp
 pop ebp
 ret

; shared ret
proc6:
 call proc6_1
 call proc6_2
 ret

proc6_1:
 add eax, ebx
 jmp retloc
 nop

proc6_2:
 sub eax, ebx
 jmp retloc
 nop

retloc: ret

; ret as jmp [esp]
proc7:
 jmp [esp]

; retaddr mangling
proc8:
 add dword ptr [esp], 42
 ret

; call as push
proc9:
 call pushed_addr
dd hiddenlabel - addr_0
pushed_addr:
 pop eax
 mov eax, [eax]
 jmp eax

hiddenlabel:
 add eax, eax
 ret

; case-style
proc10:
 cmp eax, 42
 jnz case1
 mov ebx, proc10_1 - addr_0
 jmp esac
case1:
 cmp eax, 28
 jnz case2
 mov ebx, proc10_2 - addr_0
 jmp esac
case2:
 mov ebx, proc10_3 - addr_0
esac:
 call ebx
 ret

proc10_1:
 ret

proc10_2:
 ret

proc10_3:
 add eax, 42
 ret

; case with pointer table
proc11:
 cmp ebx, 4
 jae proc11_else
 mov eax, [ebx*4 + (jmp_table - addr_0)]
 jmp eax
 nop

align 4
jmp_table dd proc11_0 - addr_0, proc11_1 - addr_0, proc11_2 - addr_0, proc11_3 - addr_0
db 0
proc11_0:
 ret
proc11_1:
 ret
proc11_2:
 add ebx, 42
 ret
proc11_3:
 sub ebx, 21
 ret
proc11_else:
 nop
 ret

proc12:
 call proc12_ret
 call proc12_ret
 ret
proc12_ret:
 ret

eof:
 nop
