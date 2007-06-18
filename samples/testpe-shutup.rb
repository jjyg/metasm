require 'metasm'

include Metasm

pe = PE.assemble Ia32.new, <<EOS
.section '.text' r w x

.import 'kernel32' 'GetCurrentProcess'
.import 'advapi32' 'OpenProcessToken'
.import 'advapi32' 'LookupPrivilegeValueA'
.import 'advapi32' 'AdjustTokenPrivileges'
.import 'user32'   'ExitWindowsEx'

.entrypoint

; OpenProcessToken(GetCurrentProcess, ADJUST_PRIV | QUERY, &htok)
push htok
push 28h
call [GetCurrentProcess]
push eax
call [OpenProcessToken]

; LookupPrivVal(0, SE_SHUTDOWN, &tokpriv.priv[0].luid)
push tokpriv_luid
push privname
push 0
call [LookupPrivilegeValueA]

; tokpriv.privcnt = 1 ; tokpriv.priv[0].attr = ENABLED
mov dword ptr [tokpriv], 1
mov dword ptr [tokpriv_attr], 2

; AdjustTokenPrivileges(htok, 0, &tokpriv, 0, 0, 0)
xor eax, eax
push eax
push eax
push eax
push tokpriv
push eax
push dword ptr [htok]
call [AdjustTokenPrivileges]

; ExitWindowsEx(SHUTDOWN | FORCE, OS | MINORUPDATE | PLANNED)
push 80020003h
push 5
call [ExitWindowsEx]

ret

.align 4
htok dd ?
tokpriv:
 tokpriv_count dd ?
 tokpriv_luid  dd ?, ?
 tokpriv_attr  dd ?
privname db "SeShutdownPrivilege\0"

EOS
pe.encode_file 'metasm-shutup.exe'
