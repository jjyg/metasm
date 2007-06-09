require 'metasm'
require 'metasm-shell'

# padding
edata = <<EOS.encode_edata
inc ebx
jmp toto

pre_pad:
.pad
post_pad:

toto:
.offset 42	; we are now at 42 bytes from the beginning of the shellcode (inc eax)
mov eax, [ebx+(12<<1)]

.padto 50, 0x90	; fill space till byte 50 with the specified byte (same as .pad + .offset)

inc eax

.align 16, dw foobar + 42	; align/pad/padto accepts arbitrary data specification to fill with

ret
EOS

edata.fixup 'foobar' => 1	# fixup the value of 'foobar'
edata.patch 'pre_pad', 'post_pad', 'somestring'		# replace the section beetween the label with the string, pads with 0
#edata.patch 'pre_pad', 'post_pad', 'somestring, but this one is tooooooooooooooooooooooooooooooo big :('	# raise an error

p edata.data # show the resulting raw string
