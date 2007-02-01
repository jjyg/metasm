require 'metasm/exe_format/main'
require 'metasm/exe_format/mz'
require 'metasm/exe_format/coff'

module Metasm
class PE < ExeFormat
class << self
	def encode(program, opts={})
		pehdr = EncodedData.new
		if opts['pre_header']
			pehdr << opts.delete('pre_header')
		else
			mzstubp = Program.new(Ia32.new(386))
			mzstubp.parse <<EOMZSTUB
.mode 16
.text
_str	db "Win32 needed\r\n$"
start:
	push cs
	pop  ds
	xor  dx, dx	  ; ds:dx = addr of $-terminated string
	# mov  dx, _str
	mov  ah, 9
	int  21h
	mov  ax, 4c01h    ; exit code in al
	int  21h
EOMZSTUB

			mzstubp.encode
			mzparts = MZ.pre_encode mzstubp
			pehdr << mzparts.shift 
			until mzparts.empty?
				break if mzparts.first.virtsize + pehdr.virtsize > 0x3c
				pehdr << mzparts.shift
			end
			pehdr.fill 0x40
			until mzparts.empty?
				pehdr << mzparts.shift
			end
			start = mzstubp.label_at pehdr, 0
			pehdr.fixup pehdr.export.inject({}) { |binding, (name, offset)| binding.update name => Expression[start, :+, offset] }
			pehdr.fill 0x40
			pehdr.align_size 8
			pehdr.data[0x3c, 4] = Expression.encode_immediate(pehdr.virtsize, :u32, program.cpu.endianness)

                	MZ.encode_fix_checksum pehdr.data

		end
		pehdr.fill 0x40
		pehdr.data[0x3c, 4] = Expression.encode_immediate(pehdr.virtsize, :u32, program.cpu.endianness)
		opts['pre_header'] = pehdr.data << "PE\0\0"

		csum = opts['checksum']
		data = COFF.encode(program, opts)
		fix_checksum data if not csum
		data
	end

	def fix_checksum(data)
		# little endian only, wont work with overlapping sections

		# check we have a valid PE
		return if data[0, 2] != 'MZ'
		off = data[0x3c, 4].unpack('V').first
		return if data[off, 4] != "PE\0\0"
		off += 4

		# read some header information
		csumoff = off + 0x14 + 0x40
		secoff  = off + 0x14 + data[off+0x10, 2].unpack('v').first
		secnum  = data[off+2, 2].unpack('v').first

		sum = 0
		flen = 0

		# header
		# patch csum at 0
		data[csumoff, 4] = [0].pack('V')
		curoff  = 0
		cursize = data[off+0x14+0x3c, 4].unpack('V').first
		data[curoff, cursize].unpack('v*').each { |s|
			sum += s
			sum = (sum & 0xffff) + (sum >> 16) if (sum >> 16) > 0
		}
		flen += cursize

		# sections
		secnum.times { |n|
			cursize, curoff = data[secoff + 0x28*n + 0x10, 8].unpack('VV')
			data[curoff, cursize].unpack('v*').each { |s|
				sum += s
				sum = (sum & 0xffff) + (sum >> 16) if (sum >> 16) > 0
			}
			flen += cursize
		}
		sum += flen

		# patch good value
		data[csumoff, 4] = [sum].pack('V')
	end

	def is_valid?(data)
		data[0, 2] == 'MZ' and data[data[0x3c, 4].unpack('V').first, 4] == "PE\0\0"
	end

	def decode(str, opts)
		p = Program.new
	end
end
end
