require 'metasm/exe_format/main'
require 'metasm/exe_format/mz'
require 'metasm/exe_format/coff'

module Metasm
class PE < ExeFormat
	class Header
		attr_accessor :coff_offset
		def self.decode(pe)
			hdr = new
			pe.encoded.ptr = 0x3c
			hdr.coff_offset = Expression.decode_imm(pe.encoded, :u32, :little) + 4
			pe.encoded.ptr = hdr.coff_offset - 4
			raise 'Invalid PE signature' if pe.read(4) != "PE\0\0"
			hdr
		end
	end

	def self.decode(str)
		pe = new
		pe.encoded = pe.coff.encoded = pe.mz.encoded = EncodedData.new << str
		pe.decode_header
		pe.coff.encoded.ptr = pe.header.coff_offset
		pe.coff.decode_header
		pe
	end


	attr_accessor :encoded
	attr_reader :mz, :coff
	attr_reader :header
	def initialize
		@coff = Coff.new
		@mz = Mz.new
	end

	def decode_header
		@header = Header.decode self
	end

	def encode_mz_header
		mzstubp = Program.new(Ia32.new(386))
		mzstubp.parse <<EOMZSTUB
.mode 16
.text
_str	db "Win32 needed\r\n$"
start:
	push cs
	pop  ds
	xor  dx, dx	  ; ds:dx = addr of $-terminated string
	// mov  dx, _str
	mov  ah, 9
	int  21h
	mov  ax, 4c01h    ; exit code in al
	int  21h
EOMZSTUB

		mzstubp.encode
		mzhdr = EncodedData.new
		mzparts = MZ.pre_encode mzstubp
		mzhdr << mzparts.shift 
		until mzparts.empty?
			break if mzparts.first.virtsize + pehdr.virtsize > 0x3c
			mzhdr << mzparts.shift
		end
		mzhdr.fill 0x40
		until mzparts.empty?
			mzhdr << mzparts.shift
		end
		start = mzstubp.label_at mzhdr, 0
		mzhdr.fixup mzhdr.export.inject({}) { |binding, (name, offset)| binding.update name => Expression[start, :+, offset] }
		mzhdr.align_size 8
		mzhdr.data[0x3c, 4] = Expression.encode_immediate(mzhdr.virtsize, :u32, :little)
		MZ.encode_fix_checksum mzhdr.data
	end
end
end


		
class << self
	def encode(program, opts={})
		pehdr = EncodedData.new
		if opts['pre_header']
			pehdr << opts.delete('pre_header')
		else

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
	end

	def pre_decode_header(str)
	end
end
end
end
