require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'

module Metasm
class MZ < ExeFormat
	class Header
		Fields = [:magic, :cblp, :cp, :crlc, :cparhdr, :minalloc, :maxalloc,
			:ss, :sp, :csum, :cs, :ip, :lfarlc, :ovno]
		attr_accessor(*Fields)

		def encode(mz, relocs)
			h = EncodedData.new
			set_default_values mz, h, relocs
			h << @magic
			Fields[1..-1].each { |m| h << Expression[send(m)].encode(:u16, mz.endianness) }
			h.align_size 16
			h
		end

		def set_default_values mz, h, relocs
			@magic    ||= 'MZ'
			@cblp     ||= Expression[[mz.label_at(mz.body, mz.body.virtsize), :-, mz.label_at(h, 0)], :%, 512]	# number of bytes used in last page
			@cp       ||= Expression[[[mz.label_at(mz.body, mz.body.virtsize), :-, mz.label_at(h, 0)], :+, 511], :/, 512]	# number of pages used
			@crlc     ||= relocs.virtsize/4
			@cparhdr  ||= Expression[[mz.label_at(relocs, 0), :-, mz.label_at(h, 0)], :/, 16]	# header size in paragraphs (16o)
			@minalloc ||= 0
			@maxalloc ||= 16
			@ss       ||= 0
			@sp       ||= 0		# ss:sp points at 1st byte of body => works if body does not reach end of segment (or maybe the overflow make the stack go to header space)
			@csum     ||= 0
			@cs       ||= 0
			@ip       ||= Expression[mz.body.export['start'] || 0]	# when empty relocs, cs:ip looks like an offset from end of header
			@lfarlc   ||= Expression[mz.label_at(relocs, 0), :-, mz.label_at(h, 0)]
			@ovno     ||= 0
		end

		def self.decode(mz)
			h = new
			h.magic = mz.encoded.read 2
			raise "Invalid MZ signature #{h.magic.inspect}" if h.magic != 'MZ'
			Fields[1..-1].each { |m| h.send("#{m}=", mz.encoded.decode_imm(:u16, mz.endianness)) }
			h
		end
	end

	class Relocation
		attr_accessor :segment, :offset
		def encode(mz)
			Expression[@offset].encode(:u16, mz.endianness) << Expression[@segment].encode(:u16, mz.endianness)
		end

		def self.decode(mz)
			r = new
			r.offset = mz.encoded.decode_imm(:u16, mz.endianness)
			r.segment = mz.encoded.decode_imm(:u16, mz.endianness)
			r
		end
	end


	attr_accessor :encoded
	attr_accessor :endianness, :header, :body, :relocs
	def initialize
		@endianness = :little
		@relocs = []
	end
	
	def self.from_program(program)
		mz = new
		mz.endianness = program.cpu.endianness
		mz.body = program.sections.inject(EncodedData.new) { |edata, s| edata << s.encoded }
		mz.header = Header.new
		# TODO mz.relocs
		mz
	end

	def pre_encode
		relocs = @relocs.inject(EncodedData.new) { |edata, r| edata << r.encode(self) }
		header = @header.encode self, relocs
		[header, relocs, @body]
	end

	def encode
		@encoded = pre_encode.inject(EncodedData.new) { |edata, pe| edata << pe }
		start = label_at @encoded, 0
		@encoded.fixup @encoded.export.inject({}) { |binding, (name, offset)| binding.update name => Expression[start, :+, offset] }
		raise EncodeError, "MZ encode: pending relocations #{@encoded.reloc.inspect}" if not @encoded.reloc.empty?
		encode_fix_checksum
		@encoded.data
	end

	def encode_fix_checksum
		@encoded.ptr = 0
		decode_header
		mzlen = @header.cp * 512 + @header.cblp
		@encoded.ptr = 0
		csum = -@header.csum
		(mzlen/2).times { csum += @encoded.decode_imm(:u16, @endianness) }
		@encoded.data[2*Header::Fields.index(:csum), 2] = Expression[csum].encode(:u16, @endianness)
	end

	def decode_header
		@header = Header.decode self
	end
	
	def decode_relocs
		@relocs.clear
		@encoded.ptr = @header.lfarlc
		@header.crlc.times { @relocs << Relocation.decode(self) }
	end

	def decode_body
		@body = @encoded[@header.cparhdr*16..@header.cp*512+@header.cblp]
		@body.virtsize += @header.minalloc * 16
		@body.export['start'] = @header.cs * 16 + @header.ip
	end

	def self.decode(str)
		mz = new
		mz.encoded = EncodedData.new << str
		mz.encoded.ptr = 0
		mz.decode_header
		mz.decode_relocs
		mz.decode_body
		mz
	end
	
	def to_program
		begin
			cpu = Ia32.new(486, 16)
		rescue NameError
			cpu = UnknownCPU.new 16, @endianness
		end
		pgm = Program.new cpu
		pgm.sections << Section.new(pgm, '.text')
		pgm.sections.first.encoded << @body
		pgm.export['start'] = 'start'
		pgm
	end
end
end
