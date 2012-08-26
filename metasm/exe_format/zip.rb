#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'
begin
	require 'zlib'
rescue LoadError
end

# generic ZIP file, may be an APK or JAR
# supports only a trivial subset of the whole ZIP specification
#  single file archive
#  deflate or no compression
#  no encryption
#  32bit offsets/sizes

module Metasm
class ZIP < ExeFormat
	MAGIC_LOCALHEADER = 0x04034b50
	COMPRESSION_METHOD = { 0 => 'NONE', 1 => 'SHRUNK', 2 => 'REDUCE1', 3 => 'REDUCE2',
		4 => 'REDUCE3', 5 => 'REDUCE4', 6 => 'IMPLODE', 7 => 'TOKENIZED',
		8 => 'DEFLATE', 9 => 'DEFLATE64', 10 => 'OLDTERSE', 12 => 'BZIP2', 14 => 'LZMA',
		18 => 'TERSE', 19 => 'LZ77', 97 => 'WAVPACK', 98 => 'PPMD' }

	class LocalHeader < SerialStruct
		word :signature, MAGIC_LOCALHEADER
		half :verneed, 10
		bitfield :half, 2 => :unk1, 3 => :streamed
		half :compress_method, 0, COMPRESSION_METHOD
		halfs :mtime, :mdate
		word :crc32
		words :compressed_sz, :uncompressed_sz
		halfs :fname_len, :extra_len
		attr_accessor :fname, :extra
		attr_accessor :compressed_off

		def decode(zip)
			super(zip)
			raise "Invalid ZIP signature #{@signature.to_s(16)}" if @signature != MAGIC_LOCALHEADER
			@fname = zip.encoded.read(@fname_len) if @fname_len > 0
			@extra = zip.encoded.read(@extra_len) if @extra_len > 0
			@compressed_off = zip.encoded.ptr
		end

		def set_default_values(zip)
			super(zip)
			@fname_len = fname ? @fname.length : 0
			@extra_len = extra ? @extra.length : 0
		end

		def encode(zip)
			ed = super(zip)
			ed << fname << extra
		end

		def file_data(zip)
			zip.encoded.ptr = @compressed_off
			raw = zip.encoded.read(@compressed_sz)
			case @compress_method
			when 'NONE'
				raw
			when 'DEFLATE'
				z = Zlib::Inflate.new(-Zlib::MAX_WBITS)
				z.inflate(raw)
			else
				raise "Unsupported zip compress method #@compress_method"
			end
		end
	end

	MAGIC_CENTRALHEADER = 0x02014b50
	class CentralHeader < SerialStruct
		word :signature, MAGIC_CENTRALHEADER
		half :vermade, 10
		half :verneed, 10
		half :flags	#bitfield :half, 2 => :unk1, 3 => :streamed
		half :compress_method, 0, COMPRESSION_METHOD
		halfs :mtime, :mdate
		word :crc32
		words :compressed_sz, :uncompressed_sz
		halfs :fname_len, :extra_len, :comment_len
		half :disk_nr
		half :file_attr_intern
		word :file_attr_extern
		word :localhdr_off
		attr_accessor :fname, :extra, :comment

		def decode(zip)
			super(zip)
			raise "Invalid ZIP signature #{@signature.to_s(16)}" if @signature != MAGIC_CENTRALHEADER
			@fname = zip.encoded.read(@fname_len) if @fname_len > 0
			@extra = zip.encoded.read(@extra_len) if @extra_len > 0
			@comment = zip.encoded.read(@comment_len) if @comment_len > 0
		end

		def set_default_values(zip)
			super(zip)
			@fname_len = fname ? @fname.length : 0
			@extra_len = extra ? @extra.length : 0
			@comment_len = comment ? @comment.length : 0
		end

		def encode(zip)
			ed = super(zip)
			ed << fname << extra << comment
		end

		def file_data(zip)
			zip.encoded.ptr = @localhdr_off
			LocalHeader.decode(zip).file_data(zip)
		end
	end

	MAGIC_ENDCENTRALDIRECTORY = 0x06054b50
	class EndCentralDirectory < SerialStruct
		word :signature, MAGIC_ENDCENTRALDIRECTORY
		halfs :disk_nr, :disk_centraldir, :entries_nr_thisdisk, :entries_nr
		word :directory_sz
		word :directory_off
		half :comment_len
		attr_accessor :comment

		def decode(zip)
			super(zip)
			raise "Invalid ZIP end signature #{@signature.to_s(16)}" if @signature != MAGIC_ENDCENTRALDIRECTORY
			@comment = zip.encoded.read(@comment_len) if @comment_len > 0
		end

		def set_default_values(zip)
			super(zip)
			@comment_len = comment ? @comment.length : 0
		end

		def encode(zip)
			ed = super(zip)
			ed << comment
		end
	end

	def decode_half(edata=@encoded) edata.decode_imm(:u16, @endianness) end
	def decode_word(edata=@encoded) edata.decode_imm(:u32, @endianness) end
	def encode_half(w) Expression[w].encode(:u16, @endianness) end
	def encode_word(w) Expression[w].encode(:u32, @endianness) end

	attr_accessor :files, :header

	def initialize(cpu = nil)
		@endianness = :little
		@files = []
		super(cpu)
	end

	# scan and decode the 'end of central directory' header
	def decode_header
		if not @encoded.ptr = @encoded.data.rindex([MAGIC_ENDCENTRALDIRECTORY].pack('V'))
			raise "ZIP: no end of central directory record"
		end
		@header = EndCentralDirectory.decode(self)
	end

	# read the whole central directory file descriptors
	def decode
		decode_header
		@encoded.ptr = @header.directory_off
		while @encoded.ptr < @header.directory_off + @header.directory_sz
			@files << CentralHeader.decode(self)
		end
	end

	# checks if a given file name exists in the archive
	# returns the CentralHeader or nil
	# case-insensitive if lcase is false
	def has_file(fname, lcase=true)
		decode if @files.empty?
		if lcase
			@files.find { |f| f.fname == fname }
		else
			fname = fname.downcase
			@files.find { |f| f.fname.downcase == fname }
		end
	end

	# returns the uncompressed raw file content from a given name
	# nil if name not found
	# case-insensitive if lcase is false
	def file_data(fname, lcase=true)
		if f = has_file(fname, lcase)
			f.file_data(self)
		end
	end
end
end
