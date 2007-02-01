require 'metasm/exe_format/main'

module Metasm
class ELF < ExeFormat
class << self
	EI_NIDENT = 16
	ELFCLASS = { 0 => 'NONE', 1 => '32', 2 => '64' }
	ELFDATA  = { 0 => 'NONE', 1 => 'LSB', 2 => 'MSB' }
	E_VERSION = { 0 => 'INVALID', 1 => 'CURRENT' }
	E_TYPE = { 0 => 'NONE', 1 => 'REL', 2 => 'EXEC', 3 => 'DYN', 4 => 'CORE',
		0xff00 => 'LOPROC', 0xffff => 'HIPROC' }
	E_MACHINE = { 0 => 'NONE', 1 => 'M32', 2 => 'SPARC', 3 => '386',
		4 => '68K', 5 => '88K', 7 => '860', 8 => 'MIPS' }

	def encode(program, opts={})
		program_start = program.new_unique_label

		segs = []
		prog_hdr = pre_encode_proghdr(program, program_start, segs, opts)
		sect_hdr = pre_encode_secthdr(program, program_start, opts)

		hdr = pre_encode_header(program, program_start, prog_hdr, sect_hdr, opts)

		hdr << prog_hdr if prog_hdr
		hdr << sect_hdr if sect_hdr

		hdr.fixup hdr.export.inject({}) { |f, (n, o)| f.update n => Expression[program_start, :+, o] }

		# XXX
		segs.each { |s|
			hdr.align_size 0x1000
			hdr << s
		}

		hdr.fixup hdr.export.inject({}) { |f, (n, o)| f.update n => Expression[program_start, :+, o] }

		hdr.data
	end

	PROGRAM_TYPE = { 0 => 'NULL', 1 => 'LOAD', 2 => 'DYNAMIC', 3 => 'INTERP',
		4 => 'NOTE', 5 => 'SHLIB', 6 => 'PHDR',
		0x7000_0000 => 'LOPROC', 0x7fff_ffff => 'HIPROC' }
	PROGRAM_FLAGS = { 1 => 'X', 2 => 'W', 4 => 'R' }

	def pre_encode_proghdr(program, program_start, segs, opts)
		hdr = EncodedData.new

		# interp must come before load, 0 or 1 occurence only
		# load must be sorted on virtaddr
		# shlib is forbidden
		# phdr must come before load, 0 or 1 occurence only
		encode = proc { |type, val| hdr << Expression[*val].encode(type, program.cpu.endianness) }
		encode_seg = proc { |type, segment, flags|
			encode[:u32, PROGRAM_TYPE.index(type)]	# type
			encode[:u32, [program.label_at(segment.edata, 0), :-, program_start]]	# file offset to segment data
			encode[:u32, segment.virtaddr]		# segment virtual base
			encode[:u32, segment.virtaddr]		# segment physical address (ignored)
			encode[:u32, segment.rawsize]		# segment file size
			encode[:u32, segment.virtsize]		# segment virtual size
			encode[:u32, flags]			# memory protection
			encode[:u32, segment.align]
		}


		# XXX
		require 'ostruct'
		program.sections.each { |s|
			ed = s.encoded
			ed.fill
			segs << ed
			dt = OpenStruct.new
			dt.edata = ed
			dt.virtaddr = 0x0800_0000
			dt.rawsize = ed.data.size
			dt.virtsize = ed.virtsize
			dt.align = 0x1000
			encode_seg['LOAD', dt, 5]
		}

		hdr
	end

	def pre_encode_secthdr(program, program_start, opts)
	end

	def pre_encode_header(program, program_start, prog_hdr, sect_hdr, opts)
		hdr = EncodedData.new
		hdr.export[program_start] = 0

		end_hdr = program.new_unique_label

		hdr << 0x7f << 'ELF'
		hdr << ELFCLASS.index(program.cpu.size.to_s)	# 16bits ?
		hdr << ELFDATA.index( {:little => 'LSB', :big => 'MSB'}[program.cpu.endianness] )
		e_version = E_VERSION.index(opts.delete('e_version') || 'CURRENT')	# XXX allow opts to override the hash lookup ?
		hdr << e_version
		hdr.fill(16, "\0")

		encode = proc { |type, val| hdr << Expression[*val].encode(type, program.cpu.endianness) }

		encode[:u16, E_TYPE.index(opts.delete('e_type') || 'DYN')]
		encode[:u16, E_MACHINE.index(opts.delete('e_machine') || '386')]	# XXX
		encode[:u32, e_version]

		entrypoint = opts.delete('entrypoint') || 'start'
		if entrypoint.kind_of? Integer
			encode[:u32, entrypoint]
		elsif not program.sections.find { |s| s.encoded.export[entrypoint] }
#			raise EncodeError, 'No entrypoint defined' if pe_target == :exe
			puts 'W: No entrypoint defined'	# if e_type == 'ET_DYN' or e_type == 'ET_EXEC'
			encode[:u32, 0]
		else
			# XXX
			encode[:u32, [0x8000_0000, :+, program.sections.first.encoded.export[entrypoint]]]
			#encode[:u32, entrypoint]
		end

		encode[:u32, prog_hdr ? [program.label_at(prog_hdr, 0), :-, program_start] : 0]
		encode[:u32, sect_hdr ? [program.label_at(sect_hdr, 0), :-, program_start] : 0]
		
		flags = 0
		encode[:u32, flags]
		encode[:u16, [end_hdr, :-, program_start]]
		encode[:u16, 0x20]	# program header entry size
		encode[:u16, prog_hdr ? prog_hdr.virtsize / 0x20 : 0]	# number of program header entries
		encode[:u16, 0x28]	# section header entry size
		encode[:u16, sect_hdr ? sect_hdr.virtsize / 0x28 : 0]	# number of section header entries
		shstrindex = 0
		encode[:u16, shstrindex]	# index of string table index in section table (0 if none)

		hdr.export[end_hdr] = hdr.virtsize
		hdr.align_size program.cpu.size/8
		hdr
	end
end
end
end

