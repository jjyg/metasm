require 'metasm/exe_format/coff'
require 'metasm/decode'

module Metasm
class COFF
	class Header
		# decodes a COFF header from coff.encoded.ptr
		def decode(coff)
			@machine  = coff.int_to_hash(coff.decode_half, MACHINE)
			@num_sect = coff.decode_half
			@time     = coff.decode_word
			@ptr_sym  = coff.decode_word
			@num_sym  = coff.decode_word
			@size_opthdr = coff.decode_half
			@characteristics = coff.bits_to_hash(coff.decode_half, CHARACTERISTIC_BITS)
		end
	end

	class OptionalHeader
		# decodes a COFF optional header from coff.encoded.ptr
		# also decodes directories in coff.directory
		def decode(coff)
			@signature  = coff.int_to_hash(coff.decode_half, SIGNATURE)
			@link_ver_maj = coff.decode_uchar
			@link_ver_min = coff.decode_uchar
			@code_size  = coff.decode_word 
			@data_size  = coff.decode_word 
			@udata_size = coff.decode_word
			@entrypoint = coff.decode_word
			@base_of_code = coff.decode_word
			@base_of_data = coff.decode_word if @signature != 'PE+'
			@image_base = coff.decode_xword
			@sect_align = coff.decode_word
			@file_align = coff.decode_word
			@os_ver_maj = coff.decode_half   
			@os_ver_min = coff.decode_half   
			@img_ver_maj= coff.decode_half  
			@img_ver_min= coff.decode_half  
			@subsys_maj = coff.decode_half
			@subsys_min = coff.decode_half
			@reserved   = coff.decode_word  
			@image_size = coff.decode_word
			@headers_size = coff.decode_word
			@checksum   = coff.decode_word
			@subsystem  = coff.int_to_hash(coff.decode_half, SUBSYSTEM)
			@dll_characts = coff.bits_to_hash(coff.decode_half, DLL_CHARACTERISTIC_BITS)
			@stack_reserve = coff.decode_xword
			@stack_commit = coff.decode_xword
			@heap_reserve = coff.decode_xword
			@heap_commit  = coff.decode_xword
			@ldrflags   = coff.decode_word
			@numrva     = coff.decode_word

			if @numrva > DIRECTORIES.length
				puts "W: COFF: Invalid directories count #{@numrva}"
				return self
			end

			coff.directory = {}
			DIRECTORIES[0, @numrva].each { |dir|
				rva = coff.decode_word
				sz  = coff.decode_word
				if rva != 0 or sz != 0
					coff.directory[dir] = [rva, sz]
				end
			}
		end
	end

	class Section
		# decodes a COFF section header from coff.encoded
		def decode(coff)
			@name = coff.encoded.read(8)
			@name = @name[0, @name.index(0)] if @name.index(0)
			@virtsize   = coff.decode_word
			@virtaddr   = coff.decode_word
			@rawsize    = coff.decode_word
			@rawaddr    = coff.decode_word
			@relocaddr  = coff.decode_word
			@linenoaddr = coff.decode_word
			@relocnr    = coff.decode_half
			@linenonr   = coff.decode_half
			@characteristics = coff.bits_to_hash(coff.decode_word, SECTION_CHARACTERISTIC_BITS)
		end
	end

	class ExportDirectory
		# decodes a COFF export table from coff.encoded.ptr
		def decode(coff)
			@reserved   = coff.decode_word
			@timestamp  = coff.decode_word
			@version_major = coff.decode_half
			@version_minor = coff.decode_half
			@libname_p  = coff.decode_word
			@ordinal_base  = coff.decode_word
			num_exports = coff.decode_word
			num_names   = coff.decode_word
			func_p     = coff.decode_word
			names_p    = coff.decode_word
			ord_p      = coff.decode_word

			if off = coff.rva_to_off(@libname_p)
				@libname = coff.encoded.data[off...coff.encoded.data.index(0, off)]
			end

			if coff.encoded.ptr = coff.rva_to_off(func_p)
				@exports = []
				num_exports.times { |i|
					e = Export.new
					e.ordinal = i + @ordinal_base
					addr = coff.decode_word
					if addr >= coff.directory['export_table'][0] and addr < coff.directory['export_table'][0] + coff.directory['export_table'][1] and off = coff.rva_to_off(addr)
						name = coff.encoded.data[off...coff.encoded.data.index(0, off)]
						e.forwarder_lib, name = name.split('.', 2)
						if name[0] == ?#
							e.forwarder_ordinal = name[1..-1].to_i
						else
							e.forwarder_name = name
						end
					else
						e.target = addr
					end
					@exports << e
				}
			end
			if coff.encoded.ptr = coff.rva_to_off(names_p)
				namep = []
				num_names.times { namep << coff.decode_word }
			end
			if coff.encoded.ptr = coff.rva_to_off(ord_p)
				ords = []
				num_names.times { ords << coff.decode_half }
			end
			if namep and ords
				namep.zip(ords).each { |np, oi|
					@exports[oi].name_p = np
					if addr = coff.rva_to_off(np)
						@exports[oi].name = coff.encoded.data[addr...coff.encoded.data.index(0, addr)]
					end
				}
			end
		end
	end

	class ImportDirectory
		# decodes all COFF import directories from coff.encoded.ptr
		def self.decode(coff)
			ret = []
			loop do
				idata = new
				idata.decode(coff)
				break if not idata.imports
				ret << idata
			end
			ret
		end

		# decode a COFF import table from coff.encoded.ptr
		# after the function, coff.encoded.ptr points to the end of the import table
		def decode(coff)
			@ilt_p = coff.decode_word
			@timestamp = coff.decode_word
			@firstforwarder = coff.decode_word
			@libname_p = coff.decode_word
			@iat_p = coff.decode_word

			nextidata_ptr = coff.encoded.ptr	# will decode other directories

			return if [@ilt_p, @timestamp, @firstforwarder, @libname_p, @iat_p].all? { |p| p == 0 }

			if off = coff.rva_to_off(@libname_p)
				@libname = coff.encoded.data[off...coff.encoded.data.index(0, off)]
			end

			if coff.encoded.ptr = coff.rva_to_off(@ilt_p)
				addrs = []
				while (a = coff.decode_xword) != 0
					addrs << a
				end

				@imports = []
				
				ord_mask = 1 << (coff.optheader.signature == 'PE+' ? 63 : 31)
				addrs.each { |a|
					i = Import.new
					if (a & ord_mask) != 0
						i.ordinal = a & (~ord_mask)
					else
						i.hintname_p = a
						if coff.encoded.ptr = coff.rva_to_off(a)
							i.hint = coff.decode_half
							i.name = coff.encoded.data[coff.encoded.ptr...coff.encoded.data.index(0, coff.encoded.ptr)]
						end
					end
					@imports << i
				}
			end

			if coff.encoded.ptr = coff.rva_to_off(@iat_p)
				@iat = []
				while (a = coff.decode_xword) != 0
					@iat << a
				end
			end

			coff.encoded.ptr = nextidata_ptr
		end
	end

	class RelocationTable
		# decodes a relocation table from coff.encoded.ptr
		def decode(coff)
			@base_addr = coff.decode_word
			@relocs = []
			len = coff.decode_word
			if len < 8 or len % 2 != 0
				puts "W: COFF: Invalid relocation table length #{len}"
				return
			end
			len -= 8
			len /= 2
			len.times {
				raw = coff.decode_half
				r = Relocation.new
				r.offset = raw & 0xfff
				r.type = coff.int_to_hash(((raw >> 12) & 15), BASE_RELOCATION_TYPE)
				@relocs << r
			}
		end
	end


	def decode_uchar(edata = @encoded) ; edata.decode_imm(:u8,  @endianness) end
	def decode_half( edata = @encoded) ; edata.decode_imm(:u16, @endianness) end
	def decode_word( edata = @encoded) ; edata.decode_imm(:u32, @endianness) end
	def decode_xword(edata = @encoded) ; edata.decode_imm((@optheader.signature == 'PE+' ? :u64 : :u32), @endianness) end

	def rva_to_off rva
		s = @sections.find { |s| s.virtaddr <= rva and s.virtaddr + s.virtsize > rva } if rva and rva != 0
		if s
			rva - s.virtaddr + s.rawaddr
		elsif rva > 0 and rva < @optheader.headers_size
			rva
		end
	end

	# decodes the COFF header, optional header, section headers
	# marks entrypoint and directories as encoded.export
	def decode_header
		@header = Header.new
		@header.decode(self)
		@optheader = OptionalHeader.new
		@optheader.decode(self)
		@header.num_sect.times {
			s = Section.new
			s.decode self
			@sections << s
		}
		if off = rva_to_off(@optheader.entrypoint)
			@encoded.export[new_label('entrypoint')] = off
		end
		DIRECTORIES.each { |d|
			if @directory and @directory[d] and off = rva_to_off(@directory[d][0])
				@encoded.export[new_label(d)] = off
			end
		}
	end

	# decodes COFF export table from directory
	# mark exported names as encoded.export
	def decode_exports
		if @directory and @directory['export_table'] and @encoded.ptr = rva_to_off(@directory['export_table'][0])
			@export = ExportDirectory.new
			@export.decode(self)
			@export.exports.each { |e|
				if e.name and off = rva_to_off(e.target)
					@encoded.export[e.name] = off
				end
			} if @export.exports
		end
	end

	# decodes COFF import tables from directory
	# mark iat entries as encoded.export
	def decode_imports
		if @directory and @directory['import_table'] and @encoded.ptr = rva_to_off(@directory['import_table'][0])
			@imports = ImportDirectory.decode(self)
			iatlen = @optheader.signature == 'PE+' ? 8 : 4
			@imports.each { |id|
				if off = rva_to_off(id.iat_p)
					id.imports.each_with_index { |i, idx|
						@encoded.export[i.name] = off + iatlen*idx if i.name
					}
				end
			}
		end
	end

	# decode COFF relocation tables from directory
	# mark relocations as encoded.relocs
	def decode_relocs
		if @directory and @directory['base_relocation_table'] and @encoded.ptr = rva_to_off(@directory['base_relocation_table'][0])
			end_addr = @encoded.ptr + @directory['base_relocation_table'][1]
			@relocations = []
			while @encoded.ptr < end_addr
				rt = RelocationTable.new
				rt.decode self
				@relocations << rt
			end

			# interpret as EncodedData relocations
			relocfunc = ('decode_reloc_' << @header.machine.downcase).to_sym
			if not respond_to? relocfunc
				puts "W: COFF: unsupported relocs for architecture #{@header.machine}"
				return
			end
			@relocations.each { |rt|
				rt.relocs.each { |r|
					if off = rva_to_off(rt.base_addr + r.offset)
						@encoded.ptr = off
						rel = send(relocfunc, r)
						@encoded.reloc[off] = rel if rel
					end
				}
			}
		end
	end

	# decodes an I386 COFF relocation pointing to encoded.ptr
	def decode_reloc_i386(r)
		case r.type
		when 'ABSOLUTE'
		when 'HIGHLOW', 'DIR64'
			case r.type
			when 'HIGHLOW': addr, type = decode_word, :u32
			when 'DIR64':   addr, type = decode_xword, :u64
			end
			addr -= @optheader.image_base
			if off = rva_to_off(addr)
				Metasm::Relocation.new(Expression[label_at(@encoded, off, 'xref_%x' % addr)], type, @endianness)
			end
		else puts "W: COFF: Unsupported i386 relocation #{r.inspect}"
		end
	end

	# read section data
	def decode_sections
		@sections.each { |s|
			s.encoded = @encoded[s.rawaddr, [s.rawsize, s.virtsize].min]
			s.encoded.virtsize = s.virtsize
		}
	end

	# decodes a COFF file (headers/exports/imports/relocs/sections)
	# starts at encoded.ptr
	def decode
		decode_header
		decode_exports
		decode_imports
		decode_relocs
		decode_sections
	end

	# convert a COFF object to a Program
	def to_program
		cpu = \
		case @header.machine
		when 'I386': Ia32.new
		end rescue nil
		cpu ||= UnknownCPU.new(32, :little)
		pgm = Program.new cpu

		@sections.each { |s|
			ps = Metasm::Section.new(pgm, s.name)
			ps.encoded << s.encoded
			ps.mprot.concat({
				'MEM_EXECUTE' => :exec, 'MEM_READ' => :read, 'MEM_WRITE' => :write, 'MEM_DISCARDABLE' => :discard, 'MEM_SHARED' => :shared
			}.values_at(*s.characteristics).compact)
			ps.base = s.virtaddr
			pgm.sections << ps
		}
		
		if @imports
			@imports.each { |id|
				pgm.import[id.libname] = id.imports.map { |i| [i.name, nil] }
			}
		end

		if @export
			@export.exports.each { |e|
				pgm.export[e.name] = e.target if e.name and e.target
			}
		end

		pgm
	end
end
end
