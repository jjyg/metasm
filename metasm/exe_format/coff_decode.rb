require 'metasm/exe_format/coff'
require 'metasm/decode'

module Metasm
class COFF
	class Header
		def decode(coff)
			@machine  = coff.int_to_hash(coff.decode_half, MACHINE)
			@num_sect = coff.decode_half
			@time     = coff.decode_word
			@ptr_sym  = coff.decode_word
			@num_sym  = coff.decode_word
			@size_opthdr = coff.decode_half
			@characteristics = coff.bits_to_hash(coff.decode_half, CHARACTERISTIC_BITS)
			self
		end
	end

	class OptionalHeader
		def decode(coff)
			@sig = coff.int_to_hash(coff.decode_half, SIGNATURE)
			@linkv_maj  = coff.decode_uchar
			@linkv_min  = coff.decode_uchar
			@code_size  = coff.decode_word 
			@data_size  = coff.decode_word 
			@udata_size = coff.decode_word
			@entrypoint = coff.decode_word
			@base_of_code = coff.decode_word
			@base_of_data = coff.decode_word if @sig != 'PE+'
			@imagebase  = coff.decode_xword
			@sect_align = coff.decode_word
			@file_align = coff.decode_word
			@osv_maj    = coff.decode_half   
			@osv_min    = coff.decode_half   
			@imgv_maj   = coff.decode_half  
			@imgv_min   = coff.decode_half  
			@subsys_maj = coff.decode_half
			@subsys_min = coff.decode_half
			@reserved   = coff.decode_word  
			@image_size = coff.decode_word
			@headers_size = coff.decode_word
			@checksum   = coff.decode_word
			@subsystem  = coff.int_to_hash(coff.decode_half, SUBSYSTEM)
			@dll_characts = coff.bits_to_hash(coff.decode_half, DLL_CHARACTERISTIC_BITS)
			@stackres_size = coff.decode_xword
			@stackcom_size = coff.decode_xword
			@heapres_size = coff.decode_xword
			@heapcom_size = coff.decode_xword
			@ldrflags   = coff.decode_word
			@numrva     = coff.decode_word

			if @numrva > DIRECTORIES.length
				puts "W: COFF: Invalid directories count #{@numrva}"
				return self
			end

			DIRECTORIES[0, @numrva].each { |dir|
				rva = coff.decode_word
				sz  = coff.decode_word
				if rva != 0 or sz != 0
					coff.directory[dir] = [rva, sz]
				end
			}
			self
		end
	end

	class Section
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
			self
		end
	end

	class ExportDirectory
		def decode(coff)
			@reserved   = coff.decode_word
			@timestamp  = coff.decode_word
			@version_major = coff.decode_half
			@version_minor = coff.decode_half
			dllname     = coff.decode_word
			@ordinal_base  = coff.decode_word
			num_exports = coff.decode_word
			num_names   = coff.decode_word
			addrtable   = coff.decode_word
			namptable   = coff.decode_word
			ord_table   = coff.decode_word

			if off = coff.rva_to_off(dllname)
				@dllname = coff.encoded.data[off...coff.encoded.data.index(0, off)]
			end

			if coff.encoded.ptr = coff.rva_to_off(addrtable)
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
			if coff.encoded.ptr = coff.rva_to_off(namptable)
				namep = []
				num_names.times { namep << coff.decode_word }
			end
			if coff.encoded.ptr = coff.rva_to_off(ord_table)
				ords = []
				num_names.times { ords << coff.decode_half }
			end
			if namep and ords
				namep.each_with_index { |np, i|
					if addr = coff.rva_to_off(np)
						@exports[ords[i]].name = coff.encoded.data[addr...coff.encoded.data.index(0, addr)]
					end
				}
			end

			self
		end
	end

	class ImportDirectory
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

		def decode(coff)
			ilt = coff.decode_word
			@timestamp = coff.decode_word
			@firstforwarder = coff.decode_word
			name = coff.decode_word
			@iat_p = coff.decode_word
			nextidata_ptr = coff.encoded.ptr	# will decode other directories

			@imports = nil if [ilt, @timestamp, @firstforwarder, name, @iat_p].all? { |p| p == 0 }

			if off = coff.rva_to_off(name)
				@libname = coff.encoded.data[off...coff.encoded.data.index(0, off)]
			end

			if coff.encoded.ptr = coff.rva_to_off(ilt)
				addrs = []
				while (a = coff.decode_xword) != 0
					addrs << a
				end

				@imports = []
				
				ord_mask = 1 << (coff.optheader.sig == 'PE+' ? 63 : 31)
				addrs.each { |a|
					i = Import.new
					if (a & ord_mask) != 0
						i.ordinal = a & (~ord_mask)
					else
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


	def decode_uchar(edata = @encoded) ; edata.decode_imm(:u8,  @endianness) end
	def decode_half( edata = @encoded) ; edata.decode_imm(:u16, @endianness) end
	def decode_word( edata = @encoded) ; edata.decode_imm(:u32, @endianness) end
	def decode_xword(edata = @encoded) ; edata.decode_imm((@optheader.sig == 'PE+' ? :u64 : :u32), @endianness) end

	def rva_to_off rva
		s = @sections.find { |s| s.virtaddr <= rva and s.virtaddr + s.virtsize > rva } if rva and rva != 0
		rva - s.virtaddr + s.rawaddr if s
	end

	def decode_header
		@header = Header.new.decode(self)
		(@optheader = OptionalHeader.new).decode(self)	# #decode uses decode_xword, which needs @optheader to exist
		@header.num_sect.times { @sections << Section.new.decode(self) }
		if off = rva_to_off(@optheader.entrypoint)
			@encoded.export['entrypoint'] = off
		end
	end

	def decode_exports
		if @directory['export_table'] and @encoded.ptr = rva_to_off(@directory['export_table'][0])
			@export = ExportDirectory.new.decode(self)
			@export.exports.each { |e|
				if e.name and off = rva_to_off(e.target)
					@encoded.export[e.name] = off
				end
			}
		end
	end

	def decode_imports
		if @directory['import_table'] and @encoded.ptr = rva_to_off(@directory['import_table'][0])
			@imports = ImportDirectory.decode(self)
			iatlen = @optheader.sig == 'PE+' ? 8 : 4
			@imports.each { |id|
				if off = rva_to_off(id.iat_p)
					id.imports.each_with_index { |i, idx|
						if i.name
							@encoded.export[i.name] = off + iatlen*idx
						end
					}
				end
			}
		end
	end

	def decode_sections
		@sections.each { |s|
			s.encoded = @encoded[s.rawaddr, s.rawsize]
			s.encoded.virtsize += s.virtsize - s.rawsize
		}
	end

	def decode
		decode_header
		decode_exports
		decode_imports
		decode_sections
	end

	def to_program
		cpu = \
		case @header.machine
		when 'I386': Ia32.new
		end rescue nil
		cpu ||= UnknownCPU.new(32, :little)
		pgm = Program.new cpu

		@sections.each { |s|
			ps = Metasm::Section.new(pgm, s.name)
			ps.encoded << @encoded[s.rawaddr, s.rawsize]
			ps.encoded.virtsize += s.virtsize - s.rawsize
			ps.mprot.concat({
				'MEM_EXECUTE' => :exec, 'MEM_READ' => :read, 'MEM_WRITE' => :write, 'MEM_DISCARDABLE' => :discard, 'MEM_SHARED' => :shared
			}.values_at(*s.characteristics).compact)
			ps.base = s.virtaddr
			pgm.sections << ps
		}
		
		if @imports
			@imports.each { |id|
				pgm.import[id.libname] = []
				id.imports.each { |i|
					pgm.import[id.libname] << [i.name, nil]
				}
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
