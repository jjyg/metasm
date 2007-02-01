begin
	require 'mmap'
rescue LoadError
end

def bin(chars)
	ret = 0
	chars.length.times { |i| ret += chars[i] << (8*i) }
	ret
end

class CoffHeader
	attr_reader :machine, :nbsections, :timedatestamp, :ptrsymboltable, :nbsymbols, :sizeoptheader, :caracteristics
	
	@@machinehash = {
		0x0   => :UNKNOWN, 0x184 => :ALPHA, 0x1c0 => :ARM, 0x284 => :ALPHA64, 0x14c => :I386,
		0x200 => :IA64, 0x268 => :M68K, 0x266 => :MIPS16, 0x366 => :MIPSFPU, 0x466 => :MIPSFPU16,
		0x1f0 => :POWERPC, 0x162 => :R3000, 0x166 => :R4000, 0x168 => :R10000, 0x1a2 => :SH3,
		0x1a6 => :SH4, 0x1c2 => :THUMB
	}

	@@caracteristic_bits = {
		0x0001 => :RELOCS_STRIPPED, 0x0002 => :EXECUTABLE_IMAGE, 0x0004 => :LINE_NUMS_STRIPPED, 0x0008 => :LOCAL_SYMS_STRIPPED,
		0x0010 => :AGGRESSIVE_WS_TRIM, 0x0020 => :LARGE_ADDRESS_AWARE, 0x0040 => :x16BIT_MACHINE, 0x0080 => :BYTES_REVERSED_LO,
		0x0100 => :x32BIT_MACHINE, 0x0200 => :DEBUG_STRIPPED, 0x0400 => :REMOVABLE_RUN_FROM_SWAP,
		0x1000 => :SYSTEM, 0x2000 => :DLL, 0x4000 => :UP_SYSTEM_ONLY, 0x8000 => :BYTES_REVERSED_HI
	}
	
	def initialize(raw, offset)
		@machine = bin(raw[offset..offset+1])
		@nbsections = bin(raw[offset+2..offset+3])
		@timedatestamp = bin(raw[offset+4..offset+7])
		@ptrsymboltable = bin(raw[offset+8..offset+11])
		@nbsymbols = bin(raw[offset+12..offset+15])
		@sizeoptheader = bin(raw[offset+16..offset+17])
		@caracteristics = bin(raw[offset+18..offset+19])
	end
	
	def inspect
		char = []
		32.times { |i| char << @@caracteristic_bits[1 << i] if (@caracteristics & (1 << i)) != 0 }
		"#{@@machinehash[@machine]} #{char.join ', '}"
	end
end

class ImageDataDir
	attr_reader :rva, :size
	
	def initialize(raw, offset)
		@rva = bin(raw[offset..offset+3])
		@size = bin(raw[offset+4..offset+7])
	end
end

class OptHeader
	attr_reader :type, :sizecode, :sizeidata, :sizeudata, :entrypoint, :basecode, :basedata, :imagebase
	attr_reader :sizeimage, :sizeheaders, :sizestackresrv, :sizestackcommt, :sizeheapresrv, :sizeheapcommt
	attr_reader :numrvaent, :subsystem
	attr_reader :dirs
	
	@@subsystems = {
		0 => :UNKNOWN, 1 => :NATIVE, 2 => :WINDOWS_GUI, 3 => :WINDOWS_CUI, 7 => :POSIX_CUI,
		9 => :WINDOWS_CE_GUI, 10 => :EFI_APPLICATION, 11 => :EFI_BOOT_SERVICE_DRIVER, 12 => :EFI_RUNTIME_DRIVER
	}

	@@dll_carac_bits = { 0x800 => :NO_BIND, 0x2000 => :WDM_DRIVER, 0x8000 => :TERMINAL_SERVER_AWARE }

	def initialize(raw, offset)
		@type		= bin(raw[offset   ..offset+1 ])
		raise RuntimeError.new("invalid optheader sig") if not [0x107, 0x10b, 0x20b].include?(@type)
		@linker_min	= raw[offset+2]
		@linker_maj	= raw[offset+3]
		@sizecode	= bin(raw[offset+4 ..offset+7 ])
		@sizeidata	= bin(raw[offset+8 ..offset+11])
		@sizeudata	= bin(raw[offset+12..offset+15])
		@entrypoint	= bin(raw[offset+16..offset+19])
		@basecode	= bin(raw[offset+20..offset+23])

		@sectionalign	= bin(raw[offset+32..offset+35])
		@filealign	= bin(raw[offset+36..offset+39])
		@majos		= bin(raw[offset+40..offset+41])
		@minos		= bin(raw[offset+42..offset+43])
		@majim		= bin(raw[offset+44..offset+45])
		@minim		= bin(raw[offset+46..offset+47])
		@majsubsys	= bin(raw[offset+48..offset+49])
		@minsubsys	= bin(raw[offset+50..offset+51])
		@reserved	= bin(raw[offset+52..offset+55])
		@sizeimage	= bin(raw[offset+56..offset+59])
		@sizeheaders	= bin(raw[offset+60..offset+63])
		@checksum	= bin(raw[offset+64..offset+67])
		@subsystem	= bin(raw[offset+68..offset+69])
		@dllcarac	= bin(raw[offset+70..offset+71])
		
		case @type
		when 0x20b
			@imagebase	= bin(raw[offset+24..offset+31])

			@sizestackresrv	= bin(raw[offset+72..offset+79])
			@sizestackcommt	= bin(raw[offset+80..offset+87])
			@sizeheapresrv	= bin(raw[offset+88..offset+95])
			@sizeheapcommt	= bin(raw[offset+96..offset+103])
			@loaderflags	= bin(raw[offset+104..offset+107])
			@numrvaent	= bin(raw[offset+108..offset+111])
			
			read_image_data_dirs(raw, offset+112)
			
		else
			@basedata	= bin(raw[offset+24..offset+27])
			@imagebase	= bin(raw[offset+28..offset+31])

			@sizestackresrv	= bin(raw[offset+72..offset+75])
			@sizestackcommt	= bin(raw[offset+76..offset+79])
			@sizeheapresrv	= bin(raw[offset+80..offset+83])
			@sizeheapcommt	= bin(raw[offset+84..offset+87])
			@loaderflags	= bin(raw[offset+88..offset+91])
			@numrvaent	= bin(raw[offset+92..offset+95])

			read_image_data_dirs(raw, offset+96)
		end
	end

	def read_image_data_dirs(raw, offset)
		@dirs = Hash.new
		[:export, :import, :resource, :exception, :certificate, :basereloc, :debug, :arch, :globptr,
		 :tls, :loadconf, :boundimport, :iat, :delayimport, :comrt, :reserved].each { |i|
		 	break if @dirs.keys.length >= @numrvaent
		 	@dirs[i] = ImageDataDir.new(raw, offset)
		 	offset += 8
		}
	end
	
	def inspect
		"subsystem #{@@subsystems[@subsystem]}, base %X, imagesize %X, entrypoint %X" % [@imagebase, @sizeimage, @entrypoint]
	end
end

class Section
	attr_reader :name, :virtsize, :virtaddr, :rawsize, :rawptr, :relocptr, :linesptr, :bnreloc, :nblines, :caracs

	# more values exist
	@@caracteristic_bits = {
		0x20 => :CONTAINS_CODE, 0x40 => :CONTAINS_DATA, 0x80 => :CONTAINS_UDATA,
		0x01000000 => :LNK_NRELOC_OVFL, 0x02000000 => :MEM_DISCARDABLE, 0x04000000 => :MEM_NOT_CACHED, 0x08000000 => :MEM_NOT_PAGED,
		0x10000000 => :MEM_SHARED, 0x20000000 => :MEM_EXECUTE, 0x40000000 => :MEM_READ, 0x80000000 => :MEM_WRITE
	}
	
	def initialize(raw, offset)
		@name = raw[offset..offset+7].delete("\0")
		@virtsize	= bin(raw[offset+8 ..offset+11])
		@virtaddr	= bin(raw[offset+12..offset+15])
		@rawsize	= bin(raw[offset+16..offset+19])
		@rawptr		= bin(raw[offset+20..offset+23])
		@relocptr	= bin(raw[offset+24..offset+27])
		@linesptr	= bin(raw[offset+28..offset+31])
		@nbreloc	= bin(raw[offset+32..offset+33])
		@nblines	= bin(raw[offset+34..offset+35])
		@caracs		= bin(raw[offset+36..offset+39])
	end

	def inspect
		flags = []
		32.times { |i| flags << @@caracteristic_bits[1 << i] if (@caracs & (1 << i)) != 0 }
		"section #@name: (v/r) pos %X/%X, size %X/%X. Flags: #{flags.join(', ')}" % [@virtaddr, @rawptr, @virtsize, @rawsize]
	end
end

class Import
	attr_reader :hint, :name, :rva

	def initialize(name, hint, rva)
		@name, @hint, @rva = name, hint, rva
	end
end

class ImportTable
	attr_reader :lookuptablerva, :forwarderchain, :dllnamerva, :iatrva
	attr_accessor :imports
	
	def initialize(raw, offset)
		@lookuptablerva = bin(raw[offset..offset+3])
		@forwarderchain = bin(raw[offset+8..offset+11])
		@dllnamerva = bin(raw[offset+12..offset+15])
		@iatrva = bin(raw[offset+16..offset+19])
		@imports = []
	end
end

class Export
	attr_reader :name, :ordinal, :rva, :forwarder
	
	def initialize(name, ordinal, rva, forwarder = nil)
		@name, @ordinal, @rva, @forwarder = name, ordinal, rva, forwarder
	end
end

class ExportTable
	attr_reader :modulenamerva, :ordinalbase, :addrtablesize, :nametablesize, :addrtablerva, :nametablerva, :ordtablerva
	attr_accessor :exports, :modulename
	
	def initialize(raw, offset)
		@modulenamerva = bin(raw[offset+12..offset+15])
		@ordinalbase = bin(raw[offset+16..offset+19])
		@addrtablesize = bin(raw[offset+20..offset+23])
		@nametablesize = bin(raw[offset+24..offset+27])
		@addrtablerva = bin(raw[offset+28..offset+31])
		@nametablerva = bin(raw[offset+32..offset+35])
		@ordtablerva = bin(raw[offset+36..offset+39])
		@exports = []
	end

	def inspect
		"#{@modulename.inspect} - #{@exports.map{ |e| e.name }.sort.join ', ' if @exports}"
	end
end

class Symbols
	attr_reader :name, :value, :sectionnumber, :type, :storageclass, :nbaux, :aux
# name: if the first 4 bytes are null, the 4 next are the index to the name in the string table

	def initialize(raw, offset)
		@name = raw[offset..offset+7].delete("\0")
		@value = bin(raw[offset+8 ..offset+11])
		@sectionnumber = bin(raw[offset+12..offset+13])
		@type = bin(raw[offset+14..offset+15])
		@storageclass = raw[offset+16]
		@nbaux = raw[offset+17]
		@aux = Array.new
		@nbaux.times { @aux << raw[offset..offset+17] ; offset += 18 }
	end
end

class Strings < Array
	attr_reader :size
	
	def initialize(raw, offset)
		@size = bin(raw[offset..offset+3])
		endoffset = offset + @size
puts "String table: 0x%.8x .. 0x%.8x" % [offset, endoffset]
		curstring = ''
		while (offset < endoffset)
			if raw[offset] != 0
				curstring << raw[offset]
			else
				self << curstring
				curstring = ''
			end
			offset += 1
		end
	end
end

class PE
	def PE.load(filename)
		PE.new((File.mmap(filename) rescue File.read(filename)))
	end
	
	attr_reader :coffheader, :optheader, :sections, :symbols, :strings, :raw
	
	def find_section(rva)
		@sections.values.find { |s| rva >= s.virtaddr and rva < s.virtaddr + s.virtsize }
	end

	def rva2va(rva)
		rva + @optheader.imagebase
	end

	def rva2ra(rva)
		x = find_section rva
		rva - x.virtaddr + x.rawptr if x
	end

	def va2ra(va)
		rva2ra(va - @optheader.imagebase)
	end
	
	def readstr(offset)
		ret = ''
		while @raw[offset] != 0
			ret << @raw[offset].chr
			offset += 1
		end
		ret
	end
	
	def initialize(raw)
		@raw = raw
		offset = 0x3c
		
		offset = bin(raw[offset..offset+3])
		
		pesig = raw[offset..offset+3]
		if pesig != "PE\0\0"
			raise RuntimeError.new("Invalid PE signature!")
		end
		
		offset += 4
		@coffheader = CoffHeader.new(raw, offset)
		
		offset += 20
		@optheader = OptHeader.new(raw, offset)
		
		offset += @coffheader.sizeoptheader
		@sections = Hash.new
		@coffheader.nbsections.times {
			i = Section.new(raw, offset)
			@sections[i.name] = i
			offset += 40
		}
	end

	def exports
		class << self
			attr_reader :exports
		end
		
		edir = @optheader.dirs[:export]
		if edir and edir.size > 0 and etable = rva2ra(edir.rva) and etable < @raw.size
			@exports = ExportTable.new(raw, etable)
			if offset = rva2ra(@exports.modulenamerva)
				@exports.modulename = readstr(offset)
			end
			noff = rva2ra(@exports.nametablerva)
			ooff = rva2ra(@exports.ordtablerva)
			foff = rva2ra(@exports.addrtablerva)
			
			oseen = Hash.new
			@exports.nametablesize.times { |i|
				n = readstr(rva2ra(bin(raw[noff+4*i..noff+4*i+3])))
				oo = bin(raw[ooff+2*i..ooff+2*i+1])
				o = oo + @exports.ordinalbase
				oseen[o] = true
				f = bin(raw[foff+4*oo..foff+4*oo+3])
				fwd = nil
				if f >= edir.rva and f < edir.rva+edir.size
					fwd = readstr(rva2ra(f))
				end
				@exports.exports << Export.new(n, o, f, fwd)
			}
			@exports.addrtablesize.times { |i|
				o = i + @exports.ordinalbase
				next if oseen[o]
				n = "export_ord#{i}"
				f = bin(raw[foff+4*i..foff+4*i+3])
				fwd = nil
				if f >= edir.rva and f < edir.rva+edir.size
					fwd = readstr(rva2ra(f))
				end
				@exports.exports << Export.new(n, o, f, fwd)
			}
		end
		@exports
	end

	def imports
		class << self
			attr_reader :imports
		end

		idir = @optheader.dirs[:import]
		if idir and idir.size > 0 and itable = rva2ra(idir.rva) and itable < raw.size
			@imports = Hash.new
			loop do
				it = ImportTable.new(raw, itable)
				itable += 20
				break if it.lookuptablerva == 0
				@imports[readstr(rva2ra(it.dllnamerva))] = it
				lt = rva2ra(it.lookuptablerva)
				i = 0
				loop do
					offset = bin(raw[lt+4*i..lt+4*i+3])
					break if offset == 0
					if offset & 0x80000000 != 0
						# import by ordinal
						h = offset & 0x7fffffff
						n = "imp_ord_#{h}"
					else
						# import by name
						offset = rva2ra(offset)
						h = bin(raw[offset..offset+1])
						n = readstr(offset+2)
					end
					it.imports << Import.new(n, h, it.iatrva+4*i)
					i += 1
				end
			end
		end
		@imports
	end

	def listimports
		unless self.imports
			puts "no imports"
			return
		end
		@imports.each { |k, v|
			puts "imports from #{k}: #{v.imports.map{ |i| i.name }.sort.join ', '}"
		}
	end
		
#		if @coffheader.ptrsymboltable != 0
#			offset = @coffheader.ptrsymboltable
#			endoffset = @coffheader.ptrsymboltable + 18 * @coffheader.nbsymbols
#			@symbols = Array.new
#			while offset < endoffset
#				@symbols << Symbols.new(raw, offset)
#				offset += 18 * (1 + @symbol[-1].nb)
#			end
#			
#			offset = endoffset
#			@strings = Strings.new(raw, offset)
#		end

	def inspect
		"<PE #{@coffheader.inspect} #{@optheader.inspect} #{@sections.values.sort_by{ |s| s.virtaddr }.inspect}>"
	end
end
