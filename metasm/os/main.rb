module Metasm
# a virtual string, whose content is the memory of some other process
# may be writeable, but its size cannot change
# unknown methods falls back to a frozen full copy of the virtual content
class VirtualString
	def [](from, len=nil)
		if not len and from.kind_of? Range
			b = from.begin
			e = from.end
			b = 1 + b + length if b < 0
			e = 1 + e + length if e < 0
			len = e - b
			len += 1 if not from.exclude_end?
			from = b
		end
		from = 1 + from + length if from < 0

		return nil if from > length
		len = length - from if len and from + len > length

		read_range(from, len)
	end

	def []=(from, len, val=nil)
		raise TypeError, 'cannot modify frozen virtualstring' if frozen?

		if not val
			val = len
			len = nil
		end
		if not len and from.kind_of? Range
			b = from.begin
			e = from.end
			b = 1 + b + length if b < 0
			e = 1 + e + length if e < 0
			len = e - b
			len += 1 if not from.exclude_end?
			from = b
		elsif not len
			len = 1
			val = val.chr
		end
		from = 1 + from + length if from < 0

		raise IndexError, 'Index out of string' if from > length
		raise IndexError, 'Cannot modify virtualstring length' if val.length != len or from + len > length

		write_range(from, len, val)
	end

	def realstring
		puts "Using VirtualString.realstring from:", caller if $DEBUG
		raise 'realstring too big' if length > 0x1000000
	end
	def to_str
		realstring	# for bad people checking respond_to? :to_str (like String#<<)
	end

	def method_missing(m, *args, &b)
		if ''.respond_to? m
			realstring.freeze.send(m, *args, &b)
		else
			super
		end
	end

	# avoid triggering realstring from method_missing if possible
	def length
		raise "implement this!"
	end

	def empty?
		length == 0
	end

	# heavily used in to find 0-terminated strings
	def index(chr, base=0)
		if i = self[base, 64].index(chr) or i = self[base, 4096].index(chr)
			base + i
		else
			realstring.index(chr, base)
		end
	end
end

class VirtualFile < VirtualString
	# returns a new VirtualFile of the whole file content, with chosen open mode
	def self.read(path, mode='rb')
		File.open(path, mode) { |fd| new fd }
	end

	attr_accessor :fd, :addr_start, :length,
		:curpage, :curstart, :invalid
	# creates a new virtual mapping of a section of the file
	# the file descriptor must be seekable
	def initialize(fd, addr_start = 0, length = nil)
		@fd = fd.dup
		@addr_start = addr_start
		if not @length = length
			@fd.seek(0, File::SEEK_END)
			@length = @fd.tell - @addr_start
		end
		@invalid = true
	end

	def dup
		self.class.new(@fd, @addr_start, @length)
	end

	# reads the data from the current cached page, updating it if necessary
	def read_range(from, len)
		from += @addr_start
		get_page(from) if @invalid or @curstart < from or @curstart + @curpage.length >= from
		if not len
			@curpage[from - @curstart]
		elsif len <= 4096
			from -= @curstart
			s = @curpage[from, len]
			if from + len > 4096	# request crosses a page boundary
				get_page(@curstart + 4096)
				s << @curpage[0, from + len - 4096]
			end
			s
		else
			# big request: return a new virtual page
			self.class.new(@fd, from, len)
		end
	end

	# writes data, invalidating the cache
	def write_range(from, len, val)
		@invalid = true
		@fd.pos = @addr_start + from
		@fd.write val
	end

	# reads an aligned page from the file, at file offset addr (ignores @addr_start)
	def get_page(addr)
		@invalid = false
		@curstart = addr & 0xffff_ffff_ffff_f000
		@fd.pos = @curstart
		@curpage = @fd.read 4096
	end

	# returns the full content of the file
	def realstring
		super
		@fd.pos = @addr_start
		@fd.read(@length)
	end
end
end
