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
		puts "Using VirtualString.realstring from:" + backtrace if $DEBUG
		raise 'realstring too big' if length > 0x1000000
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
end
