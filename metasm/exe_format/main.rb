require 'metasm/main'

module Metasm
class ExeFormat
class << self
	private
	def int_from_hash(val, hash)
		val.kind_of?(Integer) ? val : hash.index(val)
	end

	def bits_from_hash(val, hash)
		val.kind_of?(Integer) ? val : val.inject(0) { |val, bitname| val | hash.index(bitname) rescue raise("unknown bit name #{bitname.inspect}") }
	end
end
end
end
