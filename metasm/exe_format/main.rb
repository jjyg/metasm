require 'metasm/main'

module Metasm
class ExeFormat
class << self
	def int_from_hash(val, hash)
		val.kind_of?(Integer) ? val : hash.index(val) or raise "unknown constant #{val.inspect}"
	end

	def bits_from_hash(val, hash)
		val.kind_of?(Array) ? val.inject(0) { |val, bitname| val | int_from_hash(bitname, hash) } : int_from_hash(val, hash)
	end

	def bits_to_hash(val, hash)
		val.kind_of?(Integer) ? hash.find_all { |k, v| val & k == k }.map { |k, v| v } : hash[val] || val
	end
end
end
end
