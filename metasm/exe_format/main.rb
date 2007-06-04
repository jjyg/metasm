require 'metasm/main'

module Metasm
class ExeFormat
	attr_accessor :cpu, :encoded

	def label_at(edata, offset, base = '')
		if not l = edata.export.invert[offset]
			edata.export[l = new_label(base)] = offset
		end
		l
	end

	def new_label(base = '')
		base = base.dup
		k = (base << '_uniquelabel_' << base.object_id.to_s(16)).freeze
		(@unique_labels_cache ||= []) << k	# prevent garbage collection, this guarantees uniqueness (object_id)
		k
	end

	# if hash = {1 => 'toto', 2 => 'tata'}
	# 'toto' => 1, 42 => 42, 'tutu' => raise
	def int_from_hash(val, hash)
		val.kind_of?(Integer) ? val : hash.index(val) or raise "unknown constant #{val.inspect}"
	end
	# ['toto', 'tata'] => 3, 'toto' => 2, 42 => 42
	def bits_from_hash(val, hash)
		val.kind_of?(Array) ? val.inject(0) { |val, bitname| val | int_from_hash(bitname, hash) } : int_from_hash(val, hash)
	end
	# 1 => 'toto', 42 => 42, 'tata' => 'tata', 'tutu' => raise
	def int_to_hash(val, hash)
		val.kind_of?(Integer) ? hash.fetch(val, val) : (hash.index(val) ? val : raise("unknown constant #{val.inspect}"))
	end
	# 5 => ['toto', 4]
	def bits_to_hash(val, hash)
		(val.kind_of?(Integer) ? (hash.find_all { |k, v| val & k == k and val &= ~k }.map { |k, v| v } << val) : val.kind_of?(Array) ? val.map { |e| int_to_hash(e, hash) } : [int_to_hash(val, hash)]) - [0]
	end
end
end
