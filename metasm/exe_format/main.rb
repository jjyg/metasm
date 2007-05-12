require 'metasm/main'

module Metasm
class ExeFormat
	def label_at(edata, offset)
		if not l = edata.export.invert[offset]
			edata.export[l = unique_label] = offset
		end
		l
	end

	def unique_label
		@uniquelabelcounter ||= 0
		labelname = "metasmintern_uniquelabel_#{self.class.name}_#{object_id}_#{@uniquelabelcounter += 1}"
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
