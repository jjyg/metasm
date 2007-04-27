require 'metasm/main'

module Metasm
class Pic16c < CPU
	def initialize(endianness = :big)
		super()
		@endianness = endianness
		init
	end
end
end
