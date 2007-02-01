require 'metasm/exe_format/main'

module Metasm
class Raw < ExeFormat
	def self.pre_encode(program)
		program.sections.inject(EncodedData.new) { |edata, s| edata << s.encoded }
	end
end
end
