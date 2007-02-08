require 'metasm/exe_format/main'

module Metasm
class Raw < ExeFormat
class << self
	def encode(program)
		edata = program.sections.inject(EncodedData.new) { |edata, s| edata << s.encoded }
		start = program.label_at(edata, 0)
		edata.fixup binding=edata.export.inject({}) { |binding, (name, offset)| binding.update name => Expression[start, :+, offset] }
		raise "Unresolved external references: #{edata.reloc.values.inspect}" unless edata.reloc.empty?
		edata.data
	end
end
end
