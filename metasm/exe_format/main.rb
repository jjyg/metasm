require 'metasm/main'

module Metasm
	class ExeFormat
		# returns a string 
		def self.encode(program)
			edata = pre_encode(program)
			start = program.label_at(edata, 0)
			edata.fixup binding=edata.export.inject({}) { |binding, (name, offset)| binding.update name => Expression[start, :+, offset] }
			raise "Unresolved external references: #{edata.reloc.values.inspect}" unless edata.reloc.empty?
			edata.data
		end
	end
end
