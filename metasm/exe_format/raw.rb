require 'metasm/exe_format/main'

module Metasm
class Raw < ExeFormat
class << self
	def encode(program, binding={})
		edata = program.sections.inject(EncodedData.new) { |edata, s| edata << s.encoded }
		start = program.label_at(edata, 0)
		edata.fixup edata.export.inject(binding) { |binding, (name, offset)| binding.update name => Expression[start, :+, offset] }
		raise "Unresolved external references: #{edata.reloc.values.inspect}" unless edata.reloc.empty?
		edata.data
	end

	def decode(cpu, data, loadaddr = 0)
		pgm = Program.new cpu
		pgm.sections << Section.new(pgm, '.text')
		pgm.sections.last.encoded << data
		pgm.sections.last.base = loadaddr
		pgm
	end
end
end
end
