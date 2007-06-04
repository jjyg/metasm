require 'metasm/exe_format/main'

module Metasm
class Shellcode < ExeFormat
	attr_accessor :sections

	def encode(binding={})
		@encoded = @sections.inject(EncodedData.new) { |sum, ed| sum << ed }
		@encoded.fixup! binding
		@encoded.fixup @encoded.binding
		@encoded.data
	end

	def self.decode(str, cpu=nil)
		sc = new
		sc.cpu = cpu
		sc.encoded = EncodedData.new
		sc.encoded << str
		sc.sections = [sc.encoded]
		sc
	end

	def self.from_program(pgm)
		sc = new
		sc.cpu = pgm.cpu
		sc.sections = pgm.sections.map { |s| s.encoded }
		sc
	end

	def to_program(base=nil)
		pgm = Program.new @cpu
		@sections.each_with_index { |s, idx|
			sec = Metasm::Section.new pgm, ".sec#{idx+1}"
			sec.encoded << s
			if base
				sec.base = base
				base += s.virtsize
			end
			pgm.sections << sec
		}
		pgm
	end
end
end
