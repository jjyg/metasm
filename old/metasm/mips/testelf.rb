require 'metasm/main'
require 'metasm/mips/main'
require 'metasm/mips/decode'
require 'metasm/mips/encode'
require 'libelf'

elf = ELF::ELF.load(ARGV[0])
puts elf.inspect
#elf.symbols.each { |s|
#	puts s.inspect
#	puts s.entries.collect { |e| e.inspect }.join("\n")
#}
#elf.relocations.each { |r|
#	puts r.inspect
#	puts r.entries.collect { |e| e.inspect }.join("\n")
#}

puts elf.find_section('.text').inspect
puts elf.find_section('.data').inspect

#offset = elf.find_section('.text').sh_offset
#size = elf.find_section('.text').sh_size

offset =  0
size = 0xFFFFFF

if elf.endian == ELF::ELFDATA2LSB then
	Metasm::MIPS.endian = :little
else
	Metasm::MIPS.endian = :big
end

text_bin = IO.read(ARGV[0], size, offset)
new = text_bin.dup
count = 0
0.step(size-4,4) do |i|
	puts i.to_s(16)+" : "+Metasm::MIPS.decode(text_bin[i, i+4]).to_s+" : "+text_bin[i, i+4].unpack("V")[0].to_s(16)
	str = Metasm::MIPS.decode(text_bin[i, i+4]).to_s
	Metasm::MIPS.parse(str).compile(new, i)
	if new[i, i+4] != text_bin[i, i+4] then
		puts i.to_s(16)+" : "+Metasm::MIPS.decode(new[i, i+4]).to_s+" : "+new[i, i+4].unpack("V")[0].to_s(16)
	#		raise RuntimeError.new("pute")
		count = count +1
	end
end
puts count
