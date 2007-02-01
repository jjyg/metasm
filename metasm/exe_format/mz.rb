require 'metasm/exe_format/main'

module Metasm
class MZ < ExeFormat
	# returns an array of EncodedData, with interdependency in relocations
	# array == [header, reloc, body]
	# header must come first, reloc is empty (unsupported for now)
	def self.pre_encode(program, opts={})
		header = EncodedData.new

		encode = proc { |*expr|
			header << Expression[*expr].encode(:u16, :little)
		}

		start_header = program.new_unique_label
		end_header = program.new_unique_label
		start_reloc = program.new_unique_label
		start_body = program.new_unique_label
		end_body = program.new_unique_label

		header << 'MZ'
		encode[ [end_body,    :-, start_header], :%, 512]		# last page bytes used
		encode[ [[end_body,   :-, start_header], :+, 511], :/, 512]	# number of pages
		encode[ [end_header,  :-, start_reloc],  :/,   4]		# number_of_relocations
		encode[ [[end_header, :-, start_header], :+,  15], :/,  16]	# header_size_paragraph

		encode['min_bss_paragraphs']
		encode['max_bss_paragraphs']
		encode['ss_offset']
		encode['sp']
		encode['checksum']
		encode['ip']
		encode['cs']

		# relocation table offset
		encode[start_reloc, :-, start_header]
		encode['overlay']
		header.align_size 16
		header.export[start_header] = 0
	
		# array of couples (offset within segment, segment)
		# what does it represent ?
		reloc = [].inject(EncodedData.new) { |reloc, (off, seg)|
			reloc << Expression.encode_immediate(off, :u16, :little) << Expression.encode_immediate(seg, :u16, :little)
		}
		reloc.align_size 16
		reloc.export[start_reloc] = 0
		reloc.export[end_header] = reloc.virtsize

		entrypoint = opts.delete('entrypoint') || 'start'

		body = program.sections.inject(EncodedData.new) { |body, sec| body << sec.encoded }
		body.align_size 2
		body.fill
		body.export.update start_body => 0, end_body => body.virtsize
		body.export[entrypoint] ||= 0
		body.fixup body.export.inject({}) { |binding, (name, offset)| binding.update name => Expression[[start_body, :-, end_header], :+, offset] }, true

		header.fixup({'overlay' => 0,				# main executable
			'min_bss_paragraphs' => 0,
			'max_bss_paragraphs' => 0,
			'checksum' => 0,
			'cs' => 0, 'ss_offset' => 0,
			'ip' => Expression[entrypoint, :-, end_header], 'sp' => Expression[start_body, :-, start_header]}, true)
		
		[header, reloc, body]
	end

	def self.encode_fix_checksum(str)
		mzlen = str[4, 2].unpack('v').first * 512 + str[2, 2].unpack('v').first - 512
		sum = str[0, mzlen].unpack('v*').inject { |a, b| a+b }
		str[18, 2] = [str[18, 2].unpack('v').first - sum].pack('v')
	end

	def self.encode(program, opts={})
		edata = EncodedData.new
		pre_encode(program, opts).each { |ed| edata << ed }
		start = program.label_at edata, 0
		edata.fixup edata.export.inject({}) { |binding, (name, offset)| binding.update name => Expression[start, :+, offset] }
		raise EncodeError, 'MZ encode: pending relocations' if not edata.reloc.empty?
		encode_fix_checksum edata.data
		edata.data
	end
end
end
