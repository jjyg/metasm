require 'metasm/main'

module Metasm

class DecodedInstruction
	attr_accessor :bin_length, :instruction, :opcode
end

class CPU
	def decode(program, edata)
		@bin_lookaside ||= build_binlookaside
		di = DecodedInstruction.new
		di.instruction = Instruction.new
		pre_ptr = edata.ptr
		decode_findopcode(program, edata, di)
		decode_instr(program, edata, di)
		di.bin_length = edata.ptr - pre_ptr
		di
	end
end

class InstructionBlock
	# list of DecodedInstructions
	# list of addresses (excluding continued ?)
	attr_accessor :list, :from, :to

	def initialize
		@list = []
		@from = []
		@to   = []
	end
end

class Program
	# decodes instructions from entrypoints, (tries to) follows code flow
	def desasm(entrypoints = [0])
		entrypoints = [entrypoints] if not entrypoints.kind_of? Array

		@blocks ||= {}	# addr => list of decodedinstr
		@decoded ||= {}	# addr => block start addr

		curblock = nil

		while ep = entrypoints.pop
			# resolve labels
			if ep.kind_of? Integer
				s = sections.find { |s| (s.base || 0) >= ep and (s.base || 0) + s.encoded.virtsize < ep }
			else
				next unless s = sections.find { |s| s.export[ep] }
				ep = s.export[ep]
			end

			# already gone there
			if @decoded[ep]
				if curblock
					@block[curblock].to << ep
					curblock = nil
				end

				desasm_split_block(@decoded[ep], ep) if not @block[ep]

				next
			end

			# decode the instruction
			s.encoded.ptr = ep - (s.base || 0)
			di = @cpu.decode self, s.encoded

			# start a new block if needed
			if not curblock or s.export.invert[ep]
				curblock = ep
				@block[curblock] = InstructionBlock.new
			end

			# mark this address as already decoded
			@decoded[ep] = curblock
			@block[curblock].list << di

			# check what's the next addr to disasm
			# TODO delay slot

			# invalid opcode
			if not di.opcode
				curblock = nil
				next
			end

			# jump/call
			if di.opcode.props[:setip]
				targets = resolve_jump_target(di, ep)

				entrypoints.unshift(*targets)

				# end curblock
				@block[curblock].to = targets
				@block[curblock].to << (ep + di.bin_length) if not di.opcode.props[:stopexec]
				curblock = nil
			end

			if di.opcode.props[:stopexec]
				# XXX callback to find procedures ?
				curblock = nil
			else
				entrypoints << (ep + di.bin_length)
			end
		end
	end

	# split the block (starting at oldaddr) at newaddr
	def desasm_split_block(oldaddr, newaddr)
		@block[newaddr] = InstructionBlock.new
		@block[newaddr].to = @block[oldaddr].to
		@block[oldaddr].to = [newaddr]
		@block[newaddr].from = [oldaddr]
		
		# walk the block to find the splitting instruction
		curaddr = oldaddr
		i = nil
		@block[oldaddr].list.each_with_index { |di, i|
			break if curaddr == newaddr
			curaddr += di.bin_length
		}
		
		@block[newaddr].list = @block[oldaddr].list[i..-1]
		@block[oldaddr].list[i..-1] = []
		
		# fixup @decoded to point to the new block
		curaddr = newaddr
		@block[newaddr].list.each { |di|
			@decoded[curaddr] = newaddr
			curaddr += di.bin_length
		}
	end
	
	def blocks_to_source
		# @blocks -> @source, fill gaps with Data

		sections = @sections.sort_by { |s| s.base || 0 }.reverse
		blocks = blocks.sort.reverse

		# optimization: pop instead of shift
		while cursect = sections.pop
			cursect.source.clear
			curoff = curbase = cursect.base || 0
			labels = cursect.encoded.export.sort.reverse
			off, block = blocks.pop

			if block and off < curbase + cursect.encoded.data.length
				if off > curoff
					# TODO split on relocs/labels
					cursect.source << Data.new(:db, cursect.encoded.data[curoff...off])
				end

				# XXX quickfix for interlaced code
				labels.pop while labels.last and labels.last[1] < off

				while labels.last and labels.last[1] == off
					cursect.source << Label.new(labels.pop[0])
				end

				block.list.each { |di|
					next if not di.opcode
					cursect.source << di.instruction
					curoff += di.bin_length
				}
			else
				blocks << [off, block]

				# no more blocks till end of this section: dump as Data

				# dump data
				if curoff < curbase + cursect.encoded.data.length
					cursect.source << Data.new(:db, cursect.encoded.data[curoff..-1]) if curoff < curbase + cursect.encoded.data.length
					curoff = curbase + cursect.encoded.data.length
				end
				# dump uninitialized data
				if curoff < curbase + cursect.encoded.virtsize
					cursect.source << Data.new(:db, Data.new(:db, Data::Uninitialized), curstart + cursect.encoded.virtsize - curoff)
					curoff = curbase + cursect.encoded.virtsize
				end
			end
		end
	end
end

class EncodedData
	attr_accessor :ptr
	def get_byte
		@ptr += 1
		if @ptr <= @data.length
			@data[ptr-1]
		elsif @ptr <= @virtsize
			0
		# else raise
		end
	end
end

class Expression
	# returns an immediate or an Expression (if relocated)
	def self.decode(edata, type, endianness)
		if rel = edata.reloc[edata.ptr]
			# XXX allow :i32 for :u32 ?
			if rel.type == type or rel.endianness == endianness
				edata.ptr += INT_SIZE[type]
				return rel.target
			end
			puts "immediate type/endianness mismatch, ignoring relocation #{rel.target.inspect}"
		end

                val = 0
                case endianness
                when :little : (INT_SIZE[type]/8).times { |i| val |= edata.get_byte << (8*i) }
                when :big    : (INT_SIZE[type]/8).times { val <<= 8 ; val |= edata.get_byte  }
                else raise SyntaxError, "Unsupported endianness #{endianness.inspect}"
                end

		val = val - (1 << (INT_SIZE[type])) if type.to_s[0] == ?i and val >> (INT_SIZE[type]-1) == 1	# XXX check

		val
	end
end
end
