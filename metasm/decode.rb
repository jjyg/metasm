require 'metasm/main'

module Metasm

class DecodedInstruction
	attr_accessor :bin_length, :instruction, :opcode
end

class Opcode
	attr_accessor :bin_mask
end

class CPU
	def decode(program, edata)
		@bin_lookaside ||= build_bin_lookaside
		di = DecodedInstruction.new
		di.instruction = Instruction.new self
		pre_ptr = edata.ptr
		decode_findopcode(program, edata, di) rescue di.opcode = nil
		decode_instruction(program, edata, di) if di.opcode rescue di.opcode = nil
		di.bin_length = edata.ptr - pre_ptr
		di
	end

	def emu_backtrace(di, off, value)
	end

	def get_jump_targets(pgm, di, off)
		[]
	end
end

class InstructionBlock
	# list of DecodedInstructions
	# list of addresses (excluding continued ?)
	# from = list of addresses of instructions (call/jmp), also addr of normal instruction when call flow continues to this block
	# to = list of addresses of instructions called, does include normal flow transitions (no jump)
	attr_accessor :list, :from, :to
	# list of addr of instruction for which backtrace was needed, and passed by us (an instruction in the end of this block should appear here too, in case of a later split)
	attr_accessor :backtracked_for

	def initialize
		@list = []
		@from = []
		@to   = []

		@backtracked_for = []
	end
end

class Indirection
	# Expression + type
	attr_accessor :target, :type

	def initialize(target, type)
		@target, @type = target, type
	end

	def reduce
		Indirection.new(Expression[@target.reduce], @type)
	end
	alias reduce_rec reduce

	def bind(h)
		h.fetch(self, Indirection.new(@target.bind(h), @type))
	end

	def ==(o)
		o.class == self.class and [o.target, o.type] == [@target, @type]
	end
	def hash
		[@target, @type].hash
	end
	alias eql? ==
end

class Program
	attr_reader :block
	# decodes instructions from an entrypoint, (tries to) follows code flow
	# TODO delay slot
	def desasm(entrypoint = 0)
		@block ||= {}	# addr => list of decodedinstr
		@decoded ||= {}	# addr => block start addr

		curblock = nil
		s = @sections.first
		s_start = s.base || 0
		s_end = s_start + s.encoded.virtsize

		# [offset to disasm, addr of instruction pointing there]
		offsets = [[entrypoint, nil]]
		while foo = offsets.pop
			off = foo[0]
			from = foo[1]

			# resolve labels
			if off.kind_of? Integer
				if not s or off < s_start or off >= s_end
					next if not s = sections.find { |s| off >= (s_start = s.base || 0) and off < (s_end = s_start + s.encoded.virtsize) }
				end
			else
				if not s or not s.encoded.export[off]
					next if not s = sections.find { |s| s.encoded.export[off] }
					s_start = s.base || 0
					s_end = s_start + s.encoded.virtsize
				end
				off = s_start + s.encoded.export[off]
			end

			# already gone there
			if @decoded[off]
				if curblock
					@block[curblock].to |= [off]
					from ||= @block[curblock].list[0..-2].inject(curblock) { |off, di| off + di.bin_length }
					curblock = nil
				end

				desasm_split_block(@decoded[off], off) if not @block[off]

				if from
					@block[@decoded[off]].from |= [from]
					@block[@decoded[off]].backtracked_for.each { |targetoff|
						di = @block[@decoded[targetoff]].list.inject(@decoded[targetoff]) { |o, di|
							break di if o == targetoff
							o + di.bin_length
						}
#puts "\nrebacktracking to #{'%08x' % targetoff} for #{di.instruction}"
						targets = resolve_jump_target(di, targetoff)
						offsets.unshift(*targets.reject { |t|
							@block[@decoded[targetoff]].to.include? t and @block[t] and @block[t].from.include? targetoff
						}.map { |t| [t, targetoff] })
						@block[@decoded[off]].to |= targets
					}
				end

				next
			end

			# decode the instruction
			s.encoded.ptr = off - s_start
			di = @cpu.decode self, s.encoded

			# start a new block if needed
			if not curblock
				@block[curblock = off] = InstructionBlock.new
				@block[curblock].from |= [from] if from
			end

			# mark this address as already decoded
			@decoded[off] = curblock
			@block[curblock].list << di

			# invalid opcode
			if not di.opcode
				curblock = nil
				next
			end
#puts "decoded at #{'%08x' % off} #{di.instruction}"

			# jump/call
			if di.opcode.props[:setip]
				targets = resolve_jump_target(di, off)

				offsets.unshift(*targets.map { |t| [t, off] })

				# end curblock
				@block[curblock].to |= targets
				@block[curblock].to |= [off + di.bin_length] if not di.opcode.props[:stopexec]
				curblock = nil
			end

			if di.opcode.props[:stopexec]
				# XXX callback to detect procedures ?
				curblock = nil
			else
				offsets << [off + di.bin_length, off]
			end
		end

		# labels only allowed at start of a block
		@sections.each { |s|
			s.encoded.export.values.each { |off|
				off += s.base || 0
				desasm_split_block(@decoded[off], off) if @decoded[off] and not @block[off]
			}
		}
	end

	# split the block (starting at oldaddr) at newaddr
	def desasm_split_block(oldaddr, newaddr)
		@block[newaddr] = InstructionBlock.new
		@block[newaddr].to = @block[oldaddr].to
		@block[oldaddr].to = [newaddr]
		@block[newaddr].from = [oldaddr]
		@block[newaddr].backtracked_for.concat @block[oldaddr].backtracked_for
		
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

	def resolve_jump_target(di, off)
		# returns either a String (target == label) or an Integer (address) on success, or nil
		check_target = proc { |target|
			if target.kind_of? String or target.kind_of? Integer
				target
			elsif target.kind_of? Expression or target.kind_of? Indirection
				target = target.reduce
				if target.kind_of? Integer
					target
				elsif target.kind_of? Expression and target.op == :+ and not target.lexpr
					check_target[target.rexpr]
				elsif target.kind_of? Indirection
					break if not t = check_target[target.target]
					if t.kind_of? String
						s = @sections.find { |s| s.encoded.export[t] }
						break if not s
						s.encoded.ptr = s.encoded.export[t]
					else
						s = @sections.find { |s| s.base <= t and s.base + s.encoded.virtsize > t }
						break if not s
						s.encoded.ptr = t - s.base
					end
					check_target[s.encoded.decode_imm(target.type, @cpu.endianness)]
				end
			end
		}

		orig_off = off
		targets = @cpu.get_jump_targets(self, di, off)
		targets_found = targets.map { |t| check_target[t] }

		trace = []
		result = []
		# XXX highly suboptimal
		# [max_depth, addr of last di checked, block, index in block.list of last di checked, target to resolve]
		# TODO
		# when marking a subfunc, check all paths forward
		# when find a subfunc return, mark the path in the subfunc 
		#  (to allow foo: jmp retloc ; bar: jmp retloc retloc: ret to be both recognized as subfuncs 
		#   otherwise when dasm bar, 'retloc' is marked as 'already dasmed' and no subfunc detection takes place)
		targets.zip(targets_found).each { |t, tf|
			if tf
				result |= [tf]
			else
				trace << [20, off, @block[@decoded[off]], @block[@decoded[off]].list.index(di), t]
			end
		}

		if not trace.empty?
			@block[@decoded[orig_off]].backtracked_for |= [orig_off]
		end

		while foo = trace.pop
			depth, off, block, idx, target = foo

			next if depth == 0

			if idx == 0
				block.from.each { |f|
#puts "backtracking : (#{depth}) up to #{'%08x' % f}"
					b = @block[@decoded[f]]
					trace << [depth, f + b.list.last.bin_length, b, b.list.length, target]
					b.backtracked_for |= [orig_off]
				}
			else
				di = block.list[idx-1]
				off -= di.bin_length
#puts "backtracking : eval #{target} in #{di.instruction}"
				target = @cpu.emu_backtrace(di, off, target)
				if t = check_target[target]
#puts " found #{t.inspect}#{' (%08x)' % t if t.kind_of? Integer}"
					result |= [t]
					# TODO
					# mark_as_subfunc(curblock.to) if di.opcode.props[:startsubfunc]
				elsif target and target = target.reduce
#puts " continuing with #{target}"
					# target.reduce is either an Expression or an Indirection, an Integer would have been caught by check_target
					trace << [depth-1, off, block, idx-1, target]
				end
			end
		end

		result
	end
	
	def make_label(addr, pfx = 'metasmintern_uniquelabel')
		s_start = nil
		return addr if not s = @sections.find { |s|
			s_start = s.base || 0
			addr >= s_start and addr < s_start + s.encoded.virtsize
		}
		if not label = s.encoded.export.invert[addr - s_start]
			label = "#{pfx}_#{'%x' % addr}"
			s.encoded.export[label] = addr - s_start
		end
		label
	end

	def blocks_to_source
		# @block -> @source, fill gaps with Data

		# optimization: pop instead of shift
		sections = @sections.sort_by { |s| s.base || 0 }.reverse
		blocks = @block.sort.reverse

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
		end
	end

	def read(len)
		str = ''
		if @ptr < @data.length
			str << @data[@ptr, len]
		end
		@ptr += len
		str.ljust(len, "\0")
	end
	
	# returns an Expression on relocation, or a Numeric
	def decode_imm(type, endianness)
		if rel = @reloc[@ptr]
			if rel.type == type and rel.endianness == endianness
				@ptr += Expression::INT_SIZE[type]/8
				return rel.target
			end
			puts "W: Immediate type/endianness mismatch, ignoring relocation #{rel.target.inspect}"
		end
		Expression.decode_imm(read(Expression::INT_SIZE[type]/8), type, endianness)
	end
end

class Expression
	def self.decode_imm(str, type, endianness)
                val = 0
                case endianness
                when :little : str.reverse
		when :big : str
		end.unpack('C*').each { |b| val = (val << 8) | b }
		val = val - (1 << (INT_SIZE[type])) if type.to_s[0] == ?i and val >> (INT_SIZE[type]-1) == 1	# XXX booh
		val
	end

end
end
