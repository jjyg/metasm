require 'metasm/decode'

module Metasm

class Argument
	def eval
		nil
	end
end

class Immediate < Argument
	def eval
		to_i
	end
end

# a block is a sequence of instructions executing sequencially, no jump to the middle
class InstrBlock
	# instruction sequence
	attr_reader :instrs
	attr_reader :offset, :length
	attr_accessor :name
	attr_accessor :to, :from

	def initialize offset
		@offset = offset
		@name = 'lbl_%.8X' % offset
		@instrs = []
		@length = 0
		@to = []
		@from = []
	end

	def << i
		@length += i.bin_length
		@instrs << i
	end
	
	def instrs= il
		@length = 0
		@instrs = il.each { |i|
			@length += i.bin_length
		}
	end

	# newblock is just after us
	def split(newblock, index, blocks)
		newblock.instrs = @instrs[index..-1]
		self.instrs     = @instrs[0...index]
		newblock.from   = [@offset]
		newblock.to     = @to
		
		@to.each { |t|
			next unless blocks[t]
			f = blocks[t].from
			f.delete @offset
			f << @offset + @length
		}
		
		@to             = [@offset + @length]
	end
end

class Program
	attr_reader :metasm, :memory, :blocks
	attr_accessor :pipeline_length

	def initialize(asm, mem)
		@metasm, @memory = asm, mem
		# blocks: vaddr => block starting at vaddr
		@blocks = Hash.new
		@pipeline_length = 0
		@comments = Hash.new
	end

	def desasm voffsets
		str, off, voff, b = nil
		# [voff to dasm, voff from, voff block from]
		@voffsets = voffsets.map { |o| [o, nil, nil] }
		begin
			while voffs = @voffsets.pop
				b = newblock(voffs)
				# already gone there ?
				next if b.length > 0
		
				str, off = @memory.getvaddr(voffs[0])
				next if not str or not off
				desasm_block b, str, off, voffs[0]
			end
		rescue RuntimeError
			puts 'err at %.8x : ' % voffs[0] + $!.message
			retry
		rescue Interrupt
			puts 'interrupted'
		end
	end

	# creates a new block or splits an existing one
	# TODO optimize search
	def newblock voffs
		voff, from, bfrom = *voffs
		
		if bfrom
			# bfrom may have splitted
			while blockfrom = @blocks[bfrom]
				break if from < bfrom + blockfrom.length
				bfrom += blockfrom.length
			end
		end
		
		b = @blocks[voff]
		if b
			b.from << bfrom if bfrom
			return b
		end
		
		bl = InstrBlock.new voff
		bl.from << bfrom if bfrom
		v, i = nil
		@blocks.each { |v, b|
			next if v + b.length <= voff
			b.instrs.each_index { |i|
				if v == voff
					b.split(bl, i, @blocks)
					return @blocks[voff] = bl
				elsif v > voff
					break
				end
				v += b.instrs[i].bin_length
			}
			# more than one block may contain voff
		}
		
		@blocks[voff] = bl
	end
	
	def desasm_block(b, str, off, voff)
		vdiff = voff - off

		pipeline_left = @pipeline_length
		block_finished = false

		i = nil
		loop do
			i = @metasm.decode(str, voff - vdiff)
			b << i
			voff += i.bin_length
			
			block_finished = true if emule(i, voff, b)
			if block_finished
				break if pipeline_left == 0
				pipeline_left -= 1
			end
			
			if @blocks[voff]
				# run into a block already known
				b.to << voff
				@blocks[voff].from << b.offset
				break
			end
		end
	end

	# return true if end of block
	# voff points AFTER the current instruction
	def emule(instr, voff, block)
		p = instr.op.metaprops
		if p[:setip] or p[:modip]
			# TODO make this more generic (many args ?)
			e = instr.args[0].eval
			if e
				e += voff if p[:modip]
				@comments[voff-instr.bin_length] = "=> %.8x" % e
				block.to << e
				@voffsets << [e, voff - instr.bin_length, block.offset]
			end
			if not p[:stopexec]
				block.to << voff
				@voffsets << [voff, voff - instr.bin_length, block.offset]
			end
			true
		elsif p[:stopexec]
			true
		else
			false
		end
	end

	def dump_source
		voff, o, b = nil
		@blocks.sort.each { |o, b|
			next if b.instrs.empty?
			
			puts if voff != o
			
			dump_block(o, b)
			voff = ( o + b.length if not b.instrs.last.op.metaprops[:stopexec] )
		}
	end

	def dump_block(voff, b)
		farxrefs = b.from.map { |f| f if f + @blocks[f].length != voff }.compact
		if not farxrefs.empty?
			l = (b.name + ':').ljust 40
			l << 'xrefs '
			l << ((['%.8x']*farxrefs[0..3].length).join ', ') % farxrefs[0..3]
			l << ', ...' if farxrefs.length > 4
			puts l
		end
		
		str, off = @memory.getvaddr(voff)
		b.instrs.each { |i|
			puts "%.8x\t%s\t%s%s" % [voff, hexdump(str, off, i.bin_length).ljust(10), i.to_s.ljust(20), ("; "+@comments[voff] if @comments[voff])]
			voff += i.bin_length
			off  += i.bin_length
		}
	end
end

def hexdump(str, start, len)
	ret = ''
	len.times { |i|
		ret << '%.2x' % str[start+i]
	}
	ret
end

end
