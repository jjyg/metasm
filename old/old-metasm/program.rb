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
		@length += i.length
		@instrs << i
	end
	
	def instrs= il
		@length = 0
		@instrs = il.each { |i|
			@length += i.length
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

	def initialize(asm, mem)
		@metasm, @memory = asm, mem
		# blocks: vaddr => block starting at vaddr
		@blocks = Hash.new
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
				v += b.instrs[i].length
			}
			# more than one block may contain voff
		}
		
		@blocks[voff] = bl
	end
	
	def desasm_block(b, str, off, voff)
		vdiff = voff - off

		i = nil
		loop do
			i = @metasm.decode(str, voff - vdiff)
			b << i
			voff += i.length
			break if emule(i, voff, b)
			
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
		p = instr.mn.metaprops
		if p[:setip] or p[:modip]
			# TODO make this more generic (many args)
			e = instr.args[0].eval
			if e
				e += voff if p[:modip]
				block.to << e
				@voffsets << [e, voff - instr.length, block.offset]
			end
			if not p[:stopexec]
				block.to << voff
				@voffsets << [voff, voff - instr.length, block.offset]
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
			voff = ( o + b.length if not b.instrs[-1].mn.metaprops[:stopexec] )
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
			puts "%.8x\t%s\t%s" % [voff, hexdump(str, off, i.length).ljust(10), i]
			voff += i.length
			off  += i.length
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
