#!/usr/bin/ruby

require 'metasm/ia32/decode'
require 'metasm/desasm'
#require 'metasm/ia32/emu'
require 'libpe'

include Metasm

class PE
	def getvaddr(voff)
		ra = va2ra voff
		[@raw, ra] if ra
	end
end

class PE_Ia32_Program < Program
end

pe = PE.load ARGV[0]

names = { 'entrypoint' => pe.rva2va(pe.optheader.entrypoint) }

if pe.exports
	pe.exports.exports.each { |e|
		names[e.name] = pe.rva2va e.rva
	}
end

if ARGV[1]
	offsets = [names[ARGV[1]] || Integer(ARGV[1])]
else
	offsets = names.values
end
#p names
p offsets.map { |o| "%.8X"%o } if $DEBUG

pg = Program.new(Ia32, pe)
pg.desasm(offsets)

names.sort.each { |k, v|
	next unless pg.blocks[v]
	pg.blocks[v].name = k
}

pg.dump_source

__END__

TODO: use this

#class PE_Ia32_Program < Ia32_Program
#	def emule(instr, voff, block)
#		if (instr.name == 'mov' and instr.args[0].class == Ia32_ModRM and a0 == 'fs:[0]'
#			e = emule_backtrace([arg1])
#			@voffsets << e if e
#		else
#			super
#		end
#	end


# PE import resolution
importmap = Hash.new
k, v, i = nil
pe.imports.each { |k, v|
	v.imports.each { |i|
		importmap[pe.optheader.imagebase + i.rva] = '%s!%s' % [k, i.name]
	}
} if pe.imports

Immediate.module_eval '@@importmap = importmap'
class Immediate
	alias oldtos to_s
	def to_s(*arg)
		@@importmap[@val] or oldtos(*arg)
	end
end

Ia32_ModRM.module_eval '@@importmap = importmap'
Ia32_ModRM.module_eval '@@pe = pe'
class Ia32_ModRM
	def eval(*args)
		# solve [imm]
		if not @b and not @i and not @imm
			@imm.signed = false
			of = @imm.eval

			if not @@importmap[of]
			# do not try to follow jumps to imports
			if of = @@pe.rva2va(of - @@pe.optheader.imagebase)
				Immediate.decode(@@pe.raw, of, @ptsz)
			end
			end
		end
	end
end

# disassembler starting points
lbl = Hash.new

o = pe.optheader.imagebase + pe.optheader.entrypoint
lbl[o] = Label.new(o, 'entrypoint')

if pe.exports
	pe.exports.exports.each { |e|
		next if e.forwarder
		o = pe.optheader.imagebase + e.rva
		lbl[o] = Label.new(o, e.name)
	}
end

if ARGV[1]
	re = Regexp.new ARGV[1], Regexp::IGNORECASE
	lbl = lbl.map { |k, v| v if v.name =~ re }.compact
	if lbl.empty?
		puts 'No such function'
		puts pe.exports.exports.map { |e| e.name }.sort.join(', ') if pe.exports
		exit
	end
else
	lbl = lbl.values
end

# import propagation (call x ; x: jmp [import] => call import)
indjmp = Ia32_Metassembler.opcodes.find { |o| o.name == 'jmp' and o.fields[:modrm] }

b, o, a = nil
masm.blocks.each_value { |b|
	if not b.labels[0].named
		if o = b.instrs[0] and o.op == indjmp
			a = o.args[0]
			if a.class == Ia32_ModRM and not a.i and not a.b and a = importmap[a.imm.to_i]
				b.labels[0].name = a.sub /^.*!/, 'iat_'
			end
		end
	end
}

