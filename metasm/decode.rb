#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'


module Metasm

# holds information for decoded instructions: the original opcode, a pointer to the InstructionBlock, etc
class DecodedInstruction
	# the instance of InstructionBlock this di is into
	attr_accessor :block
	# our offset (in bytes) from the start of the block
	attr_accessor :block_offset
	# the disassembled data
	attr_accessor :instruction, :opcode
	# our, length in bytes
	attr_accessor :bin_length
	# an arbitrary string
	attr_accessor :comment
	# a cache of the binding used by the backtracker to emulate this instruction
	attr_accessor :backtrace_binding

	def initialize(cpu)
		@instruction = Instruction.new cpu
		@bin_length = 0
	end

	def address
		Expression[@block.address, :+, @block_offset].reduce
	end

	def to_s
		"#{Expression[address]} #{instruction}"
	end
end

# defines a class method attr_accessor_list to declare an attribute that may have multiple values
module AccessorList
	# defines an attribute that may be a value or an array, along with its accessors
	# used to optimize ruby's memory usage with many objects that have mostly single-value attributes
	# the values must not be arrays !
	def attr_accessor_list(*a)
		a.each { |a|
			# XXX no way to yield from a define_method block...
			class_eval <<EOS
	attr_accessor :#{a}

	def each_#{a}
		case #{a}
		when nil
		when ::Array: @#{a}.each { |b| yield b }
		else yield @#{a}
		end
	end

	def add_#{a}(b)
		case #{a}
		when nil: @#{a} = b
		when b
		when ::Array: @#{a} |= [b]
		else @#{a} = [@#{a}, b]
		end
	end
EOS
		}
	end
end

# holds information on a backtracked expression near begin and end of instruction blocks (#backtracked_for)
class BacktraceTrace
	# offset of the instruction in the block from which rebacktrace should start (use with subfuncret bool)
	# exclude_instr is a bool saying if the backtrace should start at block_offset or at the preceding instruction
	# optional: if absent, expr is to be rebacktracked when a new codepath arrives at the beginning of the block
	attr_accessor :block_offset, :subfuncret, :exclude_instr
	# address of the instruction that initiated the backtrace
	attr_accessor :origin
	# the Expression to backtrace at this point
	attr_accessor :expr
	# length of r/w xref (in bytes)
	attr_accessor :len
	# :r/:w/:x
	attr_accessor :type

	def initialize(expr, origin, type, len=nil)
		@expr, @origin, @type = expr, origin, type
		@len = len if len
	end

	def hash ; [origin, expr].hash ; end
	def eql?(o)
		o.class == self.class and
		[block_offset, subfuncret, origin, expr, len, type] ==
		 [o.block_offset, o.subfuncret, o.origin, o.expr, o.len, o.type]
	end
	alias == eql?
end

# a cross-reference, tracks read/write/execute memory accesses by decoded instructions
class Xref
	# :r/:w/:x
	attr_accessor :type
	# length of r/w (in bytes)
	attr_accessor :len
	# address of the instruction responsible of the xref
	attr_accessor :origin
	# XXX list of instructions intervening in the backtrace ?

	def initialize(type, origin, len=nil)
		@origin, @type = origin, type
		@len = len if len
	end

	def hash ; @origin.hash ; end
	def eql?(o) o.class == self.class and [type, len, origin] == [o.type, o.len, o.origin] end
	alias == eql?
end

# holds a list of contiguous decoded instructions, forming an uninterrupted block (except for eg CPU exceptions)
# most attributes are either a value or an array of values, use the associated iterator.
class InstructionBlock
	extend AccessorList

	# address of the first instruction
	attr_accessor :address
	# pointer to raw data
	attr_accessor :edata, :edata_ptr
	# list of DecodedInstructions
	attr_accessor :list
	# address of instructions giving control directly to us
	# includes addr of normal instruction when call flow continues to us past the end of the preceding block
	# does not include addresses of subfunction return instructions
	attr_accessor_list :from_normal
	# address of instructions called/jumped to
	# does not include addresses of subfunctions called
	attr_accessor_list :to_normal
	# address of an instruction that calls a subfunction which returns to us
	attr_accessor_list :from_subfuncret
	# address of instruction executed after a called subfunction returns
	attr_accessor_list :to_subfuncret
	# addresses of subfunctions called
	attr_accessor_list :subfunction
	# array of BacktraceTrace
	# when a new code path comes to us, it should be backtracked for the values of :r/:w/:x using btt with no block_offset
	# for internal use only (block splitting): btt with a block_offset
	attr_accessor :backtracked_for

	def initialize(address, edata, edata_ptr=edata.ptr)
		@address = address
		@edata, @edata_ptr = edata, edata_ptr
		@list = []
		@backtracked_for = []
	end

	# splits the current block into a new one with all di from offset off (di.block_offset) to end
	# caller is responsible for rebacktracing new.bt_for to regenerate correct old.bt.b_off/new.bt
	def split(off)
		raise "invalid split #{off}" if off == 0 or not idx = @list.index(@list.find { |di| di.block_offset == off })
		new_b = self.class.new(Expression[@address, :+, off].reduce, @edata, @edata_ptr + off)
		new_b.add_di @list.delete_at(idx) while @list[idx]
		new_b.add_from_normal @list.last.address
		new_b.to_normal,     @to_normal =     to_normal,     new_b.to_normal
		new_b.to_subfuncret, @to_subfuncret = to_subfuncret, new_b.to_subfuncret
		new_b.subfunction,   @subfunction =   subfunction,   new_b.subfunction
		@backtracked_for.delete_if { |btt|
			if btt.block_offset and btt.block_offset >= off
				btt.block_offset -= off
				new_b.backtracked_for << btt
				true
			end
		}
		new_b
	end

	# adds a decodedinstruction to the block list, updates di.block and di.block_offset
	def add_di(di)
		di.block = self
		di.block_offset = (@list.empty? ? 0 : (@list.last.block_offset + @list.last.bin_length))
		@list << di
	end

	# adds an address to the from_normal/from_subfuncret list
	def add_from(addr, subfuncret=false)
		if subfuncret: add_from_subfuncret addr
		else add_from_normal addr
		end
	end
	
	# iterates over every from address, yields [address, (bool)is_subfuncret]
	def each_from
		each_from_normal { |a| yield a }
		each_from_subfuncret { |a| yield a, true }
	end

	def add_to(addr, subfuncret=false)
		if subfuncret: add_to_subfuncret addr
		else add_to_normal addr
		end
	end

	def each_to
		each_to_normal { |a| yield a }
		each_to_subfuncret { |a| yield a, true }
	end
end

# a factorized subfunction as seen by the disassembler
class DecodedFunction
	extend AccessorList
	
	# when backtracking an instruction that calls us, use this binding and then the instruction's
	attr_accessor :backtrace_binding
	# same as InstructionBlock#backtracked_for
	# includes the expression responsible of the function return (eg [esp] on ia32)
	attr_accessor :backtracked_for
	# addresses of instruction causing the function to return
	attr_accessor_list :return_address

	def initialize
		@backtracked_for = []
		@backtrace_binding = {}
	end
end

# TODO special decodedfunction, eg GetProcAddress

# symbolic pointer dereference
# API similar to Expression
class Indirection
	# Expression (the pointer)
	attr_accessor :target
	# length in bytes of data referenced
	attr_accessor :len

	def initialize(target, len)
		@target, @len = target, len
	end

	def reduce
		ptr = Expression[@target.reduce]
		(ptr.rexpr == :unknown) ? ptr : Indirection.new(ptr, @len)
	end
	alias reduce_rec reduce

	def bind(h)
		h[self] || Indirection.new(@target.bind(h), @len)
	end

	def hash ; @target.hash^@len end
	def eql?(o) o.class == self.class and [o.target, o.len] == [@target, @len] end
	alias == eql?

	def externals
		[self]
	end

	def to_s
		qual = {1 => 'byte', 2 => 'word', 4 => 'dword'}[@len] || "_#{len*8}bits"
		"#{qual} ptr [#{target}]"
	end
end

class EncodedData
	# returns an ::Integer from self.ptr, advances ptr
	# bytes from rawsize to virtsize = 0
	# ignores self.relocations
	def get_byte
		@ptr += 1
		if @ptr <= @data.length
			@data[ptr-1]
		elsif @ptr <= @virtsize
			0
		end
	end

	# returns a ::String containing +len+ bytes from self.ptr, advances ptr
	# bytes from rawsize to virtsize are returned as zeroes
	# ignores self.relocations
	def read(len=@virtsize-@ptr)
		str = ''
		if @ptr < @data.length
			str << @data[@ptr, len]
		end
		@ptr += len
		str.ljust(len, "\0")
	end
	
	# decodes an immediate value from self.ptr, advances ptr
	# returns an Expression on relocation, or an ::Integer
	# if ptr has a relocation but the type/endianness does not match, the reloc is ignored and a warning is issued
	# TODO arg type => sign+len
	def decode_imm(type, endianness)
		if rel = @reloc[@ptr]
			if Expression::INT_SIZE[rel.type] == Expression::INT_SIZE[type] and rel.endianness == endianness
				@ptr += rel.length
				return rel.target
			end
			puts "W: Immediate type/endianness mismatch, ignoring relocation #{rel.target.inspect} (wanted #{type.inspect})"
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
class CPU
	# decodes the instruction at edata.ptr, mapped at virtual address off
	# returns a DecodedInstruction or nil
	def decode_instruction(edata, addr)
		@bin_lookaside ||= build_bin_lookaside
		di = decode_findopcode edata
		di = decode_instr_op(edata, di) if di
		decode_instr_interpret(di, addr) if di
	end

	# matches the binary opcode at edata.ptr
	# returns di or nil
	def decode_findopcode(edata)
		DecodedInstruction.new self
	end

	# decodes di.instruction
	# returns di or nil
	def decode_instr_op(edata, di)
	end

	# may modify di.instruction.args for eg jump offset => absolute address
	# returns di or nil
	def decode_instr_interpret(di, addr)
		di
	end

	# return the thing to backtrace to find +value+ before the execution of this instruction
	# eg backtrace_emu('inc eax', Expression[:eax]) => Expression[:eax + 1]
	#  (the value of :eax after 'inc eax' is the value of :eax before plus 1)
	# may return Expression[:unknown]
	def backtrace_emu(di, value)
		value.bind(di.backtrace_binding ||= backtrace_binding(di)).reduce
	end

	# returns a list of Expressions/Integer to backtrace to find an execution target
	def get_xrefs_x(dasm, di)
	end

	# returns a list of [type, address, len]
	def get_xrefs_rw(dasm, di)
		b = di.backtrace_binding ||= backtrace_binding(di)
		find_ind = proc { |list| (list + list.grep(Expression).map { |e| e.externals }.flatten).grep(Indirection) }
		find_ind[b.values].map { |e| [:r, e.target, e.len] } + find_ind[b.keys].map { |e| [:w, e.target, e.len] }
	end

	# checks if the expression corresponds to a function return value with the instruction
	# (eg di == 'call something' and expr == [esp])
	def backtrace_is_function_return(di, expr)
	end

	# updates f.backtrace_binding when a new return address has been found
	# TODO update also when anything changes inside the function (new loop found etc) - use backtracked_for ?
	def backtrace_update_function_binding(dasm, faddr, f, retaddr)
	end

	# returns if the expression is an address on the stack
	# (to avoid trying to backtrace its absolute address until we found function boundaries)
	def backtrace_is_stack_address(expr)
	end

	# updates the instruction arguments: replace an expression with another (eg when a label is renamed)
	def replace_instr_arg_immediate(i, old, new)
		i.args.map! { |a|
			case a
			when Expression: Expression[a.bind(old => new).reduce]
			else a
			end
		}
	end
end

class ExeFormat
	# returns a string containing asm-style section declaration
	def dump_section_header(addr, edata)
		"\n// section at #{Expression[addr]}"
	end

	# returns an array of expressions that may be executed by this instruction
	def get_xrefs_x(dasm, di)  @cpu.get_xrefs_x(dasm, di)  end

	# returns an array of [type, expression, length] that may be accessed by this instruction (type is :r/:w, len is in bytes)
	def get_xrefs_rw(dasm, di) @cpu.get_xrefs_rw(dasm, di) end
end

# a disassembler class
# holds a copy of a program sections, a list of decoded instructions, xrefs
# is able to backtrace an expression from an address following the call flow (backwards)
# TODO method to rename a label
class Disassembler
	attr_accessor :program, :cpu
	# binding (jointure of @sections.values.exports)
	attr_accessor :prog_binding
	# hash addr => edata
	attr_accessor :sections
	# hash addr => DecodedInstruction
	attr_accessor :decoded
	# hash addr => DecodedFunction	 (includes 'imported' functions)
	attr_accessor :function
	# hash addr => (array of) xrefs - access with +add_xref+/+each_xref+
	attr_accessor :xrefs
	# bool, true to trace data acces (default true)
	attr_accessor :trace_data_xref
	# bool, true to check write xrefs on each instr disasm (default true) - depends on trace_data_xref
	attr_accessor :check_smc
	# list of [addr to disassemble, (optional)who jumped to it, (optional)got there by a subfunction return]
	attr_accessor :addrs_todo


	# creates a new disassembler
	def initialize(program, cpu=program.cpu)
		@program = program
		@cpu = cpu
		@sections = {}
		@decoded = {}
		@xrefs = {}
		@function = {}
		@check_smc = true
		@trace_data_xref = true
		@prog_binding = {}
		@addrs_todo = []
	end

	# adds a section, updates prog_binding
	# base addr is an Integer or a String (label name for offset 0)
	def add_section(encoded, base)
		case base
		when ::Integer
		when ::String
			raise "invalid section base #{base.inspect} - not at section start" if encoded.export[base] and encoded.export[base] != 0
			raise "invalid section base #{base.inspect} - already seen at #{@prog_binding[base]}" if @prog_binding[base] and @prog_binding[base] != Expression[base]
			encoded.export[base] = 0
		else raise "invalid section base #{base.inspect} - expected string or integer"
		end

		@sections[base] = encoded
		encoded.binding(base).each { |k, v|
			@prog_binding[k] = v.reduce
		}
		self
	end

	def add_xref(addr, x)
		case @xrefs[addr]
		when nil: @xrefs[addr] = x
		when x
		when ::Array: @xrefs[addr] |= [x]
		else @xrefs[addr] = [@xrefs[addr], x]
		end
	end

	# yields each xref to a given address, optionnaly restricted to a type
	def each_xref(addr, type=nil)
		case @xrefs[addr]
		when nil
		when ::Array: @xrefs[addr].each { |x| yield x if not type or x.type == type }
		else yield @xrefs[addr] if not type or @xrefs[addr].type == type
		end
	end

	# returns the canonical form of addr (absolute address integer or label of start of section + section offset)
	def normalize(addr)
		Expression[addr].bind(@prog_binding).reduce
	end

	# returns [edata, edata_base] or nil
	# edata.ptr points to addr
	def get_section_at(addr)
		case addr = normalize(addr)
		when ::Integer
			if s = @sections.find { |b, e| b.kind_of? ::Integer and addr >= b and addr < b + e.length }
				s[1].ptr = addr - s[0]
				[s[1], s[0]]
			end
		when Expression
			if addr.rexpr.kind_of? ::Integer and addr.lexpr.kind_of? ::String and e = @sections[addr.lexpr]
				e.ptr = addr.rexpr
				[e, Expression[addr.lexpr]]
			elsif addr.rexpr.kind_of? ::String and not addr.lexpr and e = @sections[addr]
				e.ptr = 0
				[e, addr]
			end
		end
	end

	# returns the label at the specified address, creates it if needed using the specified prefix (updates prog_binding)
	def label_at(addr, base='xref')
		e, b = get_section_at(addr)
		return if not e
		if not l = e.export.index(e.ptr)
			l = base + '_%08x' % (addr.kind_of?(Expression) ? addr.rexpr.kind_of?(::Integer) ? addr.rexpr : 0 : addr)
			l = @program.new_label(l) if @prog_binding[l]
			e.export[l] = e.ptr
			@prog_binding[l] = Expression[b, :+, e.ptr].reduce
		end
		l
	end

	# resolves an expression using prog_binding, follows Indirections
	def resolve(expr)
		binding = Expression[expr].externals.grep(Indirection).inject(@prog_binding) { |binding, ind|
			e, b = get_section_at(resolve(ind.target))
			return expr if not e
			binding.merge ind => Expression[ e.decode_imm("u#{8*ind.len}".to_sym, @cpu.endianness) ]
		}
		Expression[expr].bind(binding).reduce
	end

	def rename_label(old, new)
		each_xref(normalize(old)) { |x|
			@cpu.replace_instr_arg_immediate(@decoded[x.origin].instruction, old, new) if @decoded[x.origin]
		}
		e, l = get_section_at(old)
		e.export[new] = e.export.delete(old) if e
		@prog_binding[new] = @prog_binding.delete(old)
	end

	# decodes instructions from an entrypoint, (tries to) follows code flow
	def disassemble(*entrypoints)
		@addrs_todo.concat entrypoints
		while not @addrs_todo.empty?
			begin
				disassemble_step
			rescue
				puts $!, $!.backtrace if $VERBOSE
			end
		end
		self
	end

	# disassembles one block from addrs_todo
	# adds next addresses to handle to addrs_todo
	# if @function[:default] exists, jumps to unknows locations are interpreted as to @function[:default]
	def disassemble_step
		# from_func is true if from is the address of a function call that returns to addr
		addr, from, from_func = @addrs_todo.pop

		return if not addr

		addr = normalize(addr)

		if f = @function[addr]
		elsif di = @decoded[addr]
			split_block(di.block, di.block_offset) if di.block_offset != 0	# this updates di.block
			di.block.add_from(from, from_func)
			f = di.block
		elsif s = get_section_at(addr)
			block = InstructionBlock.new(Expression[s[1], :+, s[0].ptr].reduce, s[0])
			block.add_from(from, from_func) if from
			disassemble_block(block)
		elsif from
			add_xref(Expression[:unknown], Xref.new(:x, from))
			f = @function[:default]
			@decoded[from].block.add_subfunction :default if @decoded[from] and f
		else
			raise "unknown location to disassemble #{addr}"
		end

		f.backtracked_for.each { |btt|
			backtrace(btt.expr, from, true, from_func, btt.origin, btt.type, btt.len) if not btt.block_offset
		} if f
	end

	# splits an InstructionBlock, updates the blocks backtracked_for
	def split_block(block, offset)
		new_b = block.split offset
		todo = []	# array of [expr, off]
		new_b.backtracked_for.each { |btt|
			expr = btt.expr
			if btt.is_subfunc
				new_b.each_subfunc { |f|
					todo << [expr.bind(f.backtrace_binding).reduce, btt.block_offset - 1, btt.origin, btt.type, btt.len]
				}
			elsif btt.exclude_instr
				todo << [expr, btt.block_offset - 1, btt.origin, btt.type, btt.len]
			else
				todo << [expr, btt.block_offset, btt.origin, btt.type, btt.len]
			end
		}
		todo.each { |expr, off, origin, type, len|
			new_b.list.reverse_each { |di|
				next if di.block_offset > off
				if backtrace_check_found([], expr, nil, nil, nil, nil, nil, nil)
					expr = nil
					break
				end
				expr = @cpu.backtrace_emu(di, expr)
			}
			if expr
				btt = BacktraceTrace.new(expr, origin, type, len)
				new_b.backtracked_for |= [btt]
				btt = btt.dup
				btt.block_offset = block.list.last.block_offset
				block.backtracked_for |= [btt]
			end
		}
		new_b
	end

	# disassembles a new instruction block at block.address (must be normalized)
	def disassemble_block(block)
		raise if not block.list.empty?
		di_addr = block.address

		# try not to run for too long
		# loop usage: break if the block continues to the following instruction, else return
		100.times {
			# check collision into a known block
			break if @decoded[di_addr] or @function[di_addr]

			# decode instruction
			block.edata.ptr = block.edata_ptr + Expression[di_addr, :-, block.address].reduce
			if not di = @cpu.decode_instruction(block.edata, di_addr)
				puts "unknown instruction to decode at #{Expression[di_addr]}" if $VERBOSE
				return
			end

			@decoded[di_addr] = di
			block.add_di di

			# check self-modifying code
			(-7...di.bin_length).each { |off|
				each_xref(Expression[di_addr, :+, off].reduce, :w) { |x|
					next if off + x.len < 0
					puts "W: disasm: self-modifying code at #{Expression[di_addr, :+, off].reduce}" if $VERBOSE
					di.comment ||= ''
					di.comment << ' overwritten'
					return
				}
			} if @check_smc and @trace_data_xref

			# trace xrefs
			breakafter = false
			@program.get_xrefs_x( self, di).each { |expr| backtrace(expr, di_addr, false, false, di_addr, :x).each { breakafter = true } }
			@program.get_xrefs_rw(self, di).each { |type, ptr, len|
				backtrace(ptr, di_addr, false, false, di_addr, type, len).each { |xaddr|
					next if xaddr.kind_of? Expression and xaddr.rexpr == :unknown
					len.times { |i|
						if @decoded[normalize(Expression[xaddr, :+, i].reduce)]
							puts "W: disasm: #{di_addr} modifies existing code at #{xaddr}+#{i}" if $VERBOSE
						end
					} if @check_smc and type == :w
				}
			} if @trace_data_xref

			return if di.opcode.props[:stopexec]

			di_addr = Expression[di_addr, :+, di.bin_length].reduce

			break if breakafter
		}

		block.add_to di_addr
		@addrs_todo << [di_addr, block.list.last.address]
		block
	end

	# emulates each instruction from start_addr (including it if include_start)
	# follows the call flow backwards to find the value of expr
	# returns an array of Integer/Expression (may contain Expression[:unknown])
	# set is_subfunc to true if the instr at start_addr is a call and this call is to be backtracked as a factorized subfunction call (block.each_subfunc)
	# if snapshot_addr is defined, when the backtrace gets at it the current value of the expression is added to result. Must be a block start addr.
	# if snapshot_addr is not defined, expressions that are @cpu.backtrace_is_stack_address are not backtraced
	# if origin is defined: (it is the normalized address of the instruction that initiated the backtrace)
	#  updates block.backtracked_for on the way
	#  on resolution, checks cpu.backtrace_is_function_return to recognise subfunctions
	#  creates Xrefs on successful resolution
	# type is :r/:w/:x
	# len is the length of the r/w access (xref.len)
	# updates @addrs_todo with type :x
	def backtrace(expr, start_addr, include_start=false, is_subfunc=false, origin=nil, type=nil, len=nil, snapshot_addr=nil)
		start_addr = normalize(start_addr)
		# list of Expression/Integer
		result = []
		# array of [addr, expr, path, from, is_subfunc]
		# path is a hash { addr of end of block => expr backtracked }, used to detect/emulate loops
		todo = []
		
		# updates todo to check for expr before di (will walk block.from* if di.block_offset == 0)
		# updates block.backtracked_from{,_end} if +origin+ is defined
		# checks path, handles loops
		walk_up = proc { |e, di, path|
			if di.block_offset != 0
				prev_di = di.block.list[di.block.list.index(di)-1]
				todo << [prev_di.address, e, path, di.address]
			elsif snapshot_addr and snapshot_addr == di.block.address
				result |= [e]
			else
				if origin
					btt = BacktraceTrace.new(e, origin, type, len)
					di.block.backtracked_for |= [btt]
					if f = @function[di.block.address]
						f.backtracked_for |= [btt]
					end
				end
				di.block.each_from { |addr, is_subfunc|
					if path[addr]
						# XXX no_subfunc VS subfunc
						# XXX nested loops ?
						if e != path[addr]
							# TODO
							puts "  backtrace: modifying loop at #{addr}: #{e} was #{path[addr]}" if $VERBOSE
						end
					else
						todo << [addr, e, path.merge(addr => e), di.block.address, is_subfunc]
						if origin and pdi = @decoded[addr]
							btt = BacktraceTrace.new(e, origin, type, len)
							btt.block_offset = pdi.block_offset
							btt.subfuncret = is_subfunc if is_subfunc
							pdi.block.backtracked_for |= [btt]
						end
					end
				}
			end
		}

		if backtrace_check_found(result, expr, @decoded[start_addr], origin, type, len, expr, nil)
			# no need for backtraced_for update
			return result
		end

		# TODO backtrace from @function['foo']
		return result if not di = @decoded[start_addr]

		is_subfunc = false if di.block.list.last != di or not di.block.subfunction

		# create initial backtracked_for
		# XXX is origin normalized?
		if origin and origin == start_addr
			btt = BacktraceTrace.new(expr, origin, type, len)
			btt.block_offset = di.block_offset
			btt.exclude_instr = true if not include_start
			btt.is_subfunc = true if is_subfunc and include_start
			di.block.backtracked_for |= [btt]
		end

		# initialize the todo list
		if include_start
			todo << [start_addr, expr, {start_addr => expr}, nil, is_subfunc]
		else
			walk_up[expr, di, {}]
		end

puts "backtracking #{type} #{expr} from #{Expression[start_addr]} #{di.instruction if di}" if $DEBUG
		# do the backtrace
		while not todo.empty?
			addr, expr, path, from, is_subfunc = todo.pop
			if not di = @decoded[addr]
				puts "  backtrace: unknown addr for #{expr} at #{Expression[addr]}" if $VERBOSE
				result |= [Expression[:unknown]]
			elsif path.length > 50
				puts "  backtrace: too long for #{expr} at #{Expression[addr]}" if $VERBOSE
				result |= [Expression[:unknown]]
			elsif is_subfunc
				# backtrace using each function backtrace_binding, then backtrace the instruction
				# TODO mark the functions so that on a bt_binding update this could be rebacktraced
				#      generally include ruby callbacks
				di.block.each_subfunction { |f|
					nexpr = expr.bind(@function[f].backtrace_binding).reduce
					if not backtrace_check_found(result, nexpr, nil, origin, type, len, expr, from)
						todo << [addr, nexpr, path]
					end
				}
			else
				off = di.block_offset
				di.block.list.reverse_each { |di|
					next if di.block_offset > off
					if not snapshot_addr and @cpu.backtrace_is_stack_address(expr)
puts "  not backtracking stack address #{expr}" if $DEBUG
						break
					end
					nexpr = @cpu.backtrace_emu(di, expr)
puts "  backtrace #{di}: #{expr} -> #{Expression[nexpr]}" if $DEBUG
					break if backtrace_check_found(result, nexpr, di, origin, type, len, expr, from)
					expr = nexpr
					from = di.address
					walk_up[expr, di, path] if di.block_offset == 0
				}
			end
		end
puts '  backtrace result: [' + result.map { |r| Expression[r] }.join(', ') + ']' if $DEBUG

		if result.empty? and type == :x and origin and @decoded[origin]
			# TODO check entrypoint == function
			@decoded[origin].comment ||= ''
			@decoded[origin].comment << ' to unknown' if not @decoded[origin].comment.include? ' to unknown'
		end

		result
	end

	# checks if expr is resolved at this point or needs more backtrace
	# if it is resolved, appends it to result, and creates an xref
	# oldexpr is the expression before the emulation of di (used for subfunc recognition)
	# TODO modifies di.instruction.args to transform integral args to expressions involving the newly found result (as label)
	# TODO avoid backtracking addr of stack variable
	# updates addrs_todo if origin and type == :x
	def backtrace_check_found(result, expr, di, origin, type, len, oldexpr, oldaddr)
		# return an expr/int if the expr need no more backtracking
		case ee = resolve(expr)
		when ::Integer, Expression[:unknown]:
		when Expression, Indirection: return if need_backtrace(ee)
		else raise 'internal error ' + ee.inspect + ' ' + expr.inspect
		end

		result << ee if not result.include? ee
		if origin
			xref = Xref.new(type, origin, len)
			@xrefs[ee] ||= []
			@xrefs[ee] |= [xref]

			if type == :x and ee == Expression[:unknown] and @decoded[origin]
				@decoded[origin].comment ||= ''
				@decoded[origin].comment << ' to unknown' if not @decoded[origin].comment.include? ' to unknown'
			end
			return true if ee == Expression[:unknown]

			# creates a label
			base = { nil => 'loc', 1 => 'byte', 2 => 'word', 4 => 'dword' }[len] || 'xref'
			base = 'sub' if @function[ee]
			l = label_at(ee, base)

			# update instr args (imm -> Expression[label])
			# TODO trace expression evolution to allow handling of
			#  mov eax, 28 ; add eax, 4 ; jmp eax
			#  => mov eax, (loc_xx-4)
			if l and di and di.address == origin
				@cpu.replace_instr_arg_immediate(di.instruction, expr, Expression[l])
			end

			return true if type != :x

			if @decoded[origin] and (not di or di.address != origin)
				c = @decoded[origin].comment ||= ''
				if c.length < 32
					c << " to #{Expression[ee]}"
				elsif not c.include? ' to ...'
					c << ' to ...'
				end
			end

			# update @addrs_todo
			# check if we found a function return
			if oldaddr and di and @cpu.backtrace_is_function_return(di, oldexpr)
				l = @prog_binding.index(oldaddr)
				# new function ?
				if not f = @function[oldaddr]
					f = @function[oldaddr] = DecodedFunction.new
					if l and l[0, 4] == 'loc_'
						newl = l.sub('loc_', 'sub_')
						if not @prog_binding[newl]
							rename_label(l, newl)
							l = newl
						end
					end
					puts "found new function #{l} at #{Expression[oldaddr]}" if $VERBOSE
				end
				if @decoded[origin]
					f.add_return_address origin
					c = @decoded[origin].comment ||= ''
					es = " endsub #{l || Expression[oldaddr]}"
					c << es if not c.include? es
				end
				f.backtracked_for |= @decoded[oldaddr].block.backtracked_for.find_all { |btt| not btt.block_offset }
				@cpu.backtrace_update_function_binding(self, oldaddr, f, origin)
				# TODO rebacktrace things
				di.block.add_to_subfuncret ee
				di.block.add_subfunction oldaddr
				@addrs_todo << [ee, di.address, true]
puts "   backtrace_check: addrs_todo << #{Expression[ee]} from #{di} (funcret)" if $DEBUG
			else
				@addrs_todo << [ee, origin]
puts "   backtrace_check: addrs_todo << #{Expression[ee]} from #{Expression[origin] if origin}" if $DEBUG
			end
		end
		true
	end

	# returns true if the expression needs more backtrace
	# it checks for the presence of a symbol (not :unknown), which means it depends on some register value
	def need_backtrace(expr)
		return if expr.kind_of? ::Integer or expr == Expression[:unknown]
		expr.externals.find { |x|
			case x
			when Indirection: need_backtrace(x.target)
			when ::Symbol: x != :unknown
			when ::String: not @prog_binding[x]
			end
		}
	end

	def to_s
		a = ''
		dump { |l| a << l << "\n" }
		a
	end

	# dumps the source, optionnally including data
	# yields (defaults puts) each line
	def dump(dump_data=true, &b)
		b ||= proc { |l| puts l }
		@sections.sort.each { |addr, edata|
			b.call @program.dump_section_header(addr, edata)
			unk_off = 0
			# blocks.sort_by { |b| b.addr }.each { |b|
			edata.length.times { |i|
				curaddr = Expression[addr, :+, i].reduce
				if di = @decoded[curaddr] and di.block_offset == 0
					dump_block(di.block, &b)
					di = di.block.list.last
					unk_off = i + di.block_offset + di.bin_length
				elsif i >= unk_off and dump_data
					unk_off = dump_data(Expression[addr, :+, unk_off].reduce, edata, unk_off, &b)
				end
			}
		}
	end

	# dumps a block of decoded instructions
	def dump_block(block, &b)
		xr = []
		each_xref(block.address, :x) { |x| xr << Expression[x.origin] }
		if not xr.empty?
			b.call ''
			b.call "// Xrefs: #{xr[0, 8].join(' ')}#{' ...' if xr.length > 8}"
		end
		if @prog_binding.index(block.address)
			@prog_binding.each { |name, addr| b.call "#{name}:" if addr == block.address }
		end
		block.list.each { |di|
			block.edata.ptr = block.edata_ptr + di.block_offset
			bin = block.edata.read(di.bin_length).unpack('C*').map { |c| '%02x' % c }.join
			b.call "    #{di.instruction.to_s.ljust(44)} ; @#{Expression[di.address]}  #{bin}  #{di.comment}"
		}
	end

	# dumps data/labels, honours @xrefs.len if exists
	# dumps one line only
	# stops on end of edata/@decoded/@xref
	# returns the next offset to display
	# TODO array-style data access
	def dump_data(addr, edata, off, &b)
		l = ''
		l << @prog_binding.index(addr).to_s
		l << ' ' if not l.empty?
		elemlen = 1	# size of each element we dump (db by default)
		dumplen = off % 16	# number of octets to dump
		dumplen = 16 if dumplen == 0
		cmt = " ; @#{Expression[addr]}"
		each_xref(addr) { |x|
			dumplen = elemlen = x.len if x.len == 2 or x.len == 4
			cmt << " #{Expression[x.origin]}:#{x.type}#{x.len}"
		}
		if r = edata.reloc[off]
			dumplen = elemlen = r.type.to_s[1..-1].to_i/8
		end
		l << { 1 => 'db ', 2 => 'dw ', 4 => 'dd ' }[elemlen]

		if off >= edata.data.length
			dups = edata.virtsize - off
			if tmp = @prog_binding.values.find { |a|
				tmp = Expression[a, :-, addr].reduce
				tmp.kind_of? ::Integer and tmp > 0 and tmp < dups
			}
			dups = tmp
			end
			if tmp = @xrefs.keys.find { |a|
				tmp = Expression[a, :-, addr].reduce
				tmp.kind_of? ::Integer and tmp > 0 and tmp < dups
			}
				dups = tmp
			end
			dups /= elemlen
			dups = 1 if dups < 1
			b.call l + "#{dups} dup(?)"
			return off + dups*elemlen
		end

		vals = []
		edata.ptr = off
		(dumplen/elemlen).times {
			vals << edata.decode_imm("u#{elemlen*8}".to_sym, @cpu.endianness)
			addr = Expression[addr, :+, elemlen].reduce
			if i = (1-elemlen..0).find { |i|
				t = Expression[addr, :+, i].reduce
				@xrefs[t] or @decoded[t] or edata.reloc[edata.ptr+i]
			}
				edata.ptr += i
				break
			end
			break if edata.reloc[edata.ptr-elemlen]
			# TODO uninitialized data
		}

		# recognize strings
		vals = vals.inject([]) { |vals, value|
			if (elemlen == 1 or elemlen == 2) and value.kind_of? ::Integer and value >= 0x20 and value <= 0x7e
				if vals.last.kind_of? ::String
					vals.last << value
				else
					vals << value.chr
				end
			else
				vals << value
			end
			vals
		}
		vals.map! { |value|
			if value.kind_of? ::String
				if value.length > 2 # or value == vals.first or value == vals.last # if there is no xref, don't care
					value.inspect
				else
					value.unpack('C*').map { |c| Expression[c] }
				end
			else
				Expression[value]
			end
		}.flatten

		l += vals.join(', ')

		b.call l.ljust(48) + cmt

		edata.ptr
	end
end
end
