#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'
require 'metasm/render'


module Metasm
# symbolic pointer dereference
# API similar to Expression
class Indirection < ExpressionType
	# Expression (the pointer)
	attr_accessor :target
	alias pointer target
	alias pointer= target=
	# length in bytes of data referenced
	attr_reader :len
	# address of the instruction who generated the indirection
	attr_accessor :origin

	def initialize(target, len, origin)
		@target, @origin = target, origin
		self.len = len
	end

	def len=(len)
		@len = len
		@max_bits_mask ||= (1 << (len*8)) - 1 if len.kind_of?(::Integer)
	end

	def reduce_rec(cb=nil)
		ptr = Expression[@target.reduce(&cb)]
		(ptr == Expression::Unknown) ? ptr : Indirection.new(ptr, @len, @origin)
	end

	def bind(h)
		h[self] || Indirection.new(@target.bind(h), @len, @origin)
	end

	def hash ; @target.hash^@len.to_i end
	def eql?(o) o.class == self.class and [o.target, o.len] == [@target, @len] end
	alias == eql?

	include Renderable
	def render
		ret = []
		qual = {1 => 'byte', 2 => 'word', 4 => 'dword', 8 => 'qword'}[len] || "_#{len*8}bits" if len
		ret << "#{qual} ptr " if qual
		ret << '[' << @target << ']'
	end

	# returns the complexity of the expression (number of externals +1 per indirection)
	def complexity
		1+@target.complexity
	end

	def self.[](t, l, o=nil)
		new(Expression[*t], l, o)
	end

	def inspect
		"Indirection[#{@target.inspect.sub(/^Expression/, '')}, #{@len.inspect}#{', '+@origin.inspect if @origin}]"
	end

	def externals
		@target.externals
	end

	def match_rec(pattern, vars)
		return false if not pattern.kind_of? Indirection
		pt = pattern.target
		if vars[pt]
			return false if @target != vars[pt]
		elsif vars.has_key? pt
			vars[pt] = @target
		elsif pt.kind_of? ExpressionType
			return false if not @target.match_rec(pt, vars)
		else
			return false if pt != @target
		end
		pl = pattern.len
		if vars[pl]
			return false if @len != vars[pl]
		elsif vars.has_key? pl
			vars[pl] = @len
		else
			return false if pl != @len
		end
		vars
	end
end

class Expression
	# returns the complexity of the expression (number of externals +1 per indirection)
	def complexity
		case @lexpr
		when ExpressionType; @lexpr.complexity
		when nil, ::Numeric; 0
		else 1
		end +
		case @rexpr
		when ExpressionType; @rexpr.complexity
		when nil, ::Numeric; 0
		else 1
		end
	end

	def expr_indirections
		ret = case @lexpr
		when Indirection; [@lexpr]
		when ExpressionType; @lexpr.expr_indirections
		else []
		end
		case @rexpr
		when Indirection; ret << @rexpr
		when ExpressionType; ret.concat @rexpr.expr_indirections
		else ret
		end
	end
end

class EncodedData
	# returns an ::Integer from self.ptr, advances ptr
	# bytes from rawsize to virtsize = 0
	# ignores self.relocations
	def get_byte
		@ptr += 1
		if @ptr <= @data.length
			b = @data[ptr-1]
			b = b.unpack('C').first if b.kind_of? ::String	# 1.9
			b
		elsif @ptr <= @virtsize
			0
		end
	end

	# reads len bytes from self.data, advances ptr
	# bytes from rawsize to virtsize are returned as zeroes
	# ignores self.relocations
	def read(len=@virtsize-@ptr)
		vlen = len
		vlen = @virtsize-@ptr if len > @virtsize-@ptr
		str = (@ptr < @data.length) ? @data[@ptr, vlen] : ''
		str = str.to_str.ljust(vlen, "\0") if str.length < vlen
		@ptr += len
		str
	end

	# decodes an immediate value from self.ptr, advances ptr
	# returns an Expression on relocation, or an ::Integer
	# if ptr has a relocation but the type/endianness does not match, the reloc is ignored and a warning is issued
	# TODO arg type => sign+len
	def decode_imm(type, endianness)
		raise "invalid imm type #{type.inspect}" if not isz = Expression::INT_SIZE[type]
		if rel = @reloc[@ptr]
			if Expression::INT_SIZE[rel.type] == isz and rel.endianness == endianness
				@ptr += rel.length
				return rel.target
			end
			puts "W: Immediate type/endianness mismatch, ignoring relocation #{rel.target.inspect} (wanted #{type.inspect})" if $DEBUG
		end
		Expression.decode_imm(read(isz/8), type, endianness)
	end
	alias decode_immediate decode_imm
end

class Expression
	# decodes an immediate from a raw binary string
	# type may be a length in bytes, interpreted as unsigned, or an expression type (eg :u32)
	# endianness is either an endianness or an object than responds to endianness
	def self.decode_imm(str, type, endianness, off=0)
		type = INT_SIZE.keys.find { |k| k.to_s[0] == ?a and INT_SIZE[k] == 8*type } if type.kind_of? ::Integer
		endianness = endianness.endianness if not endianness.kind_of? ::Symbol
		str = str[off, INT_SIZE[type]/8].to_s
		str = str.reverse if endianness == :little
		val = str.unpack('C*').inject(0) { |val_, b| (val_ << 8) | b }
		val = make_signed(val, INT_SIZE[type]) if type.to_s[0] == ?i
		val
	end
	class << self
		alias decode_immediate decode_imm
	end
end

class CPU
	def bin_lookaside
		@bin_lookaside ||= build_bin_lookaside
	end

	# decodes the instruction at edata.ptr, mapped at virtual address off
	# returns a DecodedInstruction or nil
	def decode_instruction(edata, addr)
		bin_lookaside
		di = decode_findopcode edata if edata.ptr <= edata.length
		di.address = addr if di
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

	# return a symbolic representation of an instruction argument (eg Reg[0] => :eax)
	def symbolic(arg, di=nil)
		case arg
		when ExpressionType
			arg
		when Integer
			Expression[arg]
		else
			arg.symbolic(di)
		end
	end

	# number of instructions following a jump that are still executed
	def delay_slot(di=nil)
		0
	end

	def disassembler_default_func
		DecodedFunction.new
	end

	# hash opcode_name => lambda { |dasm, di, *symbolic_args| instr_binding }
	def backtrace_binding
		@backtrace_binding ||= init_backtrace_binding
	end
	def backtrace_binding=(b) @backtrace_binding = b end

	# return the backtrace binding for a specific di
	def get_backtrace_binding(di)
		a = di.instruction.args.map { |arg| symbolic(arg, di) }

		if binding = backtrace_binding[di.opcode.name]
			binding[di, *a]
		else
			puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
			{:incomplete_binding => Expression[1]}
		end
	end

	# return something like backtrace_binding in the forward direction
	# set pc_reg to some reg name (eg :pc) to include effects on the instruction pointer
	# pass a debugger to allow reading the context and actually resolve the next pc in case of conditional jumps
	def get_fwdemu_binding(di, pc_reg=nil, dbg_ctx=nil)
		fbd = di.backtrace_binding ||= get_backtrace_binding(di)
		fbd = fix_fwdemu_binding(di, fbd)
		if pc_reg
			n_a = Expression[pc_reg, :+, di.bin_length]
			if di.opcode.props[:setip]
				xr = get_xrefs_x(nil, di).to_a
				xr |= [n_a] if not di.opcode.props[:stopexec]
				if xr.length == 1
					fbd[pc_reg] = xr[0]
				else
					dbg_resolve_pc(di, fbd, pc_reg, dbg_ctx)
				end
			else
				fbd[pc_reg] = Expression[pc_reg, :+, di.bin_length]
			end
		end
		fbd
	end

	# resolve the program counter following a conditional jump using a debugging context
	def dbg_resolve_pc(di, fbd, pc_reg, dbg_ctx)
		fbd[:incomplete_binding] = Expression[1]
	end

	# patch a forward binding from the backtrace binding
	# useful only on specific instructions that update a register *and* dereference that register (eg push)
	def fix_fwdemu_binding(di, fbd)
		fbd
	end
end
end
