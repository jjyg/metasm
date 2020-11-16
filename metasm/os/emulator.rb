#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/os/main'
require 'metasm/debug'

module Metasm
# a VirtualString mapping the segments from a disassembler
class VirtualMemoryDasm < VirtualString
	attr_accessor :disassembler

	def initialize(disassembler, addr_start = 0, length = nil)
		@disassembler = disassembler
		length ||= 1 << disassembler.cpu.size
		super(addr_start, length)
	end

	def dup(addr = @addr_start, len = @length)
		self.class.new(@disassembler, addr, len)
	end

	# reads an aligned page from the file, at file offset addr
	def read_range(addr, len=@pagelength)
		@disassembler.read_raw_data(addr, len)
	end

	def page_invalid?(addr)
		!@disassembler.get_section_at(addr)
	end

	def get_page(addr, len=@pagelength)
		read_range(addr, len) if !page_invalid?(addr)
	end

	# overwrite a section of the file
	def rewrite_at(addr, data)
		if e = @disassembler.get_section_at(addr)
			e[0].data[addr - e[1], data.length] = data
		end
	end

	def decode_imm(addr, len, cpu)
		@disassembler.decode_int(addr, len)
	end
end

# this class implements a virtual debugger over an emulated cpu (based on cpu#get_backtrace_binding)
class EmuDebugger < Debugger
	attr_accessor :ctx
	# lambda called everytime we emulate a di
	# receives the di as parameter
	# if it returns nil, the di is emulated as usual, if it returns true no further processing is done for this di
	# dont forget to handle reg_pc !
	attr_accessor :callback_emulate_di
	# lambda called everytime we cannot find an instruction at the current PC
	# return true if the context was fixed
	attr_accessor :callback_unknown_pc

	# allow only concrete values, no symbolic execution
	attr_accessor :concrete_only

	# hash { symbolic_addr => value }
	attr_accessor :symbolic_memory

	def initialize(disassembler, concrete_only=false)
		@pid = @tid = 0
		@concrete_only = concrete_only
		attach(disassembler)
	end

	def shortname; 'emudbg'; end

	def attach(disassembler)
		@memory = VirtualMemoryDasm.new(disassembler)
		@symbolic_memory = {} if not @concrete_only
		@cpu = disassembler.cpu
		@disassembler = disassembler
		@ctx = {}
		@state = :stopped
		@symbols = disassembler.prog_binding.invert
		@symbols_len = @symbols.keys.inject({}) { |h, s| h.update s => 1 }
		@modulemap = {}
		@breakpoint = {}
		@breakpoint_memory = {}
		@breakpoint_thread = {}
		make_sections_editable
		@cpu.initialize_emudbg(self) if @cpu.respond_to?(:initialize_emudbg)
	end

	def make_sections_editable
		# load dasm sections content as strings to allow nonpersistant modifications (would raise with a readonly VirtualFile object)
		@disassembler.sections.each_value { |edata|
		      if edata.length < 1024*1024
			      edata.data = edata.data.to_str
			      edata.fill
		      end
		}
	end

	def detach
	end

	def initialize_disassembler
	end
	def initialize_cpu
	end
	def initialize_memory
	end
	def invalidate
	end

	def memory_get_page(addr, len)
		@memory[addr, len]
	end

	def get_reg_value(r)
		case r.to_s
		when /flags?_(.+)/i
			f = $1.downcase.to_sym
			get_flag_value(f)
		when /^init_/
			@ctx[r] || (@concrete_only ? 0 : r)
		else
			@ctx[r] || (@concrete_only ? 0 : "init_#{r}".to_sym)
		end
	end

	def set_reg_value(r, v)
		if r.to_s =~ /flags?_(.+)/i
			f = $1.downcase.to_sym
			set_flag_value(f, v)
		else
			if v.kind_of?(::Integer) and sz = @cpu.dbg_register_size[r]
				v &= (1 << sz) - 1
			end
			@ctx[r] = v
		end
	end

	def do_check_target
		true
	end

	def do_wait_target
		true
	end

	def check_pre_run(m, *a)
		@run_method = m
		@run_args = a
	end

	def do_continue
		while not @breakpoint[pc] and do_singlestep	# TODO check bp#enabled
		end
	end

	def do_enable_bp(b)	# no need to actually patch code in memory
	end

	def do_disable_bp(b)
	end

	def do_singlestep
		if b = @breakpoint[pc]
			evt_bpx(b)
		end

		di = @disassembler.di_at(pc)
		if not di
			@disassembler.disassemble_fast(pc)
			di = @disassembler.di_at(pc)
		end
		if not di
			if callback_unknown_pc and callback_unknown_pc.call()
				return true
			end
			return
		end

		if callback_emulate_di
			ret = callback_emulate_di.call(di)
			return true if ret
		end

		return if di.opcode.props[:stopexec] and not di.opcode.props[:setip]

		# 2-pass to respect binding atomicity
		fbd = @disassembler.get_fwdemu_binding(di, register_pc, self)

		fbd.map { |k, v|
			if k.kind_of?(Indirection)
				k = Indirection.new(resolve(k.pointer), k.len, k.origin)
			end
			[k, resolve(v)]
		}.each { |k, v|
			case k
			when Indirection
				if not k.pointer.kind_of?(::Integer)
					if @concrete_only
						raise "cannot assign to pointer #{k.pointer}"
					else
						memory_write_int(k.pointer, k.len, v)
					end
				elsif not v.kind_of?(::Integer)
					if @concrete_only
						raise "cannot assign value #{v}"
					else
						raise "cannot assign symbolic value #{v} to concrete address #{k.pointer}"
					end
				else
					v = v & ((1 << (k.len*8)) - 1)
					memory_write_int(k.pointer, v, k.len)
				end
			when Symbol
				raise "cannot assign value #{v}" if @concrete_only and not v.kind_of?(::Integer)
				set_reg_value(k, v)
			when /^dummy_metasm_/
			else
				puts "singlestep: badkey #{k.inspect} = #{v}"
			end
		}
		true
	end

	def resolve_expr(e)
		v = super(e)
		if not @concrete_only and v.kind_of?(Expression)
			v = v.reduce { |i|
				if i.kind_of?(Indirection) and not i.pointer.kind_of?(::Integer)
					i.len ||= @cpu.size/8
					Expression.decode_sym(symbolic_memory_read_bytes(i.pointer, i.len).map { |b| b || 0 }, i.len, @cpu)
				end
			}
		end
		v
	end

	# read a buffer from memory
	# symbolic memory returns nul bytes for symbolic byte values
	def memory_read(addr, len)
		if not addr.kind_of?(::Integer) and not @concrete_only
			symbolic_memory_read_bytes(addr, len).map { |b| b.kind_of?(::Integer) ? b : 0 }.pack('C*')
		else
			super(addr, len)
		end
	end

	# write a concrete buffer to memory
	def memory_write(addr, len, value)
		if not addr.kind_of?(::Integer) and not @concrete_only
			symbolic_memory_write_bytes(addr, len, value.unpack('C*'))
		else
			super(addr, len, value)
		end
	end

	def memory_write_int(addr, len, val)
		if not @concrete_only and (not addr.kind_of?(::Integer) or not val.kind_of?(::Integer))
			symbolic_memory_write_bytes(addr, len, Expression.encode_sym(val, len, @cpu))
		else
			super(addr, len, val)
		end
	end

	# return a byte array from symbolic memory
	def symbolic_memory_read_bytes(ptr, len)
		(0...len).map { |i| @symbolic_memory[ptr+i] }
	end

	# write a byte array to symbolic memory
	def symbolic_memory_write_bytes(ptr, len, bytes)
		bytes.each_with_index { |b, i|
			@symbolic_memory[ptr+i] = b
		}
	end

	# allocate a new large memory zone, return the allocation address
	def allocate_memory(len, addr=nil, raw=nil)
		raw ||= EncodedData.new("\x00" * len)
		if !addr
			addr = 0x10000
			addr += 0x10000 while @disassembler.get_section_at(addr)
		end
		@disassembler.add_section(raw, addr)
		addr
	end
end
end
