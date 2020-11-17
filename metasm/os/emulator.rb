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

# Virtual debugger running emulated cpu instructions (based on cpu#get_backtrace_binding)
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

	def initialize(disassembler)
		@pid = @tid = 0
		attach(disassembler)
	end

	def shortname; 'emudbg'; end
	def is_symdbg; false; end

	def attach(disassembler)
		@memory = VirtualMemoryDasm.new(disassembler)
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
		else
			@ctx[r] || 0
		end
	end

	def set_reg_value(r, v)
		case r.to_s
		when /flags?_(.+)/i
			f = $1.downcase.to_sym
			set_flag_value(f, v)
		else
			if sz = @cpu.dbg_register_size[r]
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

		fbd = @disassembler.get_fwdemu_binding(di, register_pc, self)

		do_singlestep_emu(di, fbd)

		true
	end

	def do_singlestep_emu(di, fbd)
		# 2-pass to respect binding atomicity
		fbd.map { |k, v|
			if k.kind_of?(Indirection)
				k = Indirection.new(resolve(k.pointer), k.len, k.origin)
			end
			[k, resolve(v)]
		}.each { |k, v|
			case k
			when Indirection
				if not k.pointer.kind_of?(::Integer)
					raise "cannot assign to pointer #{k.pointer}"
				elsif not v.kind_of?(::Integer)
					raise "cannot assign value #{v}"
				else
					v = v & ((1 << (k.len*8)) - 1)
					memory_write_int(k.pointer, v, k.len)
				end
			when Symbol
				raise "cannot assign value #{k}=#{v}" if not v.kind_of?(::Integer)
				set_reg_value(k, v)
			when /^dummy_metasm_/
			else
				puts "singlestep: badkey #{k.inspect} = #{v}"
			end
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

# Same as EmuDebugger, but allows symbolic context (abstract values for registers and memory pointers, represented as symbols)
class SymEmuDebugger < EmuDebugger
	# hash { symbolic_addr => value }
	attr_accessor :symbolic_memory

	def shortname; 'symemudbg'; end
	def is_symdbg; true; end

	def attach(*a)
		@symbolic_memory = {}
		super(*a)
	end

	# initial value for registers
	# general registers are initialized to :init_<reg>, others to 0
	# eg :eax => :init_eax, :dr6 => 0, :eflags => 0
	attr_accessor :default_reg_value
	def get_default_reg_value
		@default_reg_value ||= Hash.new(0).update @cpu.dbg_register_list.inject({}) { |h, r| ir = "init_#{r}".to_sym ; h.update r => ir, ir => ir }
	end

	def get_reg_value(r)
		case r.to_s
		when /flags?_(.+)/i
			f = $1.downcase.to_sym
			get_flag_value(f)
		else
			@ctx[r] || get_default_reg_value[r]
		end
	end

	def set_reg_value(r, v)
		case r.to_s
		when /flags?_(.+)/i
			f = $1.downcase.to_sym
			set_flag_value(f, v)
		else
			if v.kind_of?(::Integer) and sz = @cpu.dbg_register_size[r]
				v &= (1 << sz) - 1
			end
			@ctx[r] = v
		end
	end

	def do_singlestep_emu(di, fbd)
		# 2-pass to respect binding atomicity
		fbd.map { |k, v|
			if k.kind_of?(Indirection)
				k = Indirection.new(resolve(k.pointer), k.len, k.origin)
			end
			[k, resolve(v)]
		}.each { |k, v|
			case k
			when Indirection
				if not k.pointer.kind_of?(::Integer)
					memory_write_int(k.pointer, k.len, v)
				elsif not v.kind_of?(::Integer)
					raise "cannot assign symbolic value #{v} to concrete address #{k.pointer}"
				else
					v = v & ((1 << (k.len*8)) - 1)
					memory_write_int(k.pointer, v, k.len)
				end
			when Symbol
				set_reg_value(k, v)
			when /^dummy_metasm_/
			else
				puts "singlestep: badkey #{k.inspect} = #{v}"
			end
		}
	end

	# handle symbolic_memory indirections
	def resolve_expr(e)
		v = super(e)
		v = v.reduce { |i|
			next if not i.kind_of?(Indirection) or i.pointer.kind_of?(::Integer)
			i.len ||= @cpu.size/8
			Expression.decode_sym(symbolic_memory_read_bytes(i.pointer, i.len).map { |b| b || 0 }, i.len, @cpu)
		} if v.kind_of?(Expression)
		v
	end

	# read a buffer from memory
	# symbolic memory returns nul bytes for symbolic byte values
	def memory_read(addr, len)
		if not addr.kind_of?(::Integer)
			symbolic_memory_read_bytes(addr, len).map { |b| b.kind_of?(::Integer) ? b : 0 }.pack('C*')
		else
			super(addr, len)
		end
	end

	# write a concrete buffer to memory
	def memory_write(addr, len, value)
		if not addr.kind_of?(::Integer)
			symbolic_memory_write_bytes(addr, len, value.unpack('C*'))
		else
			super(addr, len, value)
		end
	end

	def memory_write_int(addr, len, val)
		if addr.kind_of?(::Integer) and val.kind_of?(::Integer)
			super(addr, len, val)
		else
			# XXX may write sym val to concrete address in sym_mem, noone will read it
			symbolic_memory_write_bytes(addr, len, Expression.encode_sym(val, len, @cpu))
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

	# return the current value of the registers expressed from the values of the registers at the beginning of the emulation
	# eg 'inc eax' => { :eax => Expression[:eax+1] }
	def get_regs_changed
		out = {}
		@ctx.each { |k, v|
			nv = Expression[v].reduce { |e|
				case e
				when Symbol
					# :init_eax => :eax
					e.to_s[5..-1].to_sym if e.to_s[0, 5] == 'init_'
				when Expression
					# :eax & 0xffffffff => :eax
					e.lexpr if e.op == :& and e.lexpr.kind_of?(::Symbol) and sz = @cpu.dbg_register_size[e.lexpr] and e.rexpr == (1 << sz) - 1
				end
			}
			out[k] = nv if nv != Expression[k]
		}
		out
	end
end
end
