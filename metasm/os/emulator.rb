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
		length ||= disassembler.sections.map { |k, v| k.kind_of?(Integer) ? k + v.length : 0 }.max
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

	def initialize(disassembler)
		@pid = @tid = 0
		attach(disassembler)
	end

	def shortname; 'emudbg'; end

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
		if r.to_s =~ /flags?_(.+)/i
			f = $1.downcase.to_sym
			get_flag_value(f)
		else
			@ctx[r] || 0
		end
	end

	def set_reg_value(r, v)
		if r.to_s =~ /flags?_(.+)/i
			f = $1.downcase.to_sym
			set_flag_value(f, v)
		else
			@ctx[r] = v
		end
	end

	def do_check_target
		true
	end

	def do_wait_target
		true
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
				v = v & ((1 << (k.len*8)) - 1)
				memory_write_int(k.pointer, v, k.len)
			when Symbol
				set_reg_value(k, v)
			when /^dummy_metasm_/
			else
				puts "singlestep: badkey #{k.inspect} = #{v}"
			end
		}
		true
	end
end
end
