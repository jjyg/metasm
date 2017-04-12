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
	def get_page(addr, len=@pagelength)
		@disassembler.read_raw_data(addr, len)
	end

	def page_invalid?(addr)
		@disassembler.get_section_at(addr)
	end

	# overwrite a section of the file
	def rewrite_at(addr, data)
		if e = @disassembler.get_section_at(addr)
			e[0].data[addr - e[1], data.length] = data
		end
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
		@ctx[r] || 0
	end
	def set_reg_value(r, v)
		@ctx[r] = v
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

	def do_singlestep
		di = @disassembler.di_at(pc)
		return if not di

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
			if not v.kind_of?(Integer)
				puts "singlestep: badvalue #{k} = #{v}"
				next
			end

			case k
			when Indirection
				memory_write_int(k.pointer, v, k.len)
			when Symbol
				set_reg_value(k, v)
			else
				puts "singlestep: badkey #{k} = #{v}"
			end
		}
		true
	end
end
end
