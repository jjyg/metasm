#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/x86_64/main'

module Metasm
class X86_64
	def func_abi(dcmp)
		# TODO check cpu.abi_funcall
		@func_abi ||= nil
		return @func_abi if @func_abi

		if dcmp.dasm.program.shortname == 'coff'
			@func_abi = { :args => [:rcx, :rdx, :r8, :r9], :stackoff => 32 }	# TODO
		else
			@func_abi = { :args => [:rdi, :rsi, :rdx, :rcx], :stackoff => 0 }	# XXX saved rip offset ?
		end
	end

	# return the array of arguments (symbols, indirections wrt frameptr) to be used as arguments for decompilation of the function call in di
	def decompile_get_func_args(dcmp, func_entry, di, f)
		abi_args = func_abi(dcmp)[:args].dup
		stackoff = func_abi(dcmp)[:stackoff]

		args = []
		f.type.args.to_a.each { |a|
			if r = a.has_attribute_var('register')
				args << Expression[r.to_sym]
				abi_args.delete r.to_sym
			elsif o = a.has_attribute_var('stackoff')
				args << Indirection[[:frameptr, :+, Integer(o)], 8]
			elsif abi_args.empty?
				args << Indirection[[:frameptr, :+, stackoff], 8]
				stackoff += 8
			else
				args << Expression[abi_args.shift]
			end
		}

		args
	end

	def decompile_check_abi(dcmp, entry, func)
		abi_regargs = func_abi(dcmp)[:args].map { |ra| ra.to_s }
		a = func.type.args || []

		# delete unused regs not part of the ABI
		a.delete_if { |arg| arg.has_attribute('unused') and ra = arg.has_attribute_var('register') and not abi_regargs.index(ra) }

		# delete last regs of the ABI if unused
		abi_regargs.reverse.each { |ra|
			break if a.find { |arg| arg.has_attribute_var('register') == ra and not arg.has_attribute('unused') }
			a.delete_if { |arg| arg.has_attribute('unused') and arg.has_attribute_var('register') == ra }
		}

		# reorder ABI regs according to ABI
		a.sort_by! { |arg| ra = arg.has_attribute_var('register') ; abi_regargs.index(ra) || (1000 + a.index(arg)) }

		# TODO
		#if not f = dcmp.dasm.function[entry] or not f.return_address
			#func.add_attribute 'noreturn'
		#end
	end
end
end
