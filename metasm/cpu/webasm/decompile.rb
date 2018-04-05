#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/webasm/main'

module Metasm
class WebAsm
	def wasm_type_to_type(t)
		case t
		when 'i32'; C::BaseType.new(:int)
		when 'i64'; C::BaseType.new(:longlong)
		when 'f32'; C::BaseType.new(:float)
		when 'f64'; C::BaseType.new(:double)
		when 'anyfunc'; C::Function.new(C::BaseType.new(:void))
		when Hash
			ret = t[:ret].first ? wasm_type_to_type(t[:ret].first) : C::BaseType.new(:void)
			args = t[:params].map { |p| C::Variable.new(nil, wasm_type_to_type(p)) }
			C::Function.new(ret, args)
		end
	end

	def decompile_init(dcmp)
		dcmp.dasm.program.global.to_a.each_with_index { |g, idx|
			var = C::Variable.new
			var.name = 'global_%d' % idx
			var.type = wasm_type_to_type(g[:type])
			dcmp.c_parser.toplevel.symbol[var.name] = var
			dcmp.c_parser.toplevel.statements << C::Declaration.new(var)
			# TODO init
		}
	end

	def decompile_makestackvars(dasm, funcstart, blocks)
		oldfuncbd = dasm.address_binding[funcstart]
		dasm.address_binding[funcstart] = { :opstack => :frameptr }
		blocks.each { |block| yield block }
		dasm.address_binding[funcstart] = oldfuncbd if oldfuncbd
	end

	def decompile_func_finddeps_di(dcmp, func, di, a, w)
	end

	def decompile_func_finddeps(dcmp, blocks, func)
		{}
	end

	def decompile_blocks(dcmp, myblocks, deps, func, nextaddr = nil)
		func_entry = myblocks.first[0]
		dcmp.dasm.program.function_signature.to_a.zip(dcmp.dasm.program.function_body.to_a).each { |fs, fb|
			next if fb[:init_offset] != func_entry
			func.type = wasm_type_to_type(fs)
			func.type.args.each_with_index { |a, i| a.name ||= "local_%d" % i }
		}
		retaddrs = dcmp.dasm.function[func_entry].return_address

		scope = func.initializer
		func.type.args.each { |a| scope.symbol[a.name] = a }
		stmts = scope.statements
		blocks_toclean = myblocks.dup
		until myblocks.empty?
			b, to = myblocks.shift
			if l = dcmp.dasm.get_label_at(b)
				stmts << C::Label.new(l)
			end

			# Expr => CExpr
			ce  = lambda { |*e| dcmp.decompile_cexpr(Expression[Expression[*e].reduce], scope) }

			# go !
			di_list = dcmp.dasm.decoded[b].block.list.dup
			di_list.each { |di|
				if di.opcode.props[:setip] and not di.opcode.props[:stopexec]
					n = dcmp.backtrace_target(get_xrefs_x(dcmp.dasm, di).first, di.address)
					if di.opcode.name == /bfeq/
						cc = ce[:flag]
					else
						cc = ce[:!, :flag]
					end
					stmts << C::If.new(C::CExpression[cc], C::Goto.new(n))
					to.delete dcmp.dasm.normalize(n)
				elsif (di.opcode.name == 'end' or di.opcode.name == 'return') and retaddrs.include?(di.address)
					ret = C::CExpression[ce[Expression[Indirection[[:frameptr, :-, 8], 8]]]] unless func.type.type.kind_of?(C::BaseType) and func.type.type.name == :void
					stmts << C::Return.new(ret)
				elsif di.opcode.name == 'call' #or di.opcode.name == 'call_indirect'
					n = di.block.to_normal.first
					args = []
					if f = dcmp.c_parser.toplevel.symbol[n] and f.type.kind_of?(C::Function) and f.type.args
						# TODO
					end
					e = C::CExpression[f, :funcall, args]
					# TODO
					#e = C::CExpression[ce[abi_funcall[:retval]], :'=', e, f.type.type] if f.type.type != C::BaseType.new(:void)
					# TODO ensure dasm.bt_binding includes args pop from stack
					stmts << e
				else
					bd = get_fwdemu_binding(di)
					if di.backtrace_binding[:incomplete_binding]
						stmts << C::Asm.new(di.instruction.to_s, nil, nil, nil, nil, nil)
					else
						bd.each { |k, v|
							e = ce[k, :'=', v]
							stmts << e if not e.kind_of?(C::Variable)	# [:eflag_s, :=, :unknown].reduce
						}
					end
				end
			}

			case to.length
			when 0
				if not myblocks.empty? and not stmts.last.kind_of?(C::Return)
					puts "  block #{Expression[b]} has no to and don't end in ret"
				end
			when 1
				if (myblocks.empty? ? nextaddr != to[0] : myblocks.first.first != to[0])
					stmts << C::Goto.new(dcmp.dasm.auto_label_at(to[0], 'unknown_goto'))
				end
			else
				puts "  block #{Expression[b]} with multiple to"
			end
		end

		# cleanup di.bt_binding (we set :frameptr etc in those, this may confuse the dasm)
		blocks_toclean.each { |b_, to_|
			dcmp.dasm.decoded[b_].block.list.each { |di|
				di.backtrace_binding = nil
			}
		}
	end

	def decompile_check_abi(dcmp, entry, func)
	end
end
end
