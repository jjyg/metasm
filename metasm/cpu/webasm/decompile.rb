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
		mem = dcmp.c_parser.toplevel.symbol['mem'] = C::Variable.new('mem', C::Pointer.new(C::BaseType.new(:char)))
		mem.storage = :static
		dcmp.c_parser.toplevel.statements << C::Declaration.new(mem)

		global_idx = 0
		@wasm_file.import.to_a.each { |i|
			case i[:kind]
			when 'global'
				global_idx += 1
				var = C::Variable.new
				var.name = '%s_%s' % [i[:module], i[:field]]
				var.type = C::Array.new(wasm_type_to_type(i[:type]), 1)
				var.storage = :extern
				dcmp.c_parser.toplevel.symbol[var.name] = var
				dcmp.c_parser.toplevel.statements << C::Declaration.new(var)
			when 'function'
				var = C::Variable.new
				var.name = '%s_%s' % [i[:module], i[:field]]
				var.type = wasm_type_to_type(i[:type])
				var.storage = :extern
				dcmp.c_parser.toplevel.symbol[var.name] = var
				dcmp.c_parser.toplevel.statements << C::Declaration.new(var)
			end
		}

		@wasm_file.global.to_a.each_with_index { |g, idx|
			g_name = 'global_%d' % global_idx
			global_idx += 1
			var = C::Variable.new
			var.name = g_name
			var.type = C::Array.new(wasm_type_to_type(g[:type]), 1)
			var.storage = :static
			dcmp.c_parser.toplevel.symbol[var.name] = var
			dcmp.c_parser.toplevel.statements << C::Declaration.new(var)

			# decompile initializers
			g_init_name = g_name + '_init'
			dcmp.dasm.disassemble(g_init_name)
			dcmp.decompile_func(g_init_name)
			if init = dcmp.c_parser.toplevel.symbol[g_init_name] and init.initializer.kind_of?(C::Block) and
					init.initializer.statements.first.kind_of?(C::Return)
				dcmp.c_parser.toplevel.symbol[g_name].initializer = [ init.initializer.statements.first.value ]
				dcmp.c_parser.toplevel.symbol.delete(g_init_name)
				dcmp.c_parser.toplevel.statements.delete_if { |st| st.kind_of?(C::Declaration) and st.var.name == g_init_name }
			end
		}

		@wasm_file.table.to_a.each_with_index { |t, idx|
			break if idx > 0
			t_name = 'indirect_calltable'
			var = C::Variable.new
			var.name = t_name
			sz = t[:limits][:initial_size]
			var.type = C::Array.new(C::Pointer.new(wasm_type_to_type(t[:type])), sz)
			var.storage = :static
			dcmp.c_parser.toplevel.symbol[var.name] = var
			dcmp.c_parser.toplevel.statements << C::Declaration.new(var)
			var.initializer = [C::CExpression[0]] * sz

			# initializer
			@wasm_file.element.to_a.each_with_index { |e, eidx|
				next if e[:table_index] != idx
				# address of the code that evals the index at which to place the elements inside the table
				e_init_name = "element_#{eidx}_init_addr"
				dcmp.dasm.disassemble(e_init_name)
				dcmp.decompile_func(e_init_name)
				if init = dcmp.c_parser.toplevel.symbol[e_init_name] and init.initializer.kind_of?(C::Block) and
						init.initializer.statements.first.kind_of?(C::Return)
					eoff = init.initializer.statements.first.value.reduce(dcmp.c_parser)
					dcmp.c_parser.toplevel.symbol.delete(e_init_name)
					dcmp.c_parser.toplevel.statements.delete_if { |st| st.kind_of?(C::Declaration) and st.var.name == e_init_name }
					e[:elems].each_with_index { |ev, vidx|
						# table 0 is the only table in a wasm file and contains a list of function indexes used with the call_indirect asm instruction
						# e_init_name gives the index at which we should put e[:elems], and we convert the func indexes into C names
						vidx += eoff
						if vidx >= sz or vidx < 0
							puts "W: initializing indirect_calltable, would put #{ev} beyond end of table (#{vidx} > #{sz})"
							next
						end
						if not tg_func = @wasm_file.get_function_nr(ev)
							puts "W: initializing indirect_calltable, bad func index #{ev}"
							next
						end
						funcname = dcmp.dasm.get_label_at(tg_func[:init_offset]) || "func_at_#{'%x' % tg_func[:init_offset]}"
						# XXX should decompile funcname now ?
						var.initializer[vidx] = C::CExpression[:&, C::Variable.new(funcname)]
					}
				end
			}
		}
	end

	def abi_funcall
		@abi_funcall ||= { :changed => [] }
	end

	def decompile_makestackvars(dasm, funcstart, blocks)
		@decomp_mkstackvars_terminals = [:frameptr, :local_base, :mem]
		oldbd = {}
		oldbd[funcstart] = dasm.address_binding[funcstart]
		dasm.address_binding[funcstart] = { :opstack => Expression[:frameptr] }
		blocks.each { |block|
			oldbd[block.address] = dasm.address_binding[block.address]
			stkoff = dasm.backtrace(:opstack, block.address, :snapshot_addr => funcstart)
			dasm.address_binding[block.address] = { :opstack => Expression[:frameptr, :+, stkoff[0]-:frameptr] }
			yield block
			# store frameptr offset at each 'end' 'return' or 'else' instruction
			if di = block.list.last and %w[end return else].include?(di.opcode.name)
				stkoff = dasm.backtrace(:opstack, di.address, :snapshot_addr => funcstart)
				if stkoff.length == 1 and (stkoff[0] - :frameptr).kind_of?(::Integer)
					di.misc[:dcmp_stackoff] = stkoff[0] - :frameptr
				end
			end
		}
		oldbd.each { |a, b| b ? dasm.address_binding[a] = b : dasm.address_binding.delete(a) }
	end

	def decompile_func_finddeps_di(dcmp, func, di, a, w)
	end

	def decompile_func_finddeps(dcmp, blocks, func)
		{}
	end

	def decompile_blocks(dcmp, myblocks, deps, func, nextaddr = nil)
		func_entry = myblocks.first[0]
		if w_func = @wasm_file.function_body.find { |fb| fb[:init_offset] == func_entry }
		elsif g = @wasm_file.global.find { |gg| gg[:init_offset] == func_entry }
			w_func = { :local_var => [], :type => { :params => [], :ret => [g[:type]] } }
		elsif (@wasm_file.element.to_a + @wasm_file.data.to_a).find { |gg| gg[:init_offset] == func_entry }
			w_func = { :local_var => [], :type => { :params => [], :ret => ['i32'] } }
		end
		scope = func.initializer
		func.type.args.each { |a| scope.symbol[a.name] = a }
		stmts = scope.statements

		local = []
		w_func[:type][:params].each { |t|
			local << C::Variable.new("arg_#{local.length}", wasm_type_to_type(t))
			scope.symbol[local.last.name] = local.last
			func.type.args << local.last
		}
		w_func[:local_var].each { |t|
			local << C::Variable.new("var_#{local.length}", wasm_type_to_type(t))
			scope.symbol[local.last.name] = local.last
			local.last.initializer = C::CExpression[0]
			stmts << C::Declaration.new(local.last)
		}

		opstack = {}

		# *(_int32*)(local_base+16) => 16
		ce_ptr_offset = lambda { |ee, base|
			if ee.kind_of?(C::CExpression) and ee.op == :* and not ee.lexpr and ee.rexpr.kind_of?(C::CExpression) and
					not ee.rexpr.op and ee.rexpr.rexpr.kind_of?(C::CExpression)
				if not ee.rexpr.rexpr.op and ee.rexpr.rexpr.rexpr.kind_of?(C::Variable) and ee.rexpr.rexpr.rexpr.name == base
					0
				elsif ee.rexpr.rexpr.lexpr.kind_of?(C::Variable) and ee.rexpr.rexpr.lexpr.name == base and
						ee.rexpr.rexpr.rexpr.kind_of?(C::CExpression) and not ee.rexpr.rexpr.rexpr.op and ee.rexpr.rexpr.rexpr.rexpr.kind_of?(::Integer)
					if ee.rexpr.rexpr.op == :+
						ee.rexpr.rexpr.rexpr.rexpr
					elsif ee.rexpr.rexpr.op == :-
						-ee.rexpr.rexpr.rexpr.rexpr
					end
				end
			end
		}
		opstack_idx = -1
		ce_local_offset = lambda { |ee| ce_ptr_offset[ee, 'local_base'] }
		ce_opstack_offset = lambda { |ee| ce_ptr_offset[ee, 'frameptr'] }

		di_addr = nil

		# Expr => CExpr
		ce = lambda { |*e|
			c_expr = dcmp.decompile_cexpr(Expression[Expression[*e].reduce], scope)
			dcmp.walk_ce(c_expr, true) { |ee|
				if ee.rexpr.kind_of?(::Array)
					# funcall arglist
					ee.rexpr.map! { |eee|
						if loff = ce_local_offset[eee]
							C::CExpression[local[loff/8]]
						elsif soff = ce_opstack_offset[eee]
							C::CExpression[opstack[-soff/8]]
						else
							eee
						end
					}
				end
				if loff = ce_local_offset[ee.lexpr]
					ee.lexpr = local[loff/8]
				end
				if loff = ce_local_offset[ee.rexpr]
					ee.rexpr = local[loff/8]
					ee.rexpr = C::CExpression[ee.rexpr] if not ee.op and ee.type.pointer?
				end
				if soff = ce_opstack_offset[ee.rexpr]
					# must do soff.rexpr before lexpr in case of reaffectation !
					ee.rexpr = opstack[-soff/8]
					ee.rexpr = C::CExpression[ee.rexpr] if not ee.op and ee.type.pointer?
				end
				if soff = ce_opstack_offset[ee.lexpr]
					if ee.op == :'='
						# affectation: create a new variable
						varname = "loc_#{opstack_idx += 1}"
						ne = C::Variable.new(varname, wasm_type_to_type("i#{8*dcmp.sizeof(ee.lexpr)}"))
						scope.symbol[varname] = ne
						stmts << C::Declaration.new(ne)
						opstack[-soff/8] = ne
					end
					ee.lexpr = opstack[-soff/8]
				end
			}
			ret = if loff = ce_local_offset[c_expr]
				C::CExpression[local[loff/8]]
			elsif soff = ce_opstack_offset[c_expr]
				C::CExpression[opstack[-soff/8]]
			else
				c_expr
			end
			dcmp.walk_ce(ret) { |ee| ee.with_misc :di_addr => di_addr if di_addr }
			ret
		}


		blocks_toclean = myblocks.dup
		until myblocks.empty?
			b, to = myblocks.shift
			if l = dcmp.dasm.get_label_at(b)
				stmts << C::Label.new(l)
			end

			# go !
			di_list = dcmp.dasm.decoded[b].block.list.dup
			di_list.each { |di|
				di_addr = di.address
				if di.opcode.name == 'if' or di.opcode.name == 'br_if'
					n = dcmp.backtrace_target(get_xrefs_x(dcmp.dasm, di).first, di.address)
					bd = get_fwdemu_binding(di)
					if di.opcode.name == 'if'
						cc = ce[:!, bd[:flag]]
					else
						cc = ce[bd[:flag]]
					end
					stmts << C::If.new(C::CExpression[cc], C::Goto.new(n).with_misc(:di_addr => di.address)).with_misc(:di_addr => di.address)
					to.delete dcmp.dasm.normalize(n)
				elsif (di.opcode.name == 'end' or di.opcode.name == 'return') and di.opcode.props[:stopexec]
					fsig = w_func[:type]
					rettype = wasm_type_to_type(fsig[:ret].first) if fsig[:ret] and fsig[:ret].first
					if not fsig[:ret].empty?
						off = di.misc[:dcmp_stackoff] || -8
						ret = C::CExpression[ce[Indirection[[:frameptr, :+, off], dcmp.sizeof(rettype)]]]
					end
					stmts << C::Return.new(ret).with_misc(:di_addr => di.address)
				elsif (di.opcode.name == 'end' or di.opcode.name == 'else') and di.misc[:dcmp_stackoff] and di.misc[:end_of]
					# end of block returning a value: store the value in a real variable instead of the autogenerated local
					# so that if { } else {} both update the same var
					start = di.misc[:end_of]
					start_rettype = start.instruction.args.first.to_s
					if start_rettype != 'none'
						retsz = dcmp.sizeof(wasm_type_to_type(start_rettype))
						off = di.misc[:dcmp_stackoff]
						if not start.misc[:dcmp_retval] or not scope.symbol[start.misc[:dcmp_retval]]
							stmts << C::CExpression[ce[Indirection[[:frameptr, :+, off], retsz], :'=', Indirection[[:frameptr, :+, off], retsz]]]
							start.misc[:dcmp_retval] = stmts.last.lexpr.name
						else
							stmts << C::CExpression[ce[scope.symbol[start.misc[:dcmp_retval]], :'=', Indirection[[:frameptr, :+, off], retsz]]]
						end
					end
				elsif di.opcode.name == 'call'
					tg = di.misc[:x].first
					raise "no call target for #{di}" if not tg
					tg = dcmp.dasm.auto_label_at(tg, 'sub') if dcmp.dasm.get_section_at(tg)
					f = dcmp.c_parser.toplevel.symbol[tg]
					raise "no global function #{tg} for #{di}" if not f

					args = []
					bd = get_fwdemu_binding(di)
					i = 0
					while bd_arg = bd["param_#{i}"]
						args << ce[bd_arg]
						i += 1
					end
					e = C::CExpression[f, :funcall, args].with_misc(:di_addr => di.address)
					if bd_ret = bd.index(Expression["ret_0"])
						e = ce[bd_ret, :'=', e]
					end
					stmts << e
				elsif di.opcode.name == 'call_indirect'
					args = []
					bd = get_fwdemu_binding(di)
					wt = @wasm_file.type[di.instruction.args.first.reduce]
					fptr = C::CExpression[[dcmp.c_parser.toplevel.symbol['indirect_calltable'], :[], ce[bd['func_idx']]], wasm_type_to_type(wt)]
					i = 0
					while bd_arg = bd["param_#{i}"]
						args << ce[bd_arg]
						i += 1
					end
					e = C::CExpression[fptr, :funcall, args].with_misc(:di_addr => di.address)
					if bd_ret = bd.index(Expression["ret_0"])
						e = ce[bd_ret, :'=', e]
					end
					stmts << e
				else
					bd = get_fwdemu_binding(di)
					if di.backtrace_binding[:incomplete_binding]
						stmts << C::Asm.new(di.instruction.to_s, nil, nil, nil, nil, nil).with_misc(:di_addr => di.address)
					else
						bd.each { |k, v|
							next if k == :opstack
							e = ce[k, :'=', v]
							stmts << e if not e.kind_of?(C::Variable)	# [:eflag_s, :=, :unknown].reduce
						}
					end
				end
				di_addr = nil
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
		scope = func.initializer
		@wasm_file.function_body.to_a.each { |fb|
			next if fb[:init_offset] != entry
			w_type = wasm_type_to_type(fb[:type])
			func.type.type = w_type.type
			if func.type.args.length > w_type.args.length
				# detected an argument that is actually a local variable, move into func scope
				while a = func.type.args.delete_at(w_type.args.length)
					if a.has_attribute('unused')
						scope.symbol.delete a.name
					else
						a.initializer = C::CExpression[0]
						scope.statements[0, 0] = [C::Declaration.new(a)]
					end
				end
			end
		}
	end
end
end
