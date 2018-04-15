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
		@wasm_file.global.to_a.each_with_index { |g, idx|
			var = C::Variable.new
			var.name = 'global_%d' % idx
			var.type = C::Array.new(wasm_type_to_type(g[:type]), 1)
			dcmp.c_parser.toplevel.symbol[var.name] = var
			dcmp.c_parser.toplevel.statements << C::Declaration.new(var)
			# TODO init
		}
		@wasm_file.import.to_a.each { |i|
			case i[:kind]
			when 'global'
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
	end

	def abi_funcall
		@abi_funcall ||= { :changed => [] }
	end

	def decompile_makestackvars(dasm, funcstart, blocks)
		oldfuncbd = dasm.address_binding[funcstart]
		dasm.address_binding[funcstart] = { :opstack => Expression[:frameptr] }
		blocks.each { |block| yield block }
		dasm.address_binding[funcstart] = oldfuncbd
	end

	def decompile_func_finddeps_di(dcmp, func, di, a, w)
	end

	def decompile_func_finddeps(dcmp, blocks, func)
		{}
	end

	def decompile_blocks(dcmp, myblocks, deps, func, nextaddr = nil)
		func_entry = myblocks.first[0]
		retaddrs = dcmp.dasm.function[func_entry].return_address
		w_func = @wasm_file.function_body.find { |fb| fb[:init_offset] == func_entry }
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
			if loff = ce_local_offset[c_expr]
				C::CExpression[local[loff/8]]
			elsif soff = ce_opstack_offset[c_expr]
				C::CExpression[opstack[-soff/8]]
			else
				c_expr
			end
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
				if di.opcode.name == 'if' or di.opcode.name == 'br_if'
					n = dcmp.backtrace_target(get_xrefs_x(dcmp.dasm, di).first, di.address)
					bd = get_fwdemu_binding(di)
					if di.opcode.name == 'if'
						cc = ce[:!, bd[:flag]]
					else
						cc = ce[bd[:flag]]
					end
					stmts << C::If.new(C::CExpression[cc], C::Goto.new(n))
					to.delete dcmp.dasm.normalize(n)
				elsif (di.opcode.name == 'end' or di.opcode.name == 'return') and retaddrs.include?(di.address)
					fsig = w_func[:type]
					rettype = wasm_type_to_type(fsig[:ret].first) if fsig[:ret] and fsig[:ret].first
					ret = C::CExpression[ce[Expression[Indirection[[:frameptr, :-, 8], dcmp.sizeof(rettype)]]]] unless fsig[:ret].empty?
					stmts << C::Return.new(ret)
				elsif di.opcode.name == 'call' #or di.opcode.name == 'call_indirect'
					f_w = @wasm_file.get_function_nr(di.misc[:tg_func_nr])
					raise "no call target for #{di} @#{di.misc[:tg_func_nr]}" if not f_w
					if f_w[:init_offset]
						tg = dcmp.dasm.auto_label_at(f_w[:init_offset], 'sub')
					else
						tg = '%s_%s' % [f_w[:module], f_w[:field]]
					end
					f = dcmp.c_parser.toplevel.symbol[tg]
					raise "no global function #{tg} for #{di}" if not f

					args = []
					bd = get_fwdemu_binding(di)
					i = 0
					while bd_arg = bd["param_#{i}"]
						args << ce[bd_arg]
						i += 1
					end
					e = C::CExpression[f, :funcall, args]
					if bd_ret = bd.index(Expression["ret_0"])
						e = C::CExpression[ce[bd_ret], :'=', e, f.type.type]
					end
					stmts << e
				else
					bd = get_fwdemu_binding(di)
					if di.backtrace_binding[:incomplete_binding]
						stmts << C::Asm.new(di.instruction.to_s, nil, nil, nil, nil, nil)
					else
						bd.each { |k, v|
							next if k == :opstack
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
