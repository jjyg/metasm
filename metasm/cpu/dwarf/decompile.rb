#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/dwarf/main'

module Metasm
class Dwarf
	def decompile_makestackvars(dasm, funcstart, blocks)
		@decomp_mkstackvars_terminals = [:frameptr, :mem]
		oldbd = {}
		oldbd[funcstart] = dasm.address_binding[funcstart]
		dasm.address_binding[funcstart] = { :opstack => Expression[:frameptr] }
		blocks.each { |block|
			oldbd[block.address] = dasm.address_binding[block.address]
			stkoff = dasm.backtrace(:opstack, block.address, :snapshot_addr => funcstart)
			dasm.address_binding[block.address] = { :opstack => Expression[:frameptr, :+, stkoff[0]-:frameptr] }
			yield block
		}
		oldbd.each { |a, b| b ? dasm.address_binding[a] = b : dasm.address_binding.delete(a) }
	end

	def decompile_func_finddeps_di(dcmp, func, di, a, w)
	end

	def decompile_func_finddeps(dcmp, blocks, func)
		{}
	end

	def decompile_blocks(dcmp, myblocks, deps, func, nextaddr = nil)
		scope = func.initializer
		stmts = scope.statements

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
		ce_opstack_offset = lambda { |ee| ce_ptr_offset[ee, 'frameptr'] }

		di_addr = nil

		basetype = C::BaseType.new("__int#@size".to_sym)
		# Expr => CExpr
		ce = lambda { |*e|
			c_expr = dcmp.decompile_cexpr(Expression[Expression[*e].reduce], scope)
			dcmp.walk_ce(c_expr, true) { |ee|
				if soff = ce_opstack_offset[ee.rexpr]
					# must do soff.rexpr before lexpr in case of reaffectation !
					ee.rexpr = opstack[-soff/8]
					ee.rexpr = C::CExpression[ee.rexpr] if not ee.op and ee.type.pointer?
				end
				if soff = ce_opstack_offset[ee.lexpr]
					if ee.op == :'='
						# affectation: create a new variable
						varname = "loc_#{opstack_idx += 1}"
						ne = C::Variable.new(varname, basetype)
						scope.symbol[varname] = ne
						stmts << C::Declaration.new(ne)
						opstack[-soff/8] = ne
					end
					ee.lexpr = opstack[-soff/8]
				end
			}
			ret = if soff = ce_opstack_offset[c_expr]
				C::CExpression[opstack[-soff/8]]
			else
				c_expr
			end
			dcmp.walk_ce(ret) { |ee| ee.with_misc :di_addr => di_addr } if di_addr
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
				if di.opcode.name == 'bra'
					n = dcmp.backtrace_target(get_xrefs_x(dcmp.dasm, di).first, di.address)
					cc = ce[Indirection[:opstack, @size/8]]
					stmts << C::If.new(C::CExpression[cc], C::Goto.new(n).with_misc(:di_addr => di.address)).with_misc(:di_addr => di.address)
					to.delete dcmp.dasm.normalize(n)
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
	end
end
end
