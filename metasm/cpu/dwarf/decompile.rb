#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/dwarf/main'

module Metasm
class Dwarf
	def decompile_makestackvars(dasm, funcstart, blocks)
		oldbd = {}
		blocks.each { |block|
			oldbd[block.address] = dasm.address_binding[block.address]
			dasm.address_binding[block.address] = {}
                }

		dasm.address_binding[funcstart][:opstack] = Expression[:frameptr]
		blocks.each { |block|
			# cache the value of opstack wrt :frameptr at each block entry
			if not stkoff = dasm.address_binding[block.address][:opstack]
				stkoff = dasm.backtrace(:opstack, block.address, :snapshot_addr => funcstart)
				# conserve the minimum offset in case of conflicts
				stkoff = Expression[:frameptr] + stkoff.map { |so| so - :frameptr }.min
			end
			dasm.address_binding[block.address][:opstack] = stkoff
			block.list.first.misc ||= {}
			block.list.first.misc[:opstack_before] = stkoff

			# compute the value at the end of the block and propagate as start value for next blocks
			# allows coherent tracing along all paths if blocks are walked in code order, even with loops with stack leak/consume
			last_di = block.list.last
			stkoff = dasm.backtrace(:opstack, last_di.address, :snapshot_addr => funcstart, :include_start => true).first
			last_di.misc ||= {}
			last_di.misc[:opstack_after] = stkoff
			block.each_to_normal { |at|
				dasm.address_binding[at][:opstack] ||= stkoff if dasm.address_binding[at]
			}

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

		# TODO handle loops pushing/poping the stack (:opstack_before loop.first != :opstack_after loop.last)

		# opstack offset => current C variable
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
		ce_opstack_offset = lambda { |ee| ce_ptr_offset[ee, 'frameptr'] }

		basetype = C::BaseType.new("__int#@size".to_sym)
		new_opstack_var = lambda { |off|
			varname = "loc_#{off}"
			ne = C::Variable.new(varname, basetype)
			scope.symbol[varname] = ne
			stmts << C::Declaration.new(ne)
			ne
		}
		get_opstack_var = lambda { |off|
			opstack[off] ||= new_opstack_var[off]
		}

		di_addr = nil

		# Expr => CExpr
		ce = lambda { |*e|
			c_expr = dcmp.decompile_cexpr(Expression[Expression[*e].reduce], scope)
			dcmp.walk_ce(c_expr, true) { |ee|
				if soff = ce_opstack_offset[ee.rexpr]
					# must do soff.rexpr before lexpr in case of reaffectation !
					ee.rexpr = get_opstack_var[soff/8]
					ee.rexpr = C::CExpression[ee.rexpr] if not ee.op and ee.type.pointer?
				end
				if soff = ce_opstack_offset[ee.lexpr]
					ee.lexpr = get_opstack_var[soff/8]
				end
			}
			ret = if soff = ce_opstack_offset[c_expr]
					 C::CExpression[get_opstack_var[soff/8]]
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
				stmts << C::Label.new(l).with_misc(:di_addr => b)
			end

			# go !
			di_list = dcmp.dasm.decoded[b].block.list.dup
			di_list.each { |di|
				di_addr = di.address
				bd = get_fwdemu_binding(di)
				case di.opcode.name
				when 'bra'
					n = dcmp.backtrace_target(get_xrefs_x(dcmp.dasm, di).first, di.address)
					stacktop = ce[get_opstack_var[(bd[:opstack] - :frameptr + 8) / 8]]
					stmts << C::If.new(C::CExpression[stacktop], C::Goto.new(n).with_misc(:di_addr => di.address)).with_misc(:di_addr => di.address)
					stmts << ce[stacktop, :'=', 0]
					# XXX does not assign cond = 0 in if as decompiler may expect only single goto in if body
					to.delete dcmp.dasm.normalize(n)
				when 'swap'
					offs = []
					bd.each { |k, v|
						cvar = dcmp.decompile_cexpr(Expression[Expression[k].reduce], scope)
						if soff = ce_opstack_offset[cvar]
							offs << (soff/8)
						end
					}
					off = offs.min
					stmts << ce[get_opstack_var[:tmp], :'=', get_opstack_var[off]]
					stmts << ce[get_opstack_var[off], :'=', get_opstack_var[off+1]]
					stmts << ce[get_opstack_var[off+1], :'=', get_opstack_var[:tmp]]
					stmts << ce[get_opstack_var[:tmp],  :'=', 0]
				when 'rot'
					offs = []
					bd.each { |k, v|
						cvar = dcmp.decompile_cexpr(Expression[Expression[k].reduce], scope)
						if soff = ce_opstack_offset[cvar]
							offs << (soff/8)
						end
					}

					off = offs.min
					stmts << ce[get_opstack_var[:tmp],  :'=', get_opstack_var[off]]
					stmts << ce[get_opstack_var[off],   :'=', get_opstack_var[off+2]]
					stmts << ce[get_opstack_var[off+2], :'=', get_opstack_var[off+1]]
					stmts << ce[get_opstack_var[off+1], :'=', get_opstack_var[:tmp]]
					stmts << ce[get_opstack_var[:tmp],  :'=', 0]
				else
					if di.backtrace_binding[:incomplete_binding]
						stmts << C::Asm.new(di.instruction.to_s, nil, nil, nil, nil, nil).with_misc(:di_addr => di.address)
					else
						bd.each { |k, v|
							next if k == :opstack
							e = ce[k, :'=', v]
							stmts << e if not e.kind_of?(C::Variable)	# [:eflag_s, :=, :unknown].reduce
						}
						rawbd = dcmp.disassembler.cpu.get_backtrace_binding(di)
						if rawbd[:opstack] == Expression[:opstack, :-, 8] and (bd[:opstack] - :frameptr).kind_of?(::Integer)
							stacktop = ce[get_opstack_var[(bd[:opstack] - :frameptr + 8) / 8]]
							stmts << ce[stacktop, :'=', 0]
						end
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
					if dcmp.dasm.decoded[to[0]]
						stmts << C::Goto.new(dcmp.dasm.auto_label_at(to[0], 'unknown_goto'))
					else
						stmts << C::Return.new(C::CExpression[ce[get_opstack_var[(di_list.last.misc[:opstack_after] - :frameptr)/8]]])
					end
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
