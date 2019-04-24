#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/arm64/main'

module Metasm
class ARM64
	def abi_funcall
		@abi_funcall ||= { :changed => (0..18).map { |r| "x#{r}".to_sym } }
	end

	def decompile_makestackvars(dasm, funcstart, blocks)
		oldbd = {}
		oldbd[funcstart] = dasm.address_binding[funcstart]
		dasm.address_binding[funcstart] = { :sp => Expression[:frameptr] }
		blocks.each { |block|
			oldbd[block.address] = dasm.address_binding[block.address]
			stkoff = dasm.backtrace(:sp, block.address, :snapshot_addr => funcstart)
			dasm.address_binding[block.address] = { :sp => Expression[:frameptr, :+, stkoff[0]-:frameptr] }
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
		func.type.args.each { |a| scope.symbol[a.name] = a }
		stmts = scope.statements

		di_addr = nil

		# Expr => CExpr
		ce = lambda { |*e|
			c_expr = dcmp.decompile_cexpr(Expression[Expression[*e].reduce], scope)
			dcmp.walk_ce(c_expr) { |ee| ee.with_misc :di_addr => di_addr } if di_addr
			c_expr
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
				# TODO jz/jnz
				if di.opcode.props[:setip] and not di.opcode.props[:stopexec]
					case di.opcode.name
					when 'cbz'
						cc = Expression[di.instruction.args.first.symbolic, :==, 0]
					when 'cbnz'
						cc = Expression[di.instruction.args.first.symbolic, :!=, 0]
					when /^b(.*)/
						cc = decode_cc_to_expr($1)
					end
					n = dcmp.backtrace_target(get_xrefs_x(dcmp.dasm, di).first, di.address)
					bd = get_fwdemu_binding(di)
					stmts << C::If.new(ce[cc], C::Goto.new(n).with_misc(:di_addr => di.address)).with_misc(:di_addr => di.address)
					to.delete dcmp.dasm.normalize(n)
				elsif di.opcode.name == 'ret'
					ret = ce[:x0]
					stmts << C::Return.new(ret).with_misc(:di_addr => di.address)
				elsif di.opcode.name == 'bl'
					n = dcmp.backtrace_target(get_xrefs_x(dcmp.dasm, di).first, di.address)
					args = []
					if f = dcmp.c_parser.toplevel.symbol[n] and f.type.kind_of?(C::Function) and f.type.args
						f.type.args.each_with_index { |a, i| args << ce["x#{i}".to_sym] }
					end

					if not n.kind_of?(::String) or (f and not f.type.kind_of?(C::Function))
						# indirect funcall
						fptr = ce[n]
						proto = C::Function.new(C::BaseType.new(:__int64))
						proto = f.type if f and f.type.kind_of? C::Function
						f = C::CExpression[[fptr], C::Pointer.new(proto)]
					elsif not f
						# internal functions are predeclared, so this one is extern
						f = C::Variable.new
						f.name = n
						f.type = C::Function.new(C::BaseType.new(:__int64))
						if dcmp.recurse > 0
							dcmp.c_parser.toplevel.symbol[n] = f
							dcmp.c_parser.toplevel.statements << C::Declaration.new(f)
						end
					end
					e = C::CExpression[f, :funcall, args].with_misc(:di_addr => di_addr)
					e = C::CExpression[ce[:x0], :'=', e, f.type.type].with_misc(:di_addr => di_addr) if f.type.type != C::BaseType.new(:void)
					stmts << e
				else
					bd = get_fwdemu_binding(di)
					if di.backtrace_binding[:incomplete_binding]
						stmts << C::Asm.new(di.instruction.to_s, nil, nil, nil, nil, nil).with_misc(:di_addr => di.address)
					else
						bd.each { |k, v|
							e = ce[k, :'=', v]
							stmts << e #if not e.kind_of?(C::Variable)	# [:eflag_s, :=, :unknown].reduce
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
