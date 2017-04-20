#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/openrisc/main'

module Metasm
class OpenRisc
	# temporarily setup dasm.address_binding so that backtracking
	# stack-related offsets resolve in :frameptr (relative to func start)
	def decompile_makestackvars(dasm, funcstart, blocks)
		oldfuncbd = dasm.address_binding[funcstart]
		dasm.address_binding[funcstart] = { :r1 => :frameptr }
		blocks.each { |block| yield block }
		dasm.address_binding[funcstart] = oldfuncbd if oldfuncbd
	end

	# add di-specific registry written/accessed
	def decompile_func_finddeps_di(dcmp, func, di, a, w)
		a << abi_funcall[:retval] if di.instruction.to_s == 'jr r9' and (not func.type.kind_of?(C::BaseType) or func.type.type.name != :void)	# standard ABI
	end

	# list of register symbols
	def register_symbols
		@dbg_register_list ||= (1..31).to_a.map { |i| "r#{i}".to_sym }
	end

	# returns a hash { :retval => r, :changed => [] }
	def abi_funcall
		{ :retval => :r11, :changed => [3, 4, 5, 6, 7, 8, 11, 12, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31].map { |n| "r#{n}".to_sym }, :args => [:r3, :r4, :r5, :r6, :r7, :r8] }
	end

	# list variable dependency for each block, remove useless writes
	# returns { blockaddr => [list of vars that are needed by a following block] }
	def decompile_func_finddeps(dcmp, blocks, func)
		deps_r = {} ; deps_w = {} ; deps_to = {}
		deps_subfunc = {}	# things read/written by subfuncs

		# find read/writes by each block
		blocks.each { |b, to|
			deps_r[b] = [] ; deps_w[b] = [] ; deps_to[b] = to
			deps_subfunc[b] = []

			blk = dcmp.dasm.decoded[b].block
			blk.list.each { |di|
				a = di.backtrace_binding.values
				w = []
				di.backtrace_binding.keys.each { |k|
					case k
					when ::Symbol; w |= [k]
					else a |= Expression[k].externals	# if dword [eax] <- 42, eax is read
					end
				}
				decompile_func_finddeps_di(dcmp, func, di, a, w)

				deps_r[b] |= a.map { |ee| Expression[ee].externals.grep(::Symbol) }.flatten - [:unknown] - deps_w[b]
				deps_w[b] |= w.map { |ee| Expression[ee].externals.grep(::Symbol) }.flatten - [:unknown]
			}
			subfunccall = false
			blk.each_to_normal { |t|
				t = dcmp.backtrace_target(t, blk.list.last.address)
				next if not t = dcmp.c_parser.toplevel.symbol[t]
				t.type = C::Function.new(C::BaseType.new(:int)) if not t.type.kind_of?(C::Function)	# XXX this may seem a bit extreme, and yes, it is.
				subfunccall = true
				t.type.args.to_a.each { |arg|
					if reg = arg.has_attribute('register')
						deps_subfunc[b] |= [reg.to_sym]
					end
				}
			}
			if subfunccall	# last block instr == subfunction call
				deps_r[b] |= deps_subfunc[b] - deps_w[b]
				deps_w[b] |= abi_funcall[:changed]
			end
		}

		bt = blocks.transpose
		roots = bt[0] - bt[1].flatten	# XXX jmp 1stblock ?

		# find regs read and never written (must have been set by caller and are part of the func ABI)
		uninitialized = lambda { |b, r, done|
			if not deps_r[b]
			elsif deps_r[b].include?(r)
				blk = dcmp.dasm.decoded[b].block
				bw = []
				rdi = blk.list.find { |di|
					a = di.backtrace_binding.values
					w = []
					di.backtrace_binding.keys.each { |k|
						case k
						when ::Symbol; w |= [k]
						else a |= Expression[k].externals	# if dword [eax] <- 42, eax is read
						end
					}
					decompile_func_finddeps_di(dcmp, func, di, a, w)

					next true if (a.map { |ee| Expression[ee].externals.grep(::Symbol) }.flatten - [:unknown] - bw).include?(r)
					bw |= w.map { |ee| Expression[ee].externals.grep(::Symbol) }.flatten - [:unknown]
					false
				}
				if decompile_func_abi_fcallret(r, rdi, blk)
					func.type.type = C::BaseType.new(:void)
					false
				elsif rdi and rdi.backtrace_binding[r]
					false	# mov al, 42 ; ret  -> don't regarg eax
				else
					true
				end
			elsif deps_w[b].include?(r)
			else
				done << b
				(deps_to[b] - done).find { |tb| uninitialized[tb, r, done] }
			end
		}

		regargs = []
		register_symbols.each { |r|
			if roots.find { |root| uninitialized[root, r, []] }
				regargs << r
			end
		}

		# TODO honor user-defined prototype if available (eg no, really, eax is not read in this function returning al)
		regargs.sort_by { |r| r.to_s }.each { |r|
			a = C::Variable.new(r.to_s, C::BaseType.new(:int, :unsigned))
			a.add_attribute("register(#{r})")
			func.type.args << a
		}

		# remove writes from a block if no following block read the value
		dw = {}
		deps_w.each { |b, deps|
			dw[b] = deps.reject { |dep|
				ret = true
				done = []
				todo = deps_to[b].dup
				while a = todo.pop
					next if done.include?(a)
					done << a
					if not deps_r[a] or deps_r[a].include?(dep)
						ret = false
						break
					elsif not deps_w[a].include?(dep)
						todo.concat deps_to[a]
					end
				end
				ret
			}
		}

		dw
	end

	# return true if r is the implicit register read made by the subfunction return instruction to symbolize the return value ABI
	def decompile_func_abi_fcallret(r, rdi, blk)
		rdi ||= blk.list[-1-@delay_slot]
		return if not rdi
		r == abi_funcall[:retval] and rdi.instruction.to_s == 'jr r9'
	end

	def decompile_blocks(dcmp, myblocks, deps, func, nextaddr = nil)
		scope = func.initializer
		func.type.args.each { |a| scope.symbol[a.name] = a }
		stmts = scope.statements
		blocks_toclean = myblocks.dup
		func_entry = myblocks.first[0]
		until myblocks.empty?
			b, to = myblocks.shift
			if l = dcmp.dasm.get_label_at(b)
				stmts << C::Label.new(l)
			end

			# list of assignments [[dest reg, expr assigned]]
			ops = []
			# reg binding (reg => value, values.externals = regs at block start)
			binding = {}
			# Expr => CExpr
			ce  = lambda { |*e| dcmp.decompile_cexpr(Expression[Expression[*e].reduce], scope) }
			# Expr => Expr.bind(binding) => CExpr
			ceb = lambda { |*e| ce[Expression[*e].bind(binding)] }

			# dumps a CExprs that implements an assignment to a reg (uses ops[], patches op => [reg, nil])
			commit = lambda {
				deps[b].map { |k|
					[k, ops.rindex(ops.reverse.find { |r, v| r == k })]
				}.sort_by { |k, i| i.to_i }.each { |k, i|
					next if not i or not binding[k]
					e = k
					final = []
					ops[0..i].reverse_each { |r, v|
						final << r if not v
						e = Expression[e].bind(r => v).reduce if not final.include?(r)
					}
					ops[i][1] = nil
					binding.delete k
					stmts << ce[k, :'=', e] if k != e
				}
			}

			# returns an array to use as funcall arguments
			get_func_args = lambda { |di, f|
				# XXX see remarks in #finddeps
				args_todo = f.type.args.to_a.dup
				args = []
				args_abi = abi_funcall[:args].dup
				args_todo.each { |a_|
					if r = a_.has_attribute_var('register')
						args << Expression[r.to_sym]
						args_abi.delete r.to_sym
					else
						args << Expression[args_abi.shift]
					end
				}

				if f.type.varargs
					nargs = 1
					if f.type.args.last.type.pointer?
						# check if last arg is a fmtstring
						bt = dcmp.dasm.backtrace(args.last, di.block.list.last.address, :snapshot_addr => func_entry, :include_start => true)
						if bt.length == 1 and s = dcmp.dasm.get_section_at(bt.first)
							fmt = s[0].read(512)
							fmt = fmt.unpack('v*').pack('C*') if dcmp.sizeof(f.type.args.last.type.untypedef.type) == 2
							if fmt.index(?\0)
								fmt = fmt[0...fmt.index(?\0)]
								nargs = fmt.gsub('%%', '').count('%')	# XXX %.*s etc..
							end
						end
					end
					bt = dcmp.dasm.backtrace(:r1, di.block.list.last.address, :snapshot_addr => func_entry, :include_start => true)
					stackoff = Expression[bt, :-, :r1].bind(:r1 => :frameptr).reduce rescue nil
					if stackoff and nargs > 0
						nargs.times {
							args << Indirection[[:frameptr, :+, stackoff], @size/8]
							stackoff += @size/8
						}
					end
				end

				args.map { |e| ceb[e] }
			}

			# go !
			di_list = dcmp.dasm.decoded[b].block.list.dup
			if di_list[-2] and di_list[-2].opcode.props[:setip] and @delay_slot > 0
				di_list[-1], di_list[-2] = di_list[-2], di_list[-1]
			end
			di_list.each { |di|
				if di.opcode.props[:setip] and not di.opcode.props[:stopexec]
					# conditional jump
					commit[]
					n = dcmp.backtrace_target(get_xrefs_x(dcmp.dasm, di).first, di.address)
					if di.opcode.name == /bfeq/
						cc = ceb[:flag]
					else
						cc = ceb[:!, :flag]
					end
					# XXX switch/indirect/multiple jmp
					stmts << C::If.new(C::CExpression[cc], C::Goto.new(n))
					to.delete dcmp.dasm.normalize(n)
					next
				end

				if di.instruction.to_s == 'jr r9'
					commit[]
					ret = C::CExpression[ceb[abi_funcall[:retval]]] unless func.type.type.kind_of?(C::BaseType) and func.type.type.name == :void
					stmts << C::Return.new(ret)
				elsif di.opcode.name == 'jal' or di.opcode.name == 'jalr'
					n = dcmp.backtrace_target(get_xrefs_x(dcmp.dasm, di).first, di.address)
					args = []
					if f = dcmp.c_parser.toplevel.symbol[n] and f.type.kind_of?(C::Function) and f.type.args
						args = get_func_args[di, f]
					end
					commit[]
					#next if not di.block.to_subfuncret

					if not n.kind_of?(::String) or (f and not f.type.kind_of?(C::Function))
						# indirect funcall
						fptr = ceb[n]
						binding.delete n
						proto = C::Function.new(C::BaseType.new(:int))
						proto = f.type if f and f.type.kind_of?(C::Function)
						f = C::CExpression[[fptr], C::Pointer.new(proto)]
					elsif not f
						# internal functions are predeclared, so this one is extern
						f = C::Variable.new
						f.name = n
						f.type = C::Function.new(C::BaseType.new(:int))
						if dcmp.recurse > 0
							dcmp.c_parser.toplevel.symbol[n] = f
							dcmp.c_parser.toplevel.statements << C::Declaration.new(f)
						end
					end
					commit[]
					binding.delete abi_funcall[:retval]
					e = C::CExpression[f, :funcall, args]
					e = C::CExpression[ce[abi_funcall[:retval]], :'=', e, f.type.type] if deps[b].include?(abi_funcall[:retval]) and f.type.type != C::BaseType.new(:void)
					stmts << e
				else
					bd = get_fwdemu_binding(di)
					if di.backtrace_binding[:incomplete_binding]
						commit[]
						stmts << C::Asm.new(di.instruction.to_s, nil, nil, nil, nil, nil)
					else
						update = {}
						bd.each { |k, v|
							if k.kind_of?(::Symbol) and not deps[b].include?(k)
								ops << [k, v]
								update[k] = Expression[Expression[v].bind(binding).reduce]
							else
								stmts << ceb[k, :'=', v]
								stmts.pop if stmts.last.kind_of?(C::Variable)	# [:eflag_s, :=, :unknown].reduce
							end
						}
						binding.update update
					end
				end
			}
			commit[]

			case to.length
			when 0
				if not myblocks.empty? and (dcmp.dasm.decoded[b].block.list[-1-@delay_slot].instruction.to_s != 'jr r9' rescue true)
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
		a = func.type.args || []
		# TODO check abi_funcall[:args], dont delete r4 __unused if r5 is used
		a.delete_if { |arg| arg.has_attribute_var('register') and arg.has_attribute('unused') }
	end
end
end
