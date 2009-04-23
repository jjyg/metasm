require 'metasm/decode'
require 'metasm/parse_c'

module Metasm
class Decompiler
	# TODO add methods to C::CExpr
	AssignOp = [:'=', :'+=', :'-=', :'*=', :'/=', :'%=', :'^=', :'&=', :'|=', :'>>=', :'<<=']

	attr_accessor :dasm, :c_parser

	def initialize(dasm, cp = dasm.c_parser)
		@dasm = dasm
		@c_parser = cp || @dasm.cpu.new_cparser
	end

	# decompile a function, decompiling subfunctions as needed
	def decompile_func(entry)
		entry = @dasm.normalize entry
		return if not @dasm.decoded[entry]

		# create a new toplevel function to hold our code
		func = C::Variable.new
		func.name = @dasm.auto_label_at(entry, 'func')
		func.type = C::Function.new C::BaseType.new(:int)
		if @c_parser.toplevel.symbol[func.name]
			if not @c_parser.toplevel.statements.grep(C::Declaration).find { |decl| decl.var.name == func.name }
				# recursive dependency: declare prototype
				@c_parser.toplevel.statements << C::Declaration.new(func)
			end
			return
		end
		@c_parser.toplevel.symbol[func.name] = func
		puts "decompiling #{Expression[entry]}" if $VERBOSE

		# find decodedinstruction blocks constituing the function
		# TODO merge sequencial blocks with useless jmp (poeut) to improve dependency graph later
		myblocks = decompile_func_listblocks(entry)

		# [esp+8] => [:frameptr+8]
		decompile_makestackvars entry, myblocks.map { |b, to| @dasm.decoded[b].block }

		# find registry dependencies between blocks
		deps = decompile_func_finddeps(myblocks)

		scope = func.initializer = C::Block.new(@c_parser.toplevel)
		# di blocks => raw c statements, declare variables
		stmts = decompile_blocks(myblocks, deps, scope)
		# populate statements
		scope.statements.concat stmts
		# TODO check ABI conformance between func start&end (saved regs, stack offset...)

		# infer variable types
		decompile_c_types(scope)

		# goto bla ; bla: goto blo => goto blo ;; goto bla ; bla: return => return
		decompile_simplify_goto(scope)

		# cleanup C
		optimize(scope)

		# change if() goto to if, if/else, while
		decompile_match_controlseq(scope)

		# remove unreferenced labels
		decompile_remove_labels(scope)

		case ret = scope.statements.last
		when C::CExpression; puts "no return at end of func" if $VERBOSE
		when C::Return
			if not ret.value
				scope.statements.pop
			else
				func.type.type = C::BaseType.new(:int)
			end
		end

		# make function prototype with local arg_XX
		args = []
		decl = []
		scope.statements.delete_if { |sm|
			next if not sm.kind_of? C::Declaration
			case sm.var.name
			when /^arg_(.*)/
				args << sm.var
			else
				decl << sm
			end
			true
		}
		# reorder declarations
		scope.statements[0, 0] = decl.sort_by { |sm| sm.var.name =~ /^var_(.*)/ ? $1.to_i(16) : -1 }

		# ensure arglist has no hole (add unused arg to arglist)
		func.type.args = []
		argoff = varname_to_stackoff('arg_0')
		args.sort_by { |sm| sm.name[/arg_([0-9a-f]+)/i, 1].to_i(16) }.each { |a|
			# XXX misalignment ?
			curoff = varname_to_stackoff(a.name)
			while curoff > argoff
				wantarg = C::Variable.new
				wantarg.name = stackoff_to_varname(argoff).to_s
				wantarg.type = C::BaseType.new(:int)
				func.type.args << wantarg
				scope.symbol[wantarg.name] = wantarg
				argoff += @dasm.cpu.size/8
			end
			func.type.args << a
			argoff += @dasm.cpu.size/8
		}

		decompile_optimize_ctrl(scope)

		@c_parser.toplevel.statements << C::Declaration.new(func)
	end

	# return an array of [address of block start, list of block to]]
	# decompile subfunctions
	def decompile_func_listblocks(entry)
		@autofuncs ||= []
		blocks = []
		entry = dasm.normalize entry
		todo = [entry]
		while a = todo.pop
			next if blocks.find { |aa, at| aa == a }
			next if not di = @dasm.decoded[a]
			next if not di.kind_of? DecodedInstruction
			blocks << [a, []]
			di.block.each_to { |ta, type|
				next if type == :indirect
				ta = dasm.normalize ta
				if type != :subfuncret and not @dasm.function[ta] and
						(not @dasm.function[entry] or @autofuncs.include? entry) and
						di.block.list.last.opcode.props[:saveip]
					# noreturn function?
					@autofuncs << ta
					@dasm.function[ta] = DecodedFunction.new
					puts "autofunc #{Expression[ta]}" if $VERBOSE
				end
				
				if @dasm.function[ta] and type != :subfuncret	# and di.block.to_subfuncret # XXX __attribute__((noreturn)) ?
					f = dasm.auto_label_at(ta, 'func')
					ta = dasm.normalize($1) if f =~ /^thunk_(.*)/
					decompile_func(ta) if ta != entry
				else
					@dasm.auto_label_at(ta, 'label') if blocks.find { |aa, at| aa == ta }
					blocks.last[1] |= [ta]
					todo << ta
				end
			}
		end
		blocks
	end

	# patches instruction's backtrace_binding to replace things referring to a static stack offset from func start by :frameptr+off
	def decompile_makestackvars(funcstart, blocks)
		blockstart = nil
		tovar = lambda { |di, e, i_s|
			# need to backtrace every single reg ? must limit backtrace (maxdepth/complexity)
			# create an addr_binding[allregs] at each block start ? ondemand ?
			# we backtrace only to check for :esp, we could forward trace it instead once and for all ?
			case e
			when Expression; Expression[tovar[di, e.lexpr, i_s], e.op, tovar[di, e.rexpr, i_s]].reduce
			when Indirection; Indirection[tovar[di, e.target, i_s], e.len]
			when :frameptr; e
			when ::Symbol
				vals = @dasm.backtrace(e, di.address, :snapshot_addr => blockstart, :include_start => i_s)
				# backtrace only to blockstart first
				if vals.length == 1 and ee = vals.first and ee.kind_of? Expression and ee.externals == [:frameptr]
					ee
				else
				# fallback on full run (could restart from blockstart with ee, but may reevaluate addr_binding..
				vals = @dasm.backtrace(e, di.address, :snapshot_addr => funcstart, :include_start => i_s)
				if vals.length == 1 and ee = vals.first and ee.kind_of? Expression and (ee == Expression[:frameptr] or
						(ee.lexpr == :frameptr and ee.op == :+ and ee.rexpr.kind_of? ::Integer))
 					ee
				else e
				end
				end
			else e
			end
		}

		oldfuncbd = @dasm.address_binding[funcstart]
		@dasm.address_binding[funcstart] = { :esp => :frameptr }
		patched_binding = [funcstart]
		ebp_frame = true

		# must not change bt_bindings until everything is backtracked
		# TODO update function binding (lazy bt_binding)
		# TODO do not touch di.bt_bind, create something alongside / run this directly in decomp_cexpr (or just clear everything when done)
		repl_bind = {}	# di => bt_bd
		blocks.each { |block|
			blockstart = block.address
			if not @dasm.address_binding[blockstart]
				# calc binding of esp/ebp at begin of each block (kind of forward trace)
				patched_binding << blockstart
				@dasm.address_binding[blockstart] = {}
				foo = @dasm.backtrace(:esp, blockstart, :snapshot_addr => funcstart)
				if foo.length == 1 and ee = foo.first and ee.kind_of? Expression and (ee == Expression[:frameptr] or
						(ee.lexpr == :frameptr and ee.op == :+ and ee.rexpr.kind_of? ::Integer))
					@dasm.address_binding[blockstart][:esp] = ee
				end
				if ebp_frame == true
				foo = @dasm.backtrace(:ebp, blockstart, :snapshot_addr => funcstart)
				if foo.length == 1 and ee = foo.first and ee.kind_of? Expression and (ee == Expression[:frameptr] or
						(ee.lexpr == :frameptr and ee.op == :+ and ee.rexpr.kind_of? ::Integer))
					@dasm.address_binding[blockstart][:ebp] = ee
				else
					ebp_frame = false
				end
				end
			end

			block.list.each { |di|
				bd = di.backtrace_binding ||= @dasm.cpu.get_backtrace_binding(di)
				newbd = repl_bind[di] = {}
				bd.each { |k, v|
					# think about push/pop: keys need to include_start, value don't # TODO think again
					k = tovar[di, k, true] if k.kind_of? Indirection
					next if k == Expression[:frameptr] or (k.kind_of? Expression and k.lexpr == :frameptr and k.op == :+ and k.rexpr.kind_of? ::Integer)
					newbd[k] = tovar[di, v, false]
				}
			}
		}

		repl_bind.each { |di, bd| di.backtrace_binding = bd }

		patched_binding.each { |a| @dasm.address_binding.delete a }
		@dasm.address_binding[funcstart] = oldfuncbd if oldfuncbd
	end

	# give a name to a stackoffset (relative to start of func)
	# 4 => :arg_0, -8 => :var_4 etc
	def stackoff_to_varname(off)
		if off > @dasm.cpu.size/8
			'arg_%X' % ( off-@dasm.cpu.size/8)	#  4 => arg_0,  8 => arg_4..
		elsif off > 0
			'arg_0%X' % off
		elsif off == 0
			'retaddr'
		elsif off < -@dasm.cpu.size/8
			'var_%X' % (-off-@dasm.cpu.size/8)	# -4 => var_0, -8 => var_4..
		else
			'var_0%X' % -off
		end.to_sym
	end

	def varname_to_stackoff(var)
		case var.to_s
		when /^arg_0(.*)/;  $1.to_i(16)
		when /^var_0(.*)/; -$1.to_i(16)
		when /^arg_(.*)/;  $1.to_i(16) + @dasm.cpu.size/8
		when /^var_(.*)/; -$1.to_i(16) - @dasm.cpu.size/8
		when 'retaddr'; 0
		end
	end

	# list variable dependency for each block, remove useless writes
	# returns { blockaddr => [list of vars that are needed by a following block] }
	def decompile_func_finddeps(blocks)
		deps_r = {} ; deps_w = {} ; deps_to = {}
		deps_subfunc = {} ; deps_subfuncw = {}	# things read/written by subfuncs

		# find read/writes by each block
		blocks.each { |b, to|
			deps_r[b] = [] ; deps_w[b] = [] ; deps_to[b] = to
			deps_subfunc[b] = [] ; deps_subfuncw[b] = []

			blk = @dasm.decoded[b].block
			blk.list.each { |di|
				a = di.backtrace_binding.values
				w = []
				di.backtrace_binding.keys.each { |k|
					case k
					when ::Symbol; w |= [k]
					else a |= Expression[k].externals	# if dword [eax] <- 42, eax is read
					end
				}
				
				deps_r[b] |= a.map { |ee| Expression[ee].externals.grep(::Symbol) }.flatten - [:unknown] - deps_w[b]
				deps_w[b] |= w.map { |ee| Expression[ee].externals.grep(::Symbol) }.flatten - [:unknown]
			}
			stackoff = nil
			blk.each_to_normal { |t|
				t = backtrace_target(t, blk.list.last.address)
				next if not t = @c_parser.toplevel.symbol[t]
				stackoff ||= Expression[@dasm.backtrace(:esp, blk.list.last.address, :snapshot_addr => blocks.first[0]).first, :-, :esp].reduce

				# things that are needed by the subfunction
				args = t.type.args.map { |a| a.type }
				if t.attributes.to_a.include? 'fastcall'
					deps_subfunc[b] |= [:ecx, :edx][0, args.length]
					# XXX the two first args with size <= int are not necessarily nr 0 and nr 1..
					args.shift ; args.shift
				end
			}
			if stackoff
				deps_r[b] |= deps_subfunc[b] - deps_w[b]
				deps_w[b] |= deps_subfuncw[b] = [:eax, :ecx, :edx]
			end
			if to.empty?
				# XXX returned value
				deps_subfunc[b] |= [:eax]
			end
		}

		# remove writes from a block if no following block read the value
		deps_w.each { |b, deps|
			deps.delete_if { |dep|
				next if deps_subfunc[b].include? dep	# arg to a function called by the block
				next true if deps_subfuncw[b].include? dep	# thing written by the function
				ret = true
				done = []
				todo = deps_to[b].dup
				while a = todo.pop
					next if done.include? a
					done << a
					if not deps_r[a] or deps_r[a].include? dep
						ret = false
						break
					elsif not deps_w[a].include? dep
						todo.concat deps_to[a]
					end
				end
				ret
			}
		}

		deps_w
	end

	def decompile_blocks(myblocks, deps, scope, nextaddr = nil)
		stmts = []
		func_entry = myblocks.first[0]
		until myblocks.empty?
			b, to = myblocks.shift
			if l = @dasm.prog_binding.index(b)
				stmts << C::Label.new(l)
			end

			# list of assignments [[dest reg, expr assigned]]
			ops = []
			# reg binding (reg => value, values.externals = regs at block start)
			binding = {}
			# Expr => CExpr
			ce  = lambda { |*e|
				e = Expression[Expression[*e].reduce]
				decompile_cexpr(e, scope)
			}
			# Expr => Expr.bind(binding) => CExpr
			ceb = lambda { |*e| ce[Expression[*e].bind(binding)] }
			# shortcut to global funcname => Var (ext functions, e.g. malloc)
			ts = @c_parser.toplevel.symbol

			# dumps a CExprs that implements an assignment to a reg (uses ops[], patches op => [reg, nil])
			commit = lambda {
				#ops.each { |r, v| stmts << ce[r, :'=', v] }	# doesn't work, ops may have internal/circular deps
				#binding = {}
				deps[b].map { |k|
					[k, ops.rindex(ops.reverse.find { |r, v| r == k })]
				}.sort_by { |k, i| i.to_i }.each { |k, i|
					next if not i or not binding[k]
					e = k
					final = []
					ops[0..i].reverse_each { |r, v|
						final << r if not v
						e = Expression[e].bind(r => v).reduce if not final.include? r
					}
					ops[i][1] = nil
					binding.delete k
					stmts << ce[k, :'=', e]
				}
			}

			# go !
			# TODO not Ia32 specific
			@dasm.decoded[b].block.list.each { |di|
				a = di.instruction.args
				if di.opcode.props[:setip] and not di.opcode.props[:stopexec]
					# conditional jump
					# XXX switch/indirect/multiple jmp
					# TODO handle loop/jecxz
					commit[]
					n = backtrace_target(@dasm.cpu.get_xrefs_x(@dasm, di).first, di.address)
					stmts << C::If.new(ceb[@dasm.cpu.decode_cc_to_expr(di.opcode.name[1..-1])], C::Goto.new(n))
					to.delete @dasm.normalize(n)
					next
				end

				if di.opcode.name == 'mov'
					a1, a2 = di.instruction.args
					case a1
					when Ia32::CtrlReg, Ia32::DbgReg, Ia32::SegReg
						sz = a1.kind_of?(Ia32::SegReg) ? 16 : 32
						if not @c_parser.toplevel.symbol["intrinsic_set_#{a1}"]
							@c_parser.parse("void intrinsic_set_#{a1}(__int#{sz});")
						end
						f = @c_parser.toplevel.symbol["intrinsic_set_#{a1}"]
						a2 = a2.symbolic
						a2 = [a2, :&, 0xffff] if sz == 16
						stmts << C::CExpression.new(f, :funcall, [ceb[a2]], f.type.type)
						next
					end
					case a2
					when Ia32::CtrlReg, Ia32::DbgReg, Ia32::SegReg
						if not @c_parser.toplevel.symbol["intrinsic_get_#{a2}"]
							sz = a2.kind_of?(Ia32::SegReg) ? 16 : 32
							@c_parser.parse("__int#{sz} intrinsic_get_#{a2}(void);")
						end
						f = @c_parser.toplevel.symbol["intrinsic_get_#{a2}"]
						t = f.type.type
						stmts << C::CExpression.new(ceb[a1.symbolic], :'=', C::CExpression.new(f, :funcall, [], t), t)
						next
					end
				end

				case di.opcode.name
				when 'ret'
					commit[]
					stmts << C::Return.new(scope.symbol['eax'])
				when 'call'	# :saveip
					n = backtrace_target(@dasm.cpu.get_xrefs_x(@dasm, di).first, di.address)
					args = []
					if t = @c_parser.toplevel.symbol[n] and t.type.args
						# XXX see remarks in #finddeps
						stackoff = Expression[@dasm.backtrace(:esp, di.address, :snapshot_addr => func_entry), :-, :esp].bind(:esp => :frameptr).reduce rescue nil
						args_todo = t.type.args.dup
						args = []
						if t.attributes.to_a.include? 'fastcall'	# XXX DRY
							if a = args_todo.shift
								mask = (1 << (8*@c_parser.sizeof(a))) - 1
								args << ceb[:ecx, :&, mask]
								binding.delete :ecx
							end

							if a = args_todo.shift
								mask = (1 << (8*@c_parser.sizeof(a))) - 1	# char => dl
								args << ceb[:edx, :&, mask]
								binding.delete :edx
							end
						end
						args_todo.each {
							if stackoff.kind_of? Integer
								var = Indirection[[:frameptr, :+, stackoff], @dasm.cpu.size/8]
								stackoff += @dasm.cpu.size/8
							else
								var = 0
							end
							args << ceb[var]
							binding.delete var
						}
					end
					commit[]
					#next if not di.block.to_subfuncret

					if n.kind_of? ::String
						if not ts[n]
							# internal functions are predeclared, so this one is extern
							ts[n] = C::Variable.new
							ts[n].name = n
							ts[n].type = C::Function.new C::BaseType.new(:int)
							@c_parser.toplevel.statements << C::Declaration.new(ts[n])
						end
						commit[]
						fc = C::CExpression.new(ts[n], :funcall, args, ts[n].type.type)
					else
						# indirect funcall
						fptr = ceb[n]
						binding.delete n
						proto = C::Function.new(C::BaseType.new(:int))
						fptr = C::CExpression.new(nil, nil, fptr, C::Pointer.new(proto)) if not fptr.kind_of? C::CExpression	# cast
						fptr = C::CExpression.new(nil, nil, fptr, C::Pointer.new(proto))
						commit[]
						fc = C::CExpression.new(fptr, :funcall, args, proto.type)
					end
					stmts << C::CExpression.new(ce[:eax], :'=', fc, fc.type)
				when 'jmp'
					if di.block.to_normal.to_a.length > 1
						n = backtrace_target(@dasm.cpu.get_xrefs_x(@dasm, di).first, di.address)
						fptr = ceb[n]
						binding.delete n
						proto = C::Function.new(C::BaseType.new(:void))
						fptr = C::CExpression.new(nil, nil, fptr, C::Pointer.new(proto)) if not fptr.kind_of? C::CExpression	# cast
						fptr = C::CExpression.new(nil, nil, fptr, C::Pointer.new(proto))
						commit[]
						stmts << C::CExpression.new(fptr, :funcall, [], proto.type)
					end
					# XXX bouh
					# TODO mark instructions for which bt_binding is accurate
				when 'push', 'pop', 'mov', 'add', 'sub', 'or', 'xor', 'and', 'not', 'mul', 'div', 'idiv', 'imul', 'shr', 'shl', 'sar', 'test', 'cmp', 'inc', 'dec', 'lea', 'movzx', 'movsx', 'neg', 'cdq', 'leave', 'nop'
					di.backtrace_binding.each { |k, v|
						if k.kind_of? ::Symbol or (k.kind_of? Indirection and Expression[k.target, :-, :esp].reduce.kind_of? ::Integer)
							ops << [k, v]
						else
							stmts << ceb[k, :'=', v]
						end
					}
					update = {}
					di.backtrace_binding.each { |k, v|
						next if not k.kind_of? ::Symbol
						update[k] = Expression[Expression[v].bind(binding).reduce]
					}
					binding.update update
				when 'lgdt'
					if not @c_parser.toplevel.struct['segment_descriptor']
						@c_parser.parse('struct segment_descriptor { __int16 limit; __int16 base0_16; __int8 base16_24; __int8 flags1; __int8 flags2_limit_16_20; __int8 base24_32; };')
						@c_parser.parse('struct segment_table { __int16 size; struct segment_descriptor *table; } __attribute__((pack(2)));')
					end
					if not @c_parser.toplevel.symbol['intrinsic_lgdt']
						@c_parser.parse('void intrinsic_lgdt(struct segment_table *);')
					end
					# need a way to transform arg => :frameptr+12
					arg = di.backtrace_binding.keys.grep(Indirection).first.pointer
					stmts << C::CExpression.new(@c_parser.toplevel.symbol['intrinsic_lgdt'], :funcall, [ceb[arg]], C::BaseType.new(:void))
				when 'lidt'
					if not @c_parser.toplevel.struct['interrupt_descriptor']
						@c_parser.parse('struct interrupt_descriptor { __int16 offset0_16; __int16 segment; __int16 flags; __int16 offset16_32; };')
						@c_parser.parse('struct interrupt_table { __int16 size; struct interrupt_descriptor *table; } __attribute__((pack(2)));')
					end
					if not @c_parser.toplevel.symbol['intrinsic_lidt']
						@c_parser.parse('void intrinsic_lidt(struct interrupt_table *);')
					end
					arg = di.backtrace_binding.keys.grep(Indirection).first.pointer
					stmts << C::CExpression.new(@c_parser.toplevel.symbol['intrinsic_lidt'], :funcall, [ceb[arg]], C::BaseType.new(:void))
				when 'ltr', 'lldt'
					if not @c_parser.toplevel.symbol["intrinsic_#{di.opcode.name}"]
						@c_parser.parse("void intrinsic_#{di.opcode.name}(int);")
					end
					arg = di.backtrace_binding.keys.first
					stmts << C::CExpression.new(@c_parser.toplevel.symbol["intrinsic_#{di.opcode.name}"], :funcall, [ceb[arg]], C::BaseType.new(:void))
				when 'out'
					sz = di.instruction.args.find { |a_| a_.kind_of? Ia32::Reg and a_.val == 0 }.sz
					if not @c_parser.toplevel.symbol["intrinsic_out#{sz}"]
						@c_parser.parse("void intrinsic_out#{sz}(unsigned short port, __int#{sz} value);")
					end
					port = di.instruction.args.grep(Expression).first || :edx
					stmts << C::CExpression.new(@c_parser.toplevel.symbol["intrinsic_out#{sz}"], :funcall, [ceb[port], ceb[:eax]], C::BaseType.new(:void))
				when 'in'
					sz = di.instruction.args.find { |a_| a_.kind_of? Ia32::Reg and a_.val == 0 }.sz
					if not @c_parser.toplevel.symbol["intrinsic_in#{sz}"]
						@c_parser.parse("__int#{sz} intrinsic_in#{sz}(unsigned short port);")
					end
					port = di.instruction.args.grep(Expression).first || :edx
					f = @c_parser.toplevel.symbol["intrinsic_in#{sz}"]
					stmts << C::CExpression.new(ceb[:eax], :'=', C::CExpression.new(f, :funcall, [ceb[port]], f.type.type), f.type.type)
				when 'sti', 'cli'
					if not @c_parser.toplevel.symbol["intrinsic_#{di.opcode.name}"]
						@c_parser.parse("void intrinsic_#{di.opcode.name}(void);")
					end
					stmts << C::CExpression.new(@c_parser.toplevel.symbol["intrinsic_#{di.opcode.name}"], :funcall, [], C::BaseType.new(:void))
				else
					commit[]
					stmts << C::Asm.new(di.instruction.to_s, nil, nil, nil, nil, nil)
				end
			}
			commit[]

			case to.length
			when 0
				if not myblocks.empty? and @dasm.decoded[b].block.list.last.instruction.opname != 'ret'
					puts "  block #{Expression[b]} has no to and don't end in ret"
				end
			when 1
				if (myblocks.empty? ? nextaddr != to[0] : myblocks.first.first != to[0])
					stmts << C::Goto.new(@dasm.auto_label_at(to[0], 'unknown_goto'))
				end
			else
				puts "  block #{Expression[b]} with multiple to"
			end
		end
		stmts
	end

	# backtraces an expression from addr
	# returns an integer, a label name, or an Expression
	def backtrace_target(expr, addr)
		if n = @dasm.backtrace(expr, addr).first
			n = Expression[n].reduce_rec
			n = @dasm.prog_binding.index(n) || n
			n = $1 if n.kind_of? ::String and n =~ /^thunk_(.*)/
			n
		end
	end

	# turns an Expression to a CExpression, create+declares needed variables in scope
	def decompile_cexpr(e, scope)
		case e
		when Expression
			if e.op == :'=' and e.lexpr.kind_of? ::String and e.lexpr =~ /^dummy_metasm_/
				decompile_cexpr(e.rexpr, scope)
			elsif e.op == :+ and e.rexpr.kind_of? ::Integer and e.rexpr < 0
				decompile_cexpr(Expression[e.lexpr, :-, -e.rexpr], scope)
			elsif e.lexpr
				a = decompile_cexpr(e.lexpr, scope)
				C::CExpression.new(a, e.op, decompile_cexpr(e.rexpr, scope), a.type)
			elsif e.op == :+
				decompile_cexpr(e.rexpr, scope)
			else
				a = decompile_cexpr(e.rexpr, scope)
				C::CExpression.new(nil, e.op, a, a.type)
			end
		when Indirection
			p = decompile_cexpr(e.target, scope)
			p = C::CExpression.new(nil, nil, p, C::Pointer.new(C::BaseType.new("__int#{e.len*8}".to_sym)))
			p = C::CExpression.new(nil, nil, p, p.type) if not p.rexpr.kind_of? C::CExpression
			C::CExpression.new(nil, :*, p, p.type.type)
		when ::Integer
			C::CExpression.new(nil, nil, e, C::BaseType.new(:int))
		when C::CExpression
			e
		else
			# XXX where does ::String come from ?
			name = e.to_s
			if not s = scope.symbol_ancestors[name]
				s = C::Variable.new
				s.type = C::BaseType.new(:__int32)
				if e.kind_of? ::String
					# XXX may be string constant (as in printf("foo"))
					s.storage = :static
				elsif o = varname_to_stackoff(name)
					case o % 4	# keep var aligned
					when 1, 3; s.type = C::BaseType.new(:__int8)
					when 2; s.type = C::BaseType.new(:__int16)
					end
				else
					s.storage = :register
				end
				if not e.kind_of? ::Symbol and not e.kind_of? ::String
					puts "decompile_cexpr unhandled #{e.inspect}, using #{e.to_s.inspect}" if $VERBOSE
					s.type.qualifier = [:volatile]
				end
				s.name = name
				scope.symbol[s.name] = s
				scope.statements << C::Declaration.new(s)
			end
			s
		end
	end

	# simplify goto -> goto
	# iterative process, to not infinite loop on b:goto a; a:goto b;
	# TODO multipass ? (goto a -> goto b -> goto c -> goto d)
	# remove last return if not useful
	def decompile_simplify_goto(scope)
		cntr = -1

		simpler_goto = lambda { |g|
			case ret = g
			when C::Goto
				# return a new goto
				decompile_walk(scope) { |s|
					if s.kind_of? C::Block and l = s.statements.grep(C::Label).find { |l_| l_.name == g.target }
						case nt = s.statements[s.statements.index(l)..-1].find { |ss| not ss.kind_of? C::Label }
						when C::Goto; ret = nt
						end
					end
				}
			when C::Return
				# XXX if () { return } else { return }
				lr = scope.statements.last
				if g != lr and lr.kind_of? C::Return and g.value == lr.value
					if not scope.statements[-2].kind_of? C::Label
						scope.statements.insert(-2, C::Label.new("ret_#{cntr += 1}", nil))
					end
					ret = C::Goto.new(scope.statements[-2].name)
				end
			end
			ret
		}

		decompile_walk(scope) { |s|
			case s
			when C::Block
				s.statements.each_with_index { |ss, i|
					s.statements[i] = simpler_goto[ss]
				}
			when C::If
				s.bthen = simpler_goto[s.bthen]
			end
		}
	end

	# changes ifgoto, goto to while/ifelse..
	def decompile_match_controlseq(scope)
		scope.statements = decompile_cseq_if(scope.statements, scope)
		decompile_cseq_while(scope.statements, scope)
	end

	# optimize if() { a; } to if() a;
	def decompile_optimize_ctrl(scope)
		# while (1) { a; if(b) { c; return; }; d; }  =>  while (1) { a; if (b) break; d; } c;
		while st = scope.statements.last and st.kind_of? C::While and st.test.kind_of? C::CExpression and
				not st.test.op and st.test.rexpr == 1 and st.body.kind_of? C::Block
			break if not i = st.body.statements.find { |ist|
				ist.kind_of? C::If and not ist.belse and ist.bthen.kind_of? C::Block and ist.bthen.statements.last.kind_of? C::Return
			}
			scope.statements.concat i.bthen.statements
			i.bthen = C::Break.new
		end
		decompile_walk(scope) { |ce|
			case ce
			when C::If
				if ce.bthen.kind_of? C::Block
 					case ce.bthen.statements.length
					when 1
						decompile_walk(ce.bthen.statements) { |sst| sst.outer = ce.bthen.outer if sst.kind_of? C::Block and sst.outer == ce.bthen }
						ce.bthen = ce.bthen.statements.first
					when 0
 						if not ce.belse and i = ce.bthen.outer.statements.index(ce)
							ce.body.outer.statements[i] = ce.test	# TODO remove sideeffectless parts
						end
					end
				end
				if ce.belse.kind_of? C::Block and ce.belse.statements.length == 1
					decompile_walk(ce.belse.statements) { |sst| sst.outer = ce.belse.outer if sst.kind_of? C::Block and sst.outer == ce.belse }
					ce.belse = ce.belse.statements.first
				end
			when C::While, C::DoWhile
				if ce.body.kind_of? C::Block
				       case ce.body.statements.length
				       when 1
					       decompile_walk(ce.body.statements) { |sst| sst.outer = ce.body.outer if sst.kind_of? C::Block and sst.outer == ce.body }
					       ce.body = ce.body.statements.first
				       when 0
					       if ce.kind_of? C::DoWhile and i = ce.body.outer.statements.index(ce)
						      ce = ce.body.outer.statements[i] = C::While.new(ce.test, ce.body)
					       end
					       ce.body = nil
				       end
				end
			end
		}
		decompile_remove_labels(scope)
	end

	# ifgoto => ifthen
	# ary is an array of statements where we try to find if () {} [else {}]
	# recurses to then/else content
	def decompile_cseq_if(ary, scope)
		# the array of decompiled statements to use as replacement
		ret = []
		# list of labels appearing in ary
		inner_labels = ary.grep(C::Label).map { |l| l.name }
		while s = ary.shift
			while s.kind_of? C::If and s.bthen.kind_of? C::Goto and not s.belse and ary.first.kind_of? C::If and ary.first.bthen.kind_of? C::Goto and
					not ary.first.belse and s.bthen.target == ary.first.bthen.target
				# if (a) goto x; if (b) goto x; => if (a || b) goto x;
				s.test = C::CExpression.new(s.test, :'||', ary.shift.test, s.test.type)
			end

			# "forward" ifs only
			if s.kind_of? C::If and s.bthen.kind_of? C::Goto and l = ary.grep(C::Label).find { |l_| l_.name == s.bthen.target }
				# if {goto l;} a; l: => if (!) {a;}
				s.test = C::CExpression.negate s.test
				s.bthen = C::Block.new(scope)
				s.bthen.statements = decompile_cseq_if(ary[0...ary.index(l)], s.bthen)
				bts = s.bthen.statements
				ary[0...ary.index(l)] = []

				# if { a; goto outer; } b; return; => if (!) { b; return; } a; goto outer;
				if bts.last.kind_of? C::Goto and not inner_labels.include? bts.last.target and g = ary.find { |ss| ss.kind_of? C::Goto or ss.kind_of? C::Return } and g.kind_of? C::Return
					s.test = C::CExpression.negate s.test
					ary[0..ary.index(g)], bts[0..-1] = bts, ary[0..ary.index(g)]
				end

				# if { a; goto l; } b; l: => if {a;} else {b;}
				if bts.last.kind_of? C::Goto and l = ary.grep(C::Label).find { |l_| l_.name == bts.last.target }
					s.belse = C::Block.new(scope)
					s.belse.statements = decompile_cseq_if(ary[0...ary.index(l)], s.belse)
					ary[0...ary.index(l)] = []
					bts.pop
				end

				# if { a; l: b; goto any;} c; goto l; => if { a; } else { c; } b; goto any;
				if not s.belse and (bts.last.kind_of? C::Goto or bts.last.kind_of? C::Return) and g = ary.grep(C::Goto).first and l = bts.grep(C::Label).find { |l_| l_.name == g.target }
					s.belse = C::Block.new(scope)
					s.belse.statements = decompile_cseq_if(ary[0...ary.index(g)], s.belse)
					ary[0..ary.index(g)], bts[bts.index(l)..-1] = bts[bts.index(l)..-1], []
				end

				# if { a; b; c; } else { d; b; c; } => if {a;} else {d;} b; c;
				if s.belse
					bes = s.belse.statements
					while not bts.empty?
						if bts.last.kind_of? C::Label; ary.unshift bts.pop
						elsif bes.last.kind_of? C::Label; ary.unshift bes.pop
						elsif bts.last.to_s == bes.last.to_s; ary.unshift bes.pop ; bts.pop
						else break
						end
					end

					# if () { a; } else { b; } => if () { a; } else b;
					# if () { a; } else {} => if () { a; }
					case bes.length
					when 0; s.belse = nil
					#when 1; s.belse = bes.first
					end
				end

				# if () {} else { a; } => if (!) { a; }
				# if () { a; } => if () a;
				case bts.length
				when 0; s.test, s.bthen, s.belse = C::CExpression.negate(s.test), s.belse, nil if s.belse
				#when 1; s.bthen = bts.first	# later (allows simpler handling in _while)
				end
			end
			ret << s
		end
		ret
	end

	def decompile_cseq_while(ary, scope)
		# find the next instruction that is not a label
		ni = lambda { |l| ary[ary.index(l)..-1].find { |s| not s.kind_of? C::Label } }

		# TODO XXX get rid of #index
		finished = false ; while not finished ; finished = true # 1.9 does not support 'retry'
		ary.each { |s|
			case s
			when C::Label
				if ss = ni[s] and ss.kind_of? C::If and not ss.belse and ss.bthen.kind_of? C::Block
					if ss.bthen.statements.last.kind_of? C::Goto and ss.bthen.statements.last.target == s.name
						ss.bthen.statements.pop
						if l = ary[ary.index(ss)+1] and l.kind_of? C::Label
							ss.bthen.statements.grep(C::If).each { |i|
								i.bthen = C::Break.new if i.bthen.kind_of? C::Goto and i.bthen.target == l.name
							}
						end
						ary[ary.index(ss)] = C::While.new(ss.test, ss.bthen)
					elsif ss.bthen.statements.last.kind_of? C::Return and g = ary[ary.index(s)+1..-1].reverse.find { |_s| _s.kind_of? C::Goto and _s.target == s.name }
						wb = C::Block.new(scope)
						wb.statements = decompile_cseq_while(ary[ary.index(ss)+1...ary.index(g)], wb)
						w = C::While.new(C::CExpression.negate(ss.test), wb)
						ary[ary.index(ss)..ary.index(g)] = [w, *ss.bthen.statements]
						finished = false ; break	#retry
					end
				end
				if g = ary[ary.index(s)..-1].reverse.find { |_s| _s.kind_of? C::Goto and _s.target == s.name }
					wb = C::Block.new(scope)
					wb.statements = decompile_cseq_while(ary[ary.index(s)...ary.index(g)], wb)
					w = C::While.new(C::CExpression.new(nil, nil, 1, C::BaseType.new(:int)), wb)
					ary[ary.index(s)..ary.index(g)] = [w]
					finished = false ; break	#retry
				end
				if g = ary[ary.index(s)..-1].reverse.find { |_s| _s.kind_of? C::If and not _s.belse and _s.bthen.kind_of? C::Goto and _s.bthen.target == s.name }
					wb = C::Block.new(scope)
					wb.statements = decompile_cseq_while(ary[ary.index(s)...ary.index(g)], wb)
					w = C::DoWhile.new(g.test, wb)
					ary[ary.index(s)..ary.index(g)] = [w]
					finished = false ; break	#retry
				end
			when C::If
				decompile_cseq_while(s.bthen.statements, s.bthen) if s.bthen.kind_of? C::Block
				decompile_cseq_while(s.belse.statements, s.belse) if s.belse.kind_of? C::Block
			when C::While, C::DoWhile
				decompile_cseq_while(s.body.statements, s.body) if s.body.kind_of? C::Block
			end
		}
		end

		# break/continue
		# XXX if (foo) while (bar) goto bla; bla:  should => break
		walk = lambda { |e, brk, cnt|
			case e
			when C::Block
				walk[e.statements, brk, cnt]
				e
			when ::Array
				e.each_with_index { |st, i|
					case st
					when C::While, C::DoWhile
						l1 = e[i+1].name if e[i+1].kind_of? C::Label
						l2 = e[i-1].name if e[i-1].kind_of? C::Label
						st.body = walk[st.body, l1, l2]
					else
						e[i] = walk[st, brk, cnt]
					end
				}
				e
			when C::If
				e.bthen = walk[e.bthen, brk, cnt] if e.bthen
				e.belse = walk[e.belse, brk, cnt] if e.bthen
				e
			when C::While, C::DoWhile
				e.body = walk[e.body, nil, nil]
				e
			when C::Goto
				if e.target == brk
					C::Break.new
				elsif e.target == cnt
					C::Continue.new
				else e
				end
			else e
			end
		}
		walk[ary, nil, nil]
	end

	def decompile_remove_labels(scope)
		decompile_walk(scope) { |s|
			next if not s.kind_of? C::Block
			s.statements.delete_if { |l|
				if l.kind_of? C::Label
					notfound = true
					decompile_walk(scope) { |ss| notfound = false if ss.kind_of? C::Goto and ss.target == l.name}
				end
				notfound
			}
		}
		decompile_walk(scope) { |s|
			next if not s.kind_of? C::While
			if s.body.kind_of? C::Block and s.body.statements.last.kind_of? C::Continue
				s.body.statements.pop
			end
		}
	end

	def decompile_c_types(scope)
		# TODO handle aliases (mem+regs) (reverse liveness?) XXX this would take place in make_stack_vars
		# XXX walk { walk {} } too much, optimize

		# types = { off => type of *(frameptr+off) }
		types = {}
		vartypes = {}

		# TODO make all this standalone, to call it whenever the user updates one type through UI

		# returns o if e is like 'frameptr+o'
		frameoff = lambda { |e|
			e = e.rexpr while e.kind_of? C::CExpression and not e.op
			next if not e.kind_of? C::CExpression or (e.op != :+ and e.op != :-)
			e.op == :- ? -e.rexpr.rexpr : e.rexpr.rexpr if e.lexpr.kind_of? C::Variable and e.lexpr.name == 'frameptr' and
					e.rexpr.kind_of? C::CExpression and not e.rexpr.op and e.rexpr.rexpr.kind_of? ::Integer
		}

		# returns o if e is like '*(frameptr+o)'
		framepoff = lambda { |e|
			e = e.rexpr while e.kind_of? C::CExpression and not e.op
			next if not e.kind_of? C::CExpression or e.op != :* or e.lexpr
			frameoff[e.rexpr]
		}
		scopevar = lambda { |e|
			e.name if e.kind_of? C::Variable and scope.symbol[e.name]
		}

		propagate_type = nil	# fwd declaration

		# check if a newly found type for o is better than current type
		# order: foo* > void* > foo
		# propagate_type if type is updated
		better_type = lambda { |t0, t1|
			t1 == C::BaseType.new(:void) or (t0.pointer? and t1.kind_of? C::BaseType) or t0.untypedef.kind_of? C::Union or
			(t0.kind_of? C::BaseType and t1.kind_of? C::BaseType and (@c_parser.typesize[t0.name] > @c_parser.typesize[t1.name] or (t0.name == t1.name and t0.qualifier))) or
			(t0.pointer? and t1.pointer? and better_type[t0.untypedef.type, t1.untypedef.type])
		}
		update_type = lambda { |o, t|
			if not o.kind_of? ::Integer
				if not t0 = vartypes[o] or better_type[t, t0]
					vartypes[o] = t
					next if t == t0
					propagate_type[o, t]
				end
			elsif not t0 = types[o] or better_type[t, t0]
				next if (t.integral? or t.pointer?) and o % @c_parser.sizeof(nil, t) != 0	# keep vars aligned
				types[o] = t
				next if t == t0
				propagate_type[o, t]
				t = t.untypedef
				if t.kind_of? C::Struct
					t.members.each { |m|
						mo = t.offsetof(@c_parser, m.name)
						next if mo == 0
						update_type[o+mo, m.type]
					}
				end
			end
		}

		# try to update the type of a stack offset from knowing the type of an expr (through dereferences etc)
		known_type = lambda { |e, t|
			loop do
				e = e.rexpr while e.kind_of? C::CExpression and not e.op
				if o = scopevar[e]
					update_type[o, t]
				elsif not e.kind_of? C::CExpression
					break
				elsif o = framepoff[e]
					update_type[o, t]
				elsif o = frameoff[e] and t.pointer?
					update_type[o, t.untypedef.type]
				elsif e.op == :* and not e.lexpr
					e = e.rexpr
					t = C::Pointer.new(t)
					next
				elsif e.op == :+ and e.lexpr and e.rexpr.kind_of? C::CExpression
					if not e.rexpr.op and e.rexpr.rexpr.kind_of? ::Integer
						# (int)*(x+2) === (int) *x
						e = e.lexpr
						next
					elsif t.pointer?
 						if e.lexpr.kind_of? C::Variable
							e = e.lexpr
							next
						elsif e.lexpr.kind_of? C::CExpression and [:*, :<<, :>>, :&].include? e.lexpr.op
							e.lexpr, e.rexpr = e.rexpr, e.lexpr
							e = e.lexpr
							next
						end
					end
				end
				break
			end
		}

		# we found a type for a stackoff, propagate it through affectations
		propagate_type = lambda { |off, type|
			decompile_walk(scope) { |ce_| decompile_walk_ce(ce_) { |ce|
				# char x; x & 255 => uchar x
				if ce.op == :'&' and ce.lexpr.type.integral? and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr == (1 << (8*@c_parser.sizeof(ce.lexpr))) - 1
					known_type[ce.lexpr, C::BaseType.new(ce.lexpr.type.name, :unsigned)]
				end

				next if ce.op != :'='

				# int **x; y = **x  =>  int y
				t = type
				l = ce.lexpr
				while l.kind_of? C::CExpression and l.op == :* and not l.lexpr
					if off == frameoff[l.rexpr] || scopevar[l.rexpr]
						known_type[ce.rexpr, t]
						break
					elsif t.pointer?
						l = l.rexpr
						t = t.untypedef.type
					else break
					end
				end

				# int **x; **x = y  =>  int y
				t = type
				r = ce.rexpr
				while r.kind_of? C::CExpression and r.op == :* and not r.lexpr
					if off == frameoff[r.rexpr] || scopevar[r.rexpr]
						known_type[ce.lexpr, t]
						break
					elsif t.pointer?
						r = r.rexpr
						t = t.untypedef.type
					else break
					end
				end
			} }
		}

		# XXX struct foo { int bla } x; y = x;  =>  y = int or foo ?

		# try to find appropriate type for stack offsets ; afterwards this will lead to stack variable creation
		decompile_walk(scope) { |ce_| decompile_walk_ce(ce_) { |ce|
			if ce.op == :'=' and ce.rexpr.kind_of? C::CExpression and ce.rexpr.op == nil and ce.rexpr.rexpr.kind_of? ::Integer and ce.rexpr.rexpr.abs < 0x10000 and (not ce.lexpr.kind_of? C::CExpression or ce.lexpr.op != :'*' or ce.lexpr.lexpr)
				# var = int
				known_type[ce.lexpr, ce.rexpr.type]
			elsif ce.op == :funcall and ce.lexpr.type.kind_of? C::Function
				# cast func args to arg prototypes
				ce.lexpr.type.args.to_a.zip(ce.rexpr).each { |proto, arg| known_type[arg, proto.type] }
			elsif ce.op == :* and not ce.lexpr
				known_type[ce.rexpr, C::Pointer.new(ce.type)]
			end
		} }

		# offsets have types now
		vartypes.each { |v, t|
			q = scope.symbol[v].type.qualifier
			scope.symbol[v].type = t
			t.qualifier = q if q
		}

		# remove qualifier from special variables forwarded to auto vars
		types.each { |o, t|
			next if not t.qualifier
			types[o] = t.dup
			types[o].qualifier = nil
		}

		# remove offsets to struct members
		# off => [structoff, membername, membertype]
		memb = {}
		types.dup.each { |o, t|
			t = t.untypedef
			if t.kind_of? C::Struct
				t.members.each { |tm|
					moff = t.offsetof(@c_parser, tm.name)
					next if moff == 0
					types.delete(o+moff)
					memb[o+moff] = [o, tm.name, tm.type]
				}
			end
		}

		# patch local variables into the CExprs, incl unknown offsets
		# off => Var
		vars = {}
		varat = lambda { |off|
			if not vars[off]
				if s = memb[off]
					v = C::CExpression.new(varat[s[0]], :'.', s[1], s[2])
				else
					v = C::Variable.new
					v.type = types[off] || C::BaseType.new(:int)
					v.name = stackoff_to_varname(off).to_s
					scope.statements << C::Declaration.new(v)
					scope.symbol[v.name] = v
				end
				vars[off] = v
			end
			vars[off]
		}

		maycast = lambda { |v, e|
			if @c_parser.sizeof(v) != @c_parser.sizeof(e)
				p = C::CExpression.new(nil, :&, v, C::Pointer.new(v.type))
				p = C::CExpression.new(nil, nil, p, C::Pointer.new(e.type))
				v = C::CExpression.new(nil, :*, p, e.type)
			end
			v
		}

		decompile_walk(scope) { |ce_| decompile_walk_ce(ce_) { |ce|
			o = nil
			if ce.op == :funcall
				ce.rexpr.map! { |re|
					if o = framepoff[re]; maycast[varat[o], re]
					elsif o = frameoff[re]; C::CExpression.new(nil, :&, varat[o], C::Pointer.new(varat[o].type))
					else re
					end
				}
			end
			ce.lexpr = maycast[varat[o], ce.lexpr] if o = framepoff[ce.lexpr]
			ce.rexpr = maycast[varat[o], ce.rexpr] if o = framepoff[ce.rexpr]
			ce.lexpr = C::CExpression.new(nil, :&, varat[o], C::Pointer.new(varat[o].type)) if o = frameoff[ce.lexpr]
			ce.rexpr = C::CExpression.new(nil, :&, varat[o], C::Pointer.new(varat[o].type)) if o = frameoff[ce.rexpr]
		} }

		# fix pointer arithmetic, use struct member access

		decompile_walk(scope) { |ce_| decompile_walk_ce(ce_, true) { |ce|
			next if not ce.kind_of? C::CExpression
			if ce.op == :* and not ce.lexpr and ce.rexpr.type.pointer? and ce.rexpr.type.untypedef.type.untypedef.kind_of? C::Struct
				s = ce.rexpr.type.untypedef.type.untypedef
				m = s.members.find { |m_| s.offsetof(@c_parser, m_.name) == 0 }
				if @c_parser.sizeof(m) != @c_parser.sizeof(ce)
					ce.rexpr = C::CExpression.new(nil, nil, ce.rexpr, C::Pointer.new(s))
					ce.rexpr = C::CExpression.new(nil, nil, ce.rexpr, C::Pointer.new(ce.type))
					next
				end
				# *structptr => structptr->member
				ce.lexpr = ce.rexpr
				ce.op = :'->'
				ce.rexpr = m.name
				ce.type = m.type
				next
			elsif ce.op == :'=' and ce.lexpr.type.untypedef.kind_of? C::Struct
				s = ce.lexpr.type.untypedef
				m = s.members.find { |m_| s.offsetof(@c_parser, m_.name) == 0 }
				ce.lexpr = C::CExpression.new(ce.lexpr, :'.', m.name, m.type)
				ce.type = m.type
				next
			end

			next if not ce.lexpr or not ce.lexpr.type.pointer?
			if ce.op == :+ and ce.lexpr.type.untypedef.type.untypedef.kind_of? C::Struct and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and
					ce.rexpr.rexpr.kind_of? ::Integer and s = ce.lexpr.type.untypedef.type.untypedef and
					o = ce.rexpr.rexpr and tabidx = o / @c_parser.sizeof(nil, s) and
					o -= tabidx * @c_parser.sizeof(nil, s) and m = s.members.find { |m_| s.offsetof(@c_parser, m_.name) == o }
				# structptr + 4 => &structptr->member
				if tabidx != 0
					tabidx = C::CExpression.new(nil, nil, tabidx, C::BaseType.new(:int))
					ce.rexpr = C::CExpression.new(ce.lexpr, :'[]', tabidx, ce.lexpr.type.untypedef.type)
					ce.rexpr = C::CExpression.new(ce.rexpr, :'.', m.name, m.type)
				else
					ce.rexpr = C::CExpression.new(ce.lexpr, :'->', m.name, m.type)
				end
				ce.lexpr, ce.op, ce.type = nil, :&, C::Pointer.new(m.type)
			elsif [:+, :-, :'+=', :'-='].include? ce.op and ce.rexpr.kind_of? C::CExpression and ((not ce.rexpr.op and i = ce.rexpr.rexpr) or
					(ce.rexpr.op == :* and i = ce.rexpr.lexpr and ((i.kind_of? C::CExpression and not i.op and i = i.rexpr) or true))) and
					i.kind_of? ::Integer and psz = @c_parser.sizeof(nil, ce.lexpr.type.untypedef.type) and i % psz == 0
				# ptr += 4 => ptr += 1
				if not ce.rexpr.op
					ce.rexpr.rexpr /= psz
				else
					ce.rexpr.lexpr.rexpr /= psz
					if ce.rexpr.lexpr.rexpr == 1
						ce.rexpr = ce.rexpr.rexpr
					end
				end
				ce.type = ce.lexpr.type

			elsif (ce.op == :+ or ce.op == :-) and @c_parser.sizeof(nil, ce.lexpr.type.untypedef.type) != 1
				# ptr+x => (ptrtype*)(((__int8*)ptr)+x)
				# XXX create struct ?
				ce.rexpr = C::CExpression.new(nil, nil, ce.rexpr, C::BaseType.new(:int)) if not ce.rexpr.type.integral?
				if @c_parser.sizeof(nil, ce.lexpr.type.untypedef.type) != 1
					ptype = ce.lexpr.type
					ce.lexpr = C::CExpression.new(nil, nil, ce.lexpr, ce.lexpr.type) if not ce.lexpr.kind_of? C::CExpression
					ce.lexpr = C::CExpression.new(nil, nil, ce.lexpr, C::Pointer.new(C::BaseType.new(:__int8)))
					ce.lexpr, ce.op, ce.rexpr, ce.type = nil, nil, C::CExpression.new(ce.lexpr, ce.op, ce.rexpr, ce.lexpr.type), ptype
				end
			end
		} }
	end

	# replace all occurence of var var by expr exp in stmt (no handling of if body/while/for etc)
	def replace_var(stmt, var, newexp, skip_assign=true)
		case stmt
		when C::Return
			if stmt.value.kind_of? C::Variable and stmt.value.name == var.name
				stmt.value = newexp
			elsif stmt.value.kind_of? C::CExpression
				stmt = stmt.value
			end
		when C::If
			if stmt.test.kind_of? C::Variable and stmt.test.name == var.name
				stmt.test = newexp
			elsif stmt.test.kind_of? C::CExpression
				stmt = stmt.test
			end
		end

		if stmt.kind_of? C::CExpression
			walk = lambda { |exp|
				next if not exp.kind_of? C::CExpression
				if exp.lexpr.kind_of? C::Variable and exp.lexpr.name == var.name
					exp.lexpr = newexp if not skip_assign or exp.op != :'='
				else walk[exp.lexpr]
				end
				case exp.op
				when :funcall
					exp.rexpr.each_with_index { |a, i|
						if a.kind_of? C::Variable and a.name == var.name
							exp.rexpr[i] = newexp
						else walk[a]
						end
					}
				else
					if exp.rexpr.kind_of? C::Variable and exp.rexpr.name == var.name
						exp.rexpr = newexp
					else walk[exp.rexpr]
					end
				end
			}
			walk[stmt]
		end
	end

	# to be run with scope = function body with only CExpr/Decl/Label/Goto/IfGoto/Return, with correct variables types
	# will transform += 1 to ++, inline them to prev/next statement ('x++; if (x)..' => 'if (++x)..')
 	# remove useless variables ('int i;', i never used or 'i = 1; j = i;', i never read after => 'j = 1;')
	# remove useless casts ('(int)i' with 'int i;' => 'i')
	# also removes 'enter' traduction ('var_0 = ebp;' => '')
	def optimize(scope)
		# TODO if all occurences of __int32 x are x&255, change type to __int8
		optimize_overlap(scope)
		optimize_code(scope)
		optimize_vars(scope)
		optimize_vars(scope)	# 1st run may transform i = i+1 into i++ which second run may coalesce into if(i)
	end

	# handling of var overlapping (eg __int32 var_10; __int8 var_F)
	def optimize_overlap(scope)
		varinfo = {}
		scope.symbol.each_value { |var|
			off = varname_to_stackoff(var.name)
			next if not off
			len = @c_parser.sizeof(var)
			varinfo[var] = [off, len]
		}
		varinfo.each { |v1, (o1, l1)|
			next if not v1.type.integral?
			varinfo.each { |v2, (o2, l2)|
				next if v1.name == v2.name or o1 >= o2+l2 or o1+l1 <= o2 or l1 > l2 or (l2 == l1 and o2 > o1)
				# v1 => *(&v2+delta)
				# XXX o1 may overlap o2 AND another...
				p = C::CExpression.new(nil, :&,  v2, C::Pointer.new(v2.type))
				p = C::CExpression.new(nil, nil, p, C::Pointer.new(C::BaseType.new(:__int8))) if v2.type != C::BaseType.new(:__int8)
				o = C::CExpression.new(nil, nil, o1-o2, C::BaseType.new(:__int32))
				p = C::CExpression.new(p,   :+,  o, p.type)
				p = C::CExpression.new(nil, nil, p, C::Pointer.new(v1.type)) if v1.type != p.type.type
				p = C::CExpression.new(nil, :*,  p, v1.type)
				scope.statements.each { |stmt|
					replace_var(stmt, v1, p, false)
				}
			}
		
		}
	end

	def optimize_code(scope)
		sametype = lambda { |t1, t2|
			t1 = t1.untypedef
			t2 = t2.untypedef
			t1 == t2 or
			(t1.kind_of? C::BaseType and t1.integral? and t2.kind_of? C::BaseType and t2.integral? and @c_parser.sizeof(nil, t1) == @c_parser.sizeof(nil, t2)) or
			(t1.pointer? and t2.pointer? and sametype[t1.type, t2.type])
		}

		# most of this is a CExpr#reduce
		future_array = []
		decompile_walk(scope) { |ce_| decompile_walk_ce(ce_, true) { |ce|
			# *&bla => bla if types ok
			if ce.op == :* and not ce.lexpr and ce.rexpr.kind_of? C::CExpression and ce.rexpr.op == :& and not ce.rexpr.lexpr and sametype[ce.type, ce.rexpr.rexpr.type]
				ce.lexpr, ce.op, ce.rexpr, ce.type = ce.rexpr.rexpr.lexpr, ce.rexpr.rexpr.op, ce.rexpr.rexpr.rexpr, ce.rexpr.rexpr.type
			end

			# int x + 0xffffffff -> x-1
			if (ce.op == :+ or ce.op == :- or ce.op == :'+=' or ce.op == :'-=') and ce.lexpr and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and
					ce.rexpr.rexpr == (1 << (8*@c_parser.sizeof(ce.lexpr)))-1
				ce.op = {:+ => :-, :- => :+, :'+=' => :'-=', :'-=' => :'+='}[ce.op]
				ce.rexpr.rexpr = 1
			end

			# int *ptr; *(ptr + 4) => ptr[4]
			if ce.op == :* and not ce.lexpr and ce.rexpr.kind_of? C::CExpression and ce.rexpr.op == :+ and var = ce.rexpr.lexpr and var.kind_of? C::Variable and var.type.pointer?
				ce.lexpr, ce.op, ce.rexpr = ce.rexpr.lexpr, :'[]', ce.rexpr.rexpr
				future_array << var.name
			end

			# char x; x & 255 => x
			if ce.op == :& and ce.lexpr and (ce.lexpr.type.integral? or ce.lexpr.type.pointer?) and ce.rexpr.kind_of? C::CExpression and
					not ce.rexpr.op and ce.rexpr.rexpr.kind_of? ::Integer and m = (1 << (8*@c_parser.sizeof(ce.lexpr))) - 1 and
					ce.rexpr.rexpr & m == m
				ce.lexpr, ce.op, ce.rexpr, ce.type = nil, nil, ce.lexpr, ce.lexpr.type
			end

			# a-b == 0  =>  a == b
			if (ce.op == :== or ce.op == :'!=') and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr == 0 and
					ce.lexpr.kind_of? C::CExpression and ce.lexpr.op == :- and ce.lexpr.lexpr
				ce.lexpr, ce.rexpr = ce.lexpr.lexpr, ce.lexpr.rexpr
			end

			# (a < b) | (a == b)  =>  a <= b
			if ce.op == :| and ce.rexpr.kind_of? C::CExpression and ce.rexpr.op == :== and ce.lexpr.kind_of? C::CExpression and
					(ce.lexpr.op == :< or ce.lexpr.op == :>) and ce.lexpr.lexpr == ce.rexpr.lexpr and ce.lexpr.rexpr == ce.rexpr.rexpr
				ce.op = {:< => :<=, :> => :>=}[ce.lexpr.op]
				ce.lexpr, ce.rexpr = ce.lexpr.lexpr, ce.lexpr.rexpr
			end

			# !(bool) => bool
			if ce.op == :'!' and ce.rexpr.kind_of? C::CExpression and [:'==', :'!=', :<, :>, :<=, :>=, :'||', :'&&', :'!'].include? ce.rexpr.op
				s = ce.rexpr.negate
				ce.lexpr, ce.op, ce.rexpr = s.lexpr, s.op, s.rexpr
			end

			# (foo)(bar)x => (foo)x
			if not ce.op and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr.kind_of? C::CExpression
				ce.rexpr = ce.rexpr.rexpr
			end

			# (foo)bla => bla if bla of type foo
			if not ce.op and ce.rexpr.kind_of? C::CExpression and sametype[ce.type, ce.rexpr.type]
				ce.lexpr, ce.op, ce.rexpr = ce.rexpr.lexpr, ce.rexpr.op, ce.rexpr.rexpr
			end
			if ce.lexpr.kind_of? C::CExpression and not ce.lexpr.op and ce.lexpr.rexpr.kind_of? C::Variable and ce.lexpr.type == ce.lexpr.rexpr.type
				ce.lexpr = ce.lexpr.rexpr
			end
			if ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr.kind_of? C::Variable and ce.rexpr.type == ce.rexpr.rexpr.type
				ce.rexpr = ce.rexpr.rexpr
			end

			# &struct.1stmember => &struct
			if ce.op == :& and not ce.lexpr and ce.rexpr.kind_of? C::CExpression and ce.rexpr.op == :'.' and s = ce.rexpr.lexpr.type and
					s.kind_of? C::Struct and s.offsetof(@c_parser, ce.rexpr.rexpr) == 0
				ce.rexpr = ce.rexpr.lexpr
				ce.type = C::Pointer.new(ce.rexpr.type)
			end

			# *(1stmember*)&struct => struct.1stmember
			if ce.op == :* and not ce.lexpr and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr.kind_of? C::CExpression and
					ce.rexpr.rexpr.op == :& and s = ce.rexpr.rexpr.rexpr.type and s.kind_of? C::Struct and s.members.first and sametype[ce.type, s.members.first.type]
				ce.lexpr, ce.op, ce.rexpr = ce.rexpr.rexpr.rexpr, :'.', s.members.first.name
			end
		} }

		# if there is a ptr[4], change all *ptr to ptr[0] for consistency
		# do this after the first pass, which may change &*ptr to ptr
		decompile_walk(scope) { |ce_| decompile_walk_ce(ce_) { |ce|
			if ce.op == :* and not ce.lexpr and ce.rexpr.kind_of? C::Variable and future_array.include? ce.rexpr.name
				ce.lexpr, ce.op, ce.rexpr = ce.rexpr, :'[]', C::CExpression.new(nil, nil, 0, C::BaseType.new(:int))
			end
		} } if not future_array.empty?
	end

	# checks if a statement :read or :writes a variable
	# :access is like :read, but counts &var too
	def stmt_access(st, var, access)
		case st
		when nil; false
		when ::Array; st.find { |elem| stmt_access elem, var, access }
		when C::Declaration, C::Label, C::Goto, ::Numeric, ::String; false
		when C::Variable; access != :write and var.name == st.name
		when C::Return; stmt_access st.value, var, access
		when C::If; stmt_access(st.test, var, access) or stmt_access(st.bthen, var, access) or stmt_access(st.belse, var, access)
		when C::CExpression
			if access != :write
				if st.op == :'='
					(not st.lexpr.kind_of?(C::Variable) and stmt_access(st.lexpr, var, access)) or
					stmt_access(st.rexpr, var, access)
				elsif access == :read and st.op == :'&' and not st.lexpr and st.rexpr.kind_of? C::Variable
				else stmt_access(st.lexpr, var, access) or stmt_access(st.rexpr, var, access)
				end
			else
				if st.op == :'++' or st.op == :'--'
					e = st.lexpr || st.rexpr
					e.kind_of?(C::Variable) ? var.name == e.name : stmt_access(e, var, access)
				elsif AssignOp.include? st.op
					# *(foo=42) = 28;
					e = st.lexpr
					stmt_access(st.rexpr, var, access) or
					(e.kind_of?(C::Variable) ? var.name == e.name : stmt_access(e, var, access))
				else stmt_access(st.lexpr, var, access) or stmt_access(st.rexpr, var, access)
				end
			end
		when C::Asm; true	# failsafe
		else puts "unhandled #{st.class} in stmt_access" ; true
		end
	end

	# checks if an expr has sideeffects (funcall, var assignment, mem dereference, use var out of scope if specified)
	def sideeffect(exp, scope=nil)
		case exp
		when nil, ::Numeric, ::String; false
		when ::Array; exp.any? { |_e| sideeffect _e, scope }
		when C::Variable; (scope and not scope.symbol[exp.name]) or exp.type.qualifier.to_a.include? :volatile
		when C::CExpression; (exp.op == :* and not exp.lexpr) or exp.op == :funcall or exp.op == :'++' or
				exp.op == :'--' or AssignOp.include?(exp.op) or sideeffect(exp.lexpr, scope) or sideeffect(exp.rexpr, scope)
		else true	# failsafe
		end
	end

	# dataflow optimization
	def optimize_vars(scope)
		# count how many times a var is read in an expr
		cnt = lambda { |exp, var|
			case exp
			when nil, ::Numeric, ::String; 0
			when ::Array; exp.inject(0) { |c, _e| c + cnt[_e, var] }
			when C::CExpression
				c = cnt[exp.rexpr, var]
				if exp.op != :'=' or not exp.lexpr.kind_of? C::Variable
					c += cnt[exp.lexpr, var]
				end
				c
			when C::Variable; exp.name == var.name ? 1 : 0
			end
		}

		# walk
		swapcount = scope.statements.length/4+1	# avoids infinite statement swapping around
		finished = false ; while not finished ; finished = true
			ndel = 0
			scope.statements.length.times { |sti|
				sti -= ndel	# account for delete_at while each
				st = scope.statements[sti]

				# if (x != 0) => if (x)
				if st.kind_of? C::If and st.test.kind_of? C::CExpression and st.test.op == :'!=' and
						st.test.rexpr.kind_of? C::CExpression and not st.test.rexpr.op and st.test.rexpr.rexpr == 0
					st.test = st.test.lexpr
				end

				next if not st.kind_of? C::CExpression

				nt = scope.statements[sti+1]

				# TODO refactor this
				if (st.op == :'++' or st.op == :'--') and not st.lexpr and st.rexpr.kind_of? C::Variable and
					var = scope.symbol[st.rexpr.name] and not var.type.qualifier.to_a.include? :volatile
					# ++i; if(i) => if(++i)    *i=4; ++i => *i++=4
					if stmt_access(nt, var, :read) and e = case nt
						when C::Return; nt.value
						when C::If; nt.test
						when C::CExpression; nt
						end
						found = false
						walk = lambda { |exp|
							# walk in evaluation order, replace 1st occurence
							next if found or not exp.kind_of? C::CExpression
							if AssignOp.include? exp.op
								if exp.rexpr.kind_of? C::Variable and exp.rexpr.name == var.name
									found = true
									exp.rexpr == st
								else walk[exp.rexpr]
								end
								if exp.lexpr.kind_of? C::Variable
									throw :failed if exp.op != :'='
								else walk[exp.lexpr]
								end
							elsif exp.op == :funcall
								# XXX evaluation order ?
								exp.rexpr.each_with_index { |a, i|
									if a.kind_of? C::Variable and a.name == var.name
										next if found
										found = true
										exp.rexpr[i] = st
									else
										walk[a]
									end
								}
								next if found
								if exp.lexpr.kind_of? C::Variable and exp.lexpr.name == var.name
									found = true
									exp.lexpr = st
								else walk[exp.lexpr]
								end
							elsif exp.op == :'&&' or exp.op == :'||'
								walk[exp.lexpr]
							elsif exp.op == :'&' and not exp.lexpr and exp.rexpr.kind_of? C::Variable
							else
								if exp.lexpr.kind_of? C::Variable and exp.lexpr.name == var.name
									found = true
									exp.lexpr = st
								else walk[exp.lexpr]
								end
								next if found
								if exp.rexpr.kind_of? C::Variable and exp.rexpr.name == var.name
									found = true
									exp.rexpr = st
								else walk[exp.rexpr]
								end
							end
						}
						catch(:failed) { walk[e] }
						if found
							finished = false
							scope.statements.delete_at(sti)
							ndel += 1
							next
						end

					# reorder a++; b++; if (a) => swap a & b
					elsif swapcount > 0 and ri = (sti+1..sti+10).find { |ri_|
						case n = scope.statements[ri_]
						when C::CExpression; e = n
						when C::If; e = n.test
						when C::Return; e = n.value
						else break
						end
						if stmt_access(e, var, :access)
							true
						elsif not n.kind_of? C::CExpression or stmt_access(e, var, :write)
							break
						end
					} and ri != sti+1
						swapcount -= 1
						scope.statements[ri-1], scope.statements[sti] = scope.statements[sti], scope.statements[ri-1]
						finished = false
						next	# next ? update sti ? (break bad on infinite loop)
					end

					pt = scope.statements[sti-1]
					if stmt_access(pt, var, :read) and pt.kind_of? C::CExpression
						found = false
						st = C::CExpression.new(st.rexpr, st.op, nil, st.type) 
						walk = lambda { |exp|
							# walk in inverse of evaluation order, replace 1st occurence
							next if found or not exp.kind_of? C::CExpression
							if AssignOp.include? exp.op
								if exp.lexpr.kind_of? C::Variable
									throw :failed if exp.op != :'='
								else walk[exp.lexpr]
								end
								next if found
								if exp.rexpr.kind_of? C::Variable and exp.rexpr.name == var.name
									found = true
									exp.rexpr == st
								else walk[exp.rexpr]
								end
							elsif exp.op == :funcall
								# XXX evaluation order ?
								exp.rexpr.reverse.each_with_index { |a, i|
									i = exp.rexpr.length - i - 1
									if a.kind_of? C::Variable and a.name == var.name
										next if found
										found = true
										exp.rexpr[i] = st
									else
										walk[a]
									end
								}
								next if found
								if exp.lexpr.kind_of? C::Variable and exp.lexpr.name == var.name
									found = true
									exp.lexpr = st
								else walk[exp.lexpr]
								end
							elsif exp.op == :'&&' or exp.op == :'||'
								throw :failed
							elsif exp.op == :'&' and not exp.lexpr and exp.rexpr.kind_of? C::Variable
							else
								if exp.rexpr.kind_of? C::Variable and exp.rexpr.name == var.name
									found = true
									exp.rexpr = st
								else walk[exp.rexpr]
								end
								next if found
								if exp.lexpr.kind_of? C::Variable and exp.lexpr.name == var.name
									found = true
									exp.lexpr = st
								else walk[exp.lexpr]
								end
							end
						}
						catch(:failed) { walk[pt] }
						if found
							finished = false
							scope.statements.delete_at(sti)
							ndel += 1
							next
						end

					elsif swapcount > 0 and ri = [*sti-10...sti].reverse.find { |ri_|
						case n = scope.statements[ri_]
						when C::CExpression; e = n
						when C::If; e = n.test
						when C::Return; e = n.value
						else break
						end
						if stmt_access(e, var, :access)
							true
						elsif not n.kind_of? C::CExpression or stmt_access(e, var, :write)
							break
						end
					} and ri != sti-1
						swapcount -= 1 
						scope.statements[ri+1], scope.statements[sti] = scope.statements[sti], scope.statements[ri+1]
						finished = false
						next	# next ? update sti ? (break bad on infinite loop)
					end
				end


				next if st.op != :'=' or not st.lexpr.kind_of? C::Variable or
					not var = scope.symbol[st.lexpr.name] or var.type.qualifier.to_a.include?(:volatile)

				todo = []
				done = []
				update_todo = lambda { |s, i|
					case s
					when C::Goto
						ns = scope.statements.find { |_s| _s.kind_of? C::Label and _s.name == s.target }
						reused = true if not ns		# failsafe on out of scope jump
						todo << scope.statements.index(ns) if ns
					when C::If
						update_todo[s.bthen, nil]
						todo << i+1
					when C::Return
					else
						todo << i+1
					end
				}

				# we have a local variable assignment
				if stmt_access(nt, var, :read)
					# x=1 ; f(x) => f(1)
					if st.rexpr.kind_of? C::Variable or (st.rexpr.kind_of? C::CExpression and not st.rexpr.op and
							(st.rexpr.rexpr.kind_of? C::Variable or st.rexpr.rexpr.kind_of? ::Integer)) and
							not stmt_access(nt, var, :write)
						trivial = true
					end

					# check if nt uses var more than once
					e = case nt
					when C::Return; nt.value
					when C::If; nt.test
					when C::CExpression; nt
					end
					next if not trivial and cnt[e, var] != 1
					
					# check if var is reused later (assume function graph in only goto/ifgoto)
					# assume there is no ? : construct
					reused = false
					if not stmt_access(nt, var, :write)
						update_todo[nt, sti+1] if nt
						while i = todo.pop
							next if done.include? i
							done << i
							next if not nnt = scope.statements[i]
							reused = true if stmt_access(nnt, var, :read)
							break if reused
							update_todo[nnt, i] if not stmt_access(nnt, var, :write)
						end
					end
					next if not trivial and reused

					# check for conflicting sideeffects (eg x = foo(); bar(baz(), x) => fail ; bar(x, baz()) => ok)
					e = e.rexpr if e.kind_of? C::CExpression and e.op == :'='
					if sideeffect(st.rexpr, scope) and e.kind_of? C::CExpression and e.op == :funcall
						conflict = false
						e.rexpr.each { |a|
							if sideeffect(a, scope)
								conflict = true
								break
							elsif stmt_access(a, var, :read)
								break
							end
						}
						next if conflict
					end

					# remove the assignment and replace the value in nt
					nv = st.rexpr
					if st.rexpr.kind_of? C::CExpression
						nv = nv.reduce(@c_parser)
						nv = C::CExpression.new(nil, nil, nv, C::BaseType.new(:int)) if nv.kind_of? ::Integer
					end
					replace_var nt, var, nv

					finished = false
					if reused	# swap instead of deleting
						scope.statements[sti], scope.statements[sti+1] = scope.statements[sti+1], scope.statements[sti]
					else
						scope.statements.delete_at(sti)
						ndel += 1
					end
					next
				elsif swapcount > 0 and not sideeffect(st.rexpr, scope) and ri = (sti+1..sti+10).find { |ri_|
					case n = scope.statements[ri_]
					when C::CExpression; e = n
					when C::If; e = n.test
					when C::Return; e = n.value
					else break
					end
					if e.op != :'=' or not e.rexpr.kind_of? C::Variable or e.rexpr.name == var.name or sideeffect(e.rexpr, scope)
						break
					elsif stmt_access(e, var, :access)
						true
					elsif not n.kind_of? C::CExpression or stmt_access(e, var, :write)
						break
					end
				} and ri != sti+1
					swapcount -= 1
					scope.statements[ri-1], scope.statements[sti] = scope.statements[sti], scope.statements[ri-1]
					finished = false
					next	# next ? update sti ? (break bad on infinite loop)
				else
					# check if this value is ever used
					reused = false
					update_todo[st, sti]
					while i = todo.pop
						next if done.include? i
						done << i
						next if not nnt = scope.statements[i]
						reused = true if stmt_access(nnt, var, :access)
						break if reused
						update_todo[nnt, i] if not stmt_access(nnt, var, :write)
					end
					next if reused

					# useless cast
					st.rexpr = st.rexpr.rexpr while st.rexpr.kind_of? C::CExpression and not st.rexpr.op


					scope.statements[sti] = st.rexpr

					if not sideeffect(st.rexpr, scope)
						finished = false
						scope.statements.delete_at(sti)
						ndel += 1
						next
					end
				end
			}
		end

		used = {}
		decompile_walk(scope) { |ce_| decompile_walk_ce(ce_, true) { |ce|
			# redo some simplification that may become available after variable propagation
			if ce.op == :& and ce.lexpr and ce.lexpr.type.integral? and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr == (1 << (8*@c_parser.sizeof(ce.lexpr))) - 1
				ce.lexpr, ce.op, ce.rexpr, ce.type = nil, nil, ce.lexpr, ce.lexpr.type
			end

			if not ce.op and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr.kind_of? C::CExpression
				ce.rexpr = ce.rexpr.rexpr
			end

			if not ce.op and ce.rexpr.kind_of? C::CExpression and ce.type == ce.rexpr.type
				ce.lexpr, ce.op, ce.rexpr = ce.rexpr.lexpr, ce.rexpr.op, ce.rexpr.rexpr
			end

			# a & 3 & 1
			while (ce.op == :& or ce.op == :|) and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr.kind_of? ::Integer and
					ce.lexpr.kind_of? C::CExpression and ce.lexpr.op == ce.op and ce.lexpr.lexpr and
					ce.lexpr.rexpr.kind_of? C::CExpression and ce.lexpr.rexpr.rexpr.kind_of? ::Integer
				ce.lexpr, ce.rexpr.rexpr = ce.lexpr.lexpr, ce.lexpr.rexpr.rexpr.send(ce.op, ce.rexpr.rexpr)
			end

			# x = x | 4 => x |= 4
			if ce.op == :'=' and ce.rexpr.kind_of? C::CExpression and [:|, :&, :^, :+, :-, :>>, :<<].include? ce.rexpr.op and ce.rexpr.lexpr == ce.lexpr
				ce.op = (ce.rexpr.op.to_s + '=').to_sym
				ce.rexpr = ce.rexpr.rexpr
			end

			# x += 1 => ++x
			if (ce.op == :'+=' or ce.op == :'-=') and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr == 1
				ce.lexpr, ce.op, ce.rexpr = nil, {:'+=' => :'++', :'-=' => :'--'}[ce.op], ce.lexpr
			end

			# --x+1 => x--
			if (ce.op == :+ or ce.op == :-) and ce.lexpr.kind_of? C::CExpression and ce.lexpr.op == {:+ => :'--', :- => :'++'}[ce.op] and
					ce.lexpr.rexpr and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr == 1
				ce.lexpr, ce.op, ce.rexpr = ce.lexpr.rexpr, ce.lexpr.op, nil
			end

			# remove unreferenced local vars
			used[ce.rexpr.name] = true if ce.rexpr.kind_of? C::Variable
			used[ce.lexpr.name] = true if ce.lexpr.kind_of? C::Variable
			ce.rexpr.each { |v| used[v.name] = true if v.kind_of? C::Variable } if ce.rexpr.kind_of?(::Array)
		} }
		scope.statements.delete_if { |sm| sm.kind_of? C::Declaration and not used[sm.var.name] }
		scope.symbol.delete_if { |n, v| not used[n] }
	end

	# yield each CExpr member (recursive, allows arrays, order: self(!post), lexpr, rexpr, self(post))
	def decompile_walk_ce(ce, post=false, &b)
		case ce
		when C::CExpression
			yield ce if not post
			decompile_walk_ce(ce.lexpr, post, &b)
			decompile_walk_ce(ce.rexpr, post, &b)
			yield ce if post
		when ::Array
			ce.each { |ce_| decompile_walk_ce(ce_, post, &b) }
		end
	end

	# yields each statement (recursive)
	def decompile_walk(scope, post=false, &b)
		case scope
		when ::Array; scope.each { |s| decompile_walk(s, post, &b) }
		when C::Statement
			yield scope
			case scope
			when C::Block; decompile_walk(scope.statements, post, &b)
			when C::If
				yield scope.test
				decompile_walk(scope.bthen, post, &b)
				decompile_walk(scope.belse, post, &b) if scope.belse
			when C::While, C::DoWhile
				yield scope.test
				decompile_walk(scope.body, post, &b)
			when C::Return
				yield scope.value
			end
		end
	end
end
end
