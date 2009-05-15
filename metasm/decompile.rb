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

	# decompile recursively function from an entrypoint, then perform global optimisation (static vars, ...)
	# should be called once after everything is decompiled (global optimizations may bring bad results otherwise)
	# use decompile_func for incremental decompilation
	# returns the c_parser
	def decompile(*entry)
		entry.each { |f| decompile_func(f) }
		make_static_vars
		@c_parser
	end

	# decompile a function, decompiling subfunctions as needed
	# may return :restart, which means that the decompilation should restart from the entrypoint (and bubble up) (eg a new codepath is found which may changes dependency in blocks etc)
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

		while catch(:restart) { do_decompile_func(entry, func) } == :restart
			retval = :restart
		end

		@c_parser.toplevel.statements << C::Declaration.new(func)

		retval
	end

	def do_decompile_func(entry, func)
		# TODO check ABI conformance between func start&end (saved regs, stack offset, __declspec, ...)
		# TODO handle jmp tables

		# find decodedinstruction blocks constituing the function
		# TODO merge sequencial blocks with useless jmp (poeut) to improve dependency graph later
		myblocks = decompile_func_listblocks(entry)

		# [esp+8] => [:frameptr-12]
		decompile_makestackvars entry, myblocks.map { |b, to| @dasm.decoded[b].block }

		# find registry dependencies between blocks
		deps = @dasm.cpu.decompile_func_finddeps(self, myblocks)

		scope = func.initializer = C::Block.new(@c_parser.toplevel)
		# di blocks => raw c statements, declare variables
		@dasm.cpu.decompile_blocks(self, myblocks, deps, scope)

		# goto bla ; bla: goto blo => goto blo ;; goto bla ; bla: return => return
		decompile_simplify_goto(scope)

		# infer variable types
		decompile_c_types(scope)

		# cleanup C
		optimize(scope)

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

		# ensure arglist has no hole (create&add unreferenced args)
		func.type.args = []
		argoff = varname_to_stackoff('arg_0')
		args.sort_by { |sm| sm.name[/arg_([0-9a-f]+)/i, 1].to_i(16) }.each { |a|
			# XXX misalignment ?
			curoff = varname_to_stackoff(a.name)
			while curoff > argoff
				wantarg = C::Variable.new
				wantarg.name = stackoff_to_varname(argoff).to_s
				wantarg.type = C::BaseType.new(:int)
				wantarg.attributes = ['unused']
				func.type.args << wantarg
				scope.symbol[wantarg.name] = wantarg
				argoff += @dasm.cpu.size/8
			end
			func.type.args << a
			argoff += @dasm.cpu.size/8
		}

		# change if() goto to if, if/else, while
		decompile_match_controlseq(scope)

		optimize_vars(scope)

		decompile_optimize_ctrl(scope)

		case ret = scope.statements.last
		when C::CExpression; puts "no return at end of func" if $VERBOSE
		when C::Return
			if not ret.value
				scope.statements.pop
			else
				func.type.type = ret.value.type
			end
		end
	end

	def new_global_var(addr, type)
		return if not type.pointer?

		# TODO check overlap with alreadydefined globals

		ptype = type.untypedef.type
		name = case tsz = @c_parser.sizeof(nil, ptype)
		when 1; 'byte'
		when 2; 'word'
		when 4; 'dword'
		else 'global'
		end
		name = @dasm.auto_label_at(addr, name)

		if not var = @c_parser.toplevel.symbol[name]
			var = C::Variable.new
			var.name = name
			var.type = C::Array.new(ptype)
			@c_parser.toplevel.symbol[var.name] = var
			@c_parser.toplevel.statements << C::Declaration.new(var)
			if s = @dasm.get_section_at(name) and s[0].ptr < s[0].length and [1, 2, 4].include? tsz
				# XXX initializer = all data til next defined thing (after unaliasing)
				var.initializer = [C::CExpression[s[0].decode_imm("u#{tsz*8}".to_sym, @dasm.cpu.endianness), ptype]]
			end
		end

		# TODO patch existing references to addr ? (or would they have already triggered new_global_var?)

		# return the object to use to replace the raw addr
		var
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
					# possible noreturn function
					# XXX call $+5; pop eax
					@autofuncs << ta
					@dasm.function[ta] = DecodedFunction.new
					puts "autofunc #{Expression[ta]}" if $VERBOSE
				end
				
				if @dasm.function[ta] and type != :subfuncret
					f = dasm.auto_label_at(ta, 'func')
					ta = dasm.normalize($1) if f =~ /^thunk_(.*)/
					ret = decompile_func(ta) if ta != entry
					throw :restart, :restart if ret == :restart
				else
					@dasm.auto_label_at(ta, 'label') if blocks.find { |aa, at| aa == ta }
					blocks.last[1] |= [ta]
					todo << ta
				end
			}
		end
		blocks
	end

	# backtraces an expression from addr
	# returns an integer, a label name, or an Expression
	# XXX '(GetProcAddr("foo"))()' should not decompile to 'foo()'
	def backtrace_target(expr, addr)
		if n = @dasm.backtrace(expr, addr).first
			n = Expression[n].reduce_rec
			n = @dasm.prog_binding.index(n) || n
			n = $1 if n.kind_of? ::String and n =~ /^thunk_(.*)/
			n
		end
	end

	# patches instruction's backtrace_binding to replace things referring to a static stack offset from func start by :frameptr+off
	def decompile_makestackvars(funcstart, blocks)
		blockstart = nil
		tovar = lambda { |di, e, i_s|
			case e
			when Expression; Expression[tovar[di, e.lexpr, i_s], e.op, tovar[di, e.rexpr, i_s]].reduce
			when Indirection; Indirection[tovar[di, e.target, i_s], e.len]
			when :frameptr; e
			when ::Symbol
				vals = @dasm.backtrace(e, di.address, :snapshot_addr => blockstart, :include_start => i_s)
				# backtrace only to blockstart first
				if vals.length == 1 and ee = vals.first and ee.kind_of? Expression and (ee == Expression[:frameptr] or
						(ee.lexpr == :frameptr and ee.op == :+ and ee.rexpr.kind_of? ::Integer) or
						(not ee.lexpr and ee.op == :+ and ee.rexpr.kind_of? Indirection and eep = ee.rexpr.pointer and
						(eep == Expression[:frameptr] or (eep.lexpr == :frameptr and eep.op == :+ and eep.rexpr.kind_of? ::Integer))))
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

		# must not change bt_bindings until everything is backtracked
		repl_bind = {}	# di => bt_bd

		@dasm.cpu.decompile_makestackvars(@dasm, funcstart, blocks) { |block|
			block.list.each { |di|
				bd = di.backtrace_binding ||= @dasm.cpu.get_backtrace_binding(di)
				newbd = repl_bind[di] = {}
				bd.each { |k, v|
					k = tovar[di, k, true] if k.kind_of? Indirection
					next if k == Expression[:frameptr] or (k.kind_of? Expression and k.lexpr == :frameptr and k.op == :+ and k.rexpr.kind_of? ::Integer)
					newbd[k] = tovar[di, v, false]
				}
			}
		}

		repl_bind.each { |di, bd| di.backtrace_binding = bd }
	end

	# give a name to a stackoffset (relative to start of func)
	# 4 => :arg_0, -8 => :var_4 etc
	def stackoff_to_varname(off)
		if off >= @dasm.cpu.size/8
			'arg_%X' % ( off-@dasm.cpu.size/8)	#  4 => arg_0,  8 => arg_4..
		elsif off > 0
			'arg_0%X' % off
		elsif off == 0
			'retaddr'
		elsif off <= -@dasm.cpu.size/8
			'var_%X' % (-off-@dasm.cpu.size/8)	# -4 => var_0, -8 => var_4..
		else
			'var_0%X' % -off
		end.to_sym
	end

	def varname_to_stackoff(var)
		case var.to_s
		when /^arg_0(.+)/;  $1.to_i(16)
		when /^var_0(.+)/; -$1.to_i(16)
		when /^arg_(.*)/;  $1.to_i(16) + @dasm.cpu.size/8
		when /^var_(.*)/; -$1.to_i(16) - @dasm.cpu.size/8
		when 'retaddr'; 0
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
				C::CExpression[a, e.op, decompile_cexpr(e.rexpr, scope)]
			elsif e.op == :+
				decompile_cexpr(e.rexpr, scope)
			else
				a = decompile_cexpr(e.rexpr, scope)
				C::CExpression[e.op, a]
			end
		when Indirection
			p = decompile_cexpr(e.target, scope)
			C::CExpression[:*, [[p], C::Pointer.new(C::BaseType.new("__int#{e.len*8}".to_sym))]]
		when ::Integer
			C::CExpression[e]
		when C::CExpression
			e
		else
			name = e.to_s
			if not s = scope.symbol_ancestors[name]
				s = C::Variable.new
				s.type = C::BaseType.new(:__int32)
				if e.kind_of? ::String
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
						when C::Return
						       v = nt.value
						       v = v.deep_dup if v.kind_of? C::CExpression
					       	       ret = C::Return.new(v)
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

		decompile_remove_labels(scope)
	end

	# changes ifgoto, goto to while/ifelse..
	def decompile_match_controlseq(scope)
		scope.statements = decompile_cseq_if(scope.statements, scope)
		decompile_cseq_while(scope.statements, scope)
		decompile_cseq_switch(scope)
	end

	# optimize if() { a; } to if() a;
	def decompile_optimize_ctrl(scope)
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
						e[i] = walk[st, l1, l2]
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
		walk[scope, nil, nil]

		decompile_remove_labels(scope)

		# while (1) { a; if(b) { c; return; }; d; }  =>  while (1) { a; if (b) break; d; } c;
		while st = scope.statements.last and st.kind_of? C::While and st.test.kind_of? C::CExpression and
				not st.test.op and st.test.rexpr == 1 and st.body.kind_of? C::Block
			break if not i = st.body.statements.find { |ist|
				ist.kind_of? C::If and not ist.belse and ist.bthen.kind_of? C::Block and ist.bthen.statements.last.kind_of? C::Return
			}
			decompile_walk(i.bthen.statements) { |sst| sst.outer = i.bthen.outer if sst.kind_of? C::Block and sst.outer == i.bthen }
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
							ce.bthen.outer.statements[i] = ce.test	# TODO remove sideeffectless parts
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
					w = C::While.new(C::CExpression[1], wb)
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
		ary
	end

	def decompile_cseq_switch(scope)
		uncast = lambda { |e| e = e.rexpr while e.kind_of? C::CExpression and not e.op ; e }
		decompile_walk(scope) { |s|
			# XXX pfff...
			next if not s.kind_of? C::If
			# if (v < 12) return ((void(*)())(tableaddr+4*v))();
			t = s.bthen
			t = t.statements.first if t.kind_of? C::Block and t.statements.length == 1
			next if not t.kind_of? C::Return or not t.respond_to? :from_instr
			next if t.from_instr.comment.to_a.include? 'switch'
			next if not t.value.kind_of? C::CExpression or t.value.op != :funcall or t.value.rexpr != [] or not t.value.lexpr.kind_of? C::CExpression or t.value.lexpr.op
			p = uncast[t.value.lexpr.rexpr]
			next if p.op != :* or p.lexpr
			p = uncast[p.rexpr]
			next if p.op != :+
			r, l = uncast[p.rexpr], uncast[p.lexpr]
			r, l = l, r if r.kind_of? C::CExpression
			next if not r.kind_of? ::Integer or not l.kind_of? C::CExpression or l.op != :* or not l.lexpr
			lr, ll = uncast[l.rexpr], uncast[l.lexpr]
			lr, ll = ll, lr if not ll.kind_of? ::Integer
			next if ll != @c_parser.sizeof(nil, C::Pointer.new(C::BaseType.new(:void)))
			base, index = r, lr
			if s.test.kind_of? C::CExpression and (s.test.op == :<= or s.test.op == :<) and s.test.lexpr == index and
					s.test.rexpr.kind_of? C::CExpression and not s.test.rexpr.op and s.test.rexpr.rexpr.kind_of? ::Integer
				t.from_instr.add_comment 'switch'
				sup = s.test.rexpr.rexpr
				rng = ((s.test.op == :<) ? (0...sup) : (0..sup))
				from = t.from_instr.address
				rng.map { |i| @dasm.backtrace(Indirection[base+ll*i, ll, from], from, :type => :x, :origin => from, :maxdepth => 0) }
				@dasm.disassemble
				throw :restart, :restart
			end
			puts "unhandled switch() at #{t.from_instr}" if $VERBOSE
		}
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

	# assign type to stackframe offsets, replace fptr-12 by var_8
	# types are found by subfunction argument types / indirections, and propagated through assignments
	def decompile_c_types(scope)
		# TODO handle aliases (mem+regs) (reverse liveness?) XXX this would take place in make_stack_vars
		# TODO allow user-predefined types (args/local vars)
		# TODO *(int8*)(ptr+8); *(int32*)(ptr+12) => automatic struct
		# TODO type global vars too
		# XXX walk { walk {} } too much, optimize

		# types = { off => type of *(frameptr+off) }
		types = {}
		vartypes = {}

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
		globalvar = lambda { |e|
			e if e.kind_of? ::Integer and @dasm.get_section_at(e)
		}
		update_global_type = lambda { |e, t|
			if ne = new_global_var(e, t)
				decompile_walk(scope) { |ce_| decompile_walk_ce(ce_) { |ce|
					ce.lexpr = ne if ce.lexpr == e
					ce.rexpr = ne if ce.rexpr == e
					if ce.lexpr == ne or ce.rexpr == ne
						# set ce type according to l/r
						# TODO set ce.parent type etc
						ce.type = C::CExpression[ce.lexpr, ce.op, ce.rexpr].type
					end
				} }
			end
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
				#puts "#{o} => #{t}"
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
				elsif o = globalvar[e]
					update_global_type[o, t]
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
						if e.rexpr.rexpr < 0x1000	# XXX relocatable + base=0..
							e = e.lexpr	# (int)*(x+2) === (int) *x
						elsif globalvar[e.rexpr.rexpr]
							known_type[e.lexpr, C::BaseType.new(:int)]
							e = e.rexpr
						end
						next
					elsif t.pointer? and e.lexpr.kind_of? C::CExpression
						if (e.lexpr.lexpr and [:<<, :>>, :*, :&].include? e.lexpr.op) or
								(o = framepoff[e.lexpr] and types[o] and types[o].integral? and
								 !(o = framepoff[e.rexpr] and types[o] and types[o].integral?))
							e.lexpr, e.rexpr = e.rexpr, e.lexpr
							e = e.lexpr
							next
						elsif o = framepoff[e.rexpr] and types[o] and types[o].integral? and
								!(o = framepoff[e.lexpr] and types[o] and types[o].integral?)
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
				if ce.op == :'&' and ce.lexpr and ce.lexpr.type.integral? and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr == (1 << (8*@c_parser.sizeof(ce.lexpr))) - 1
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


		# put all those macros in use
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
			# keep var type qualifiers
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
				v = C::CExpression[:*, [[:&, v], C::Pointer.new(e.type)]]
			end
			v
		}

		decompile_walk(scope) { |ce_| decompile_walk_ce(ce_) { |ce|
			case
			when ce.op == :funcall
				ce.rexpr.map! { |re|
					if o = framepoff[re]; maycast[varat[o], re]
					elsif o = frameoff[re]; C::CExpression[:&, varat[o]]
					else re
					end
				}
			when o = framepoff[ce.lexpr]; ce.lexpr = maycast[varat[o], ce.lexpr]
			when o = framepoff[ce.rexpr]; ce.rexpr = maycast[varat[o], ce.rexpr]
			when o = frameoff[ce.lexpr]; ce.lexpr = C::CExpression[:&, varat[o]]
			when o = frameoff[ce.rexpr]; ce.rexpr = C::CExpression[:&, varat[o]]
			when o = framepoff[ce]
				e = maycast[varat[o], ce]
				if e.kind_of? C::CExpression
					ce.lexpr, ce.op, ce.rexpr, ce.type = e.lexpr, e.op, e.rexpr, e.type
				else
					ce.lexpr, ce.op, ce.rexpr, ce.type = nil, nil, e, e.type
				end
			when o = frameoff[ce]; ce.lexpr, ce.op, ce.rexpr, ce.type = nil, :&, varat[o], C::Pointer.new(varat[o].type)
			end
		} }

		fix_pointer_arithmetic(scope)
		fix_type_overlap(scope)

		# if int32 var_4 is always var_4 & 255, change type to int8
		varuse = Hash.new(0)
		varandff = Hash.new(0)
		varandffff = Hash.new(0)
		decompile_walk(scope) { |ce_| decompile_walk_ce(ce_) { |ce|
			if ce.op == :& and ce.lexpr.kind_of? C::Variable and ce.lexpr.type.integral? and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr.kind_of? ::Integer
				case ce.rexpr.rexpr
				when 0xff; varandff[ce.lexpr.name] += 1
				when 0xffff; varandffff[ce.lexpr.name] += 1
				end
			end
			varuse[ce.lexpr.name] += 1 if ce.lexpr.kind_of? C::Variable
			varuse[ce.rexpr.name] += 1 if ce.rexpr.kind_of? C::Variable
		} }
		varandff.each { |k, v|
			scope.symbol[k].type = C::BaseType.new(:__int8, :unsigned) if varuse[k] == v
		}
		varandffff.each { |k, v|
			scope.symbol[k].type = C::BaseType.new(:__int16, :unsigned) if varuse[k] == v
		}

		# propagate types to cexprs
		decompile_walk(scope) { |ce_| decompile_walk_ce(ce_, true) { |ce|
			if ce.op
				ce.type = C::CExpression[ce.lexpr, ce.op, ce.rexpr].type
				if ce.op == :'=' and ce.rexpr.type != ce.type and (not ce.rexpr.type.integral? or not ce.type.integral?)
					ce.rexpr = C::CExpression[ce.rexpr, ce.type]
				end
			end
		} }
	end

	# fix pointer arithmetic (eg int foo += 4  =>  int* foo += 1)
	# use struct member access (eg *(structptr+8)  =>  structptr->bla)
	# must be run only once, right after type setting
	def fix_pointer_arithmetic(scope)
		decompile_walk(scope) { |ce_| decompile_walk_ce(ce_, true) { |ce|
			next if not ce.kind_of? C::CExpression
			if ce.lexpr and ce.lexpr.type.pointer? and [:&, :>>, :<<].include? ce.op
				ce.lexpr = C::CExpression[[ce.lexpr], C::BaseType.new(:int)]
			end

			if ce.op == :+ and ce.lexpr and ce.lexpr.type.integral? and ce.rexpr.type.pointer?
				ce.rexpr, ce.lexpr = ce.lexpr, ce.rexpr
			end

			if ce.op == :* and not ce.lexpr and ce.rexpr.type.pointer? and ce.rexpr.type.untypedef.type.untypedef.kind_of? C::Struct
				s = ce.rexpr.type.untypedef.type.untypedef
				m = s.members.find { |m_| s.offsetof(@c_parser, m_.name) == 0 }
				if @c_parser.sizeof(m) != @c_parser.sizeof(ce)
					ce.rexpr = C::CExpression[[ce.rexpr, C::Pointer.new(s)], C::Pointer.new(ce.type)]
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

			if ce.op == :+ and ce.lexpr and ce.lexpr.type.pointer? and not ce.type.pointer?
				ce.type = ce.lexpr.type
			end

			next if not ce.lexpr or not ce.lexpr.type.pointer?
			if ce.op == :+ and ce.lexpr.type.untypedef.type.untypedef.kind_of? C::Struct and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and
					ce.rexpr.rexpr.kind_of? ::Integer and s = ce.lexpr.type.untypedef.type.untypedef and
					o = ce.rexpr.rexpr and tabidx = o / @c_parser.sizeof(nil, s) and
					o -= tabidx * @c_parser.sizeof(nil, s) and m = s.members.find { |m_| s.offsetof(@c_parser, m_.name) == o }
				# structptr + 4 => &structptr->member
				if tabidx != 0
					ce.rexpr = C::CExpression[[ce.lexpr, :'[]', [tabidx]], :'.', m.name]
				else
					ce.rexpr = C::CExpression[ce.lexpr, :'->', m.name]
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
				ce.rexpr = C::CExpression[ce.rexpr, C::BaseType.new(:int)] if not ce.rexpr.type.integral?
				if @c_parser.sizeof(nil, ce.lexpr.type.untypedef.type) != 1
					ptype = ce.lexpr.type
					ce.lexpr = C::CExpression[[ce.lexpr], C::Pointer.new(C::BaseType.new(:__int8))]
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
		when C::While, C::DoWhile, C::Switch
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

	# handling of var overlapping (eg __int32 var_10; __int8 var_F  =>  replace all var_F by *((int8*)&var_10 + 1))
	def fix_type_overlap(scope)
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
				# XXX o1 may overlap o2 AND another (int32 v_10; int32 v_E; int32 v_C;)
				p = C::CExpression[:&, v2]
				p = C::CExpression[p, C::Pointer.new(C::BaseType.new(:__int8))] if v2.type != C::BaseType.new(:__int8)
				p = C::CExpression[p, :+,  [o1-o2]]
				p = C::CExpression[p, C::Pointer.new(v1.type)] if v1.type != p.type.type
				p = C::CExpression[:*,  p]
				scope.statements.each { |stmt|
					replace_var(stmt, v1, p, false)
				}
			}
		
		}
	end

	# to be run with scope = function body with only CExpr/Decl/Label/Goto/IfGoto/Return, with correct variables types
	# will transform += 1 to ++, inline them to prev/next statement ('x++; if (x)..' => 'if (++x)..')
 	# remove useless variables ('int i;', i never used or 'i = 1; j = i;', i never read after => 'j = 1;')
	# remove useless casts ('(int)i' with 'int i;' => 'i')
	# also removes 'enter' traduction ('var_0 = ebp;' => '')
	def optimize(scope)
		optimize_code(scope)
		optimize_vars(scope)
		optimize_vars(scope)	# 1st run may transform i = i+1 into i++ which second run may coalesce into if(i)
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
			if ce.op == :* and not ce.lexpr and ce.rexpr.kind_of? C::CExpression and ce.rexpr.op == :& and not ce.rexpr.lexpr and sametype[ce.rexpr.type.type, ce.rexpr.rexpr.type]
				if ce.rexpr.rexpr.kind_of? C::CExpression
					ce.lexpr, ce.op, ce.rexpr, ce.type = ce.rexpr.rexpr.lexpr, ce.rexpr.rexpr.op, ce.rexpr.rexpr.rexpr, ce.rexpr.rexpr.type
				else
					ce.lexpr, ce.op, ce.rexpr, ce.type = nil, nil, ce.rexpr.rexpr, ce.rexpr.rexpr.type
				end
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

			# a + -b  =>  a - b
			if ce.op == :+ and ce.lexpr and ce.rexpr.kind_of? C::CExpression and ce.rexpr.op == :- and not ce.rexpr.lexpr
				ce.op, ce.rexpr = :-, ce.rexpr.rexpr
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
				ce.lexpr, ce.op, ce.rexpr = ce.rexpr, :'[]', C::CExpression[0]
			end
		} } if not future_array.empty?
	end

	# checks if a statement :read or :writes a variable
	# :access is like :read, but counts &var too
	def stmt_access(st, var, access)
		case st
		when nil; false
		when ::Array; st.find { |elem| stmt_access elem, var, access }
		when C::Declaration, C::Label, C::Goto, C::Break, C::Continue, ::Numeric, ::String; false
		when C::Variable; access != :write and var.name == st.name
		when C::Return; stmt_access st.value, var, access
		when C::If; stmt_access(st.test, var, access) or stmt_access(st.bthen, var, access) or stmt_access(st.belse, var, access)
		when C::While, C::DoWhile, C::Switch; stmt_access(st.test, var, access) or stmt_access(st.body, var, access)
		when C::Block; stmt_access(st.statements, var, access)
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
		when C::Asm
			if access == :write
				st.output == [] ? false : true
			else
				st.input == [] ? false : true
			end
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
							redo
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
						scope.statements.insert(ri-1, scope.statements.delete_at(sti))
						finished = false
						redo
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
									throw :failed if exp.op != :'=' and exp.lexpr.name == var.name
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
							redo
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
						scope.statements.insert(ri+1, scope.statements.delete_at(sti))
						finished = false
						break
					end
				end


				next if st.op != :'=' or not st.lexpr.kind_of? C::Variable or
					not var = scope.symbol[st.lexpr.name] or var.type.qualifier.to_a.include?(:volatile)
				next if stmt_access(st.rexpr, var, :read)

				todo = []
				done = []
				reused = false
				trivial = nil
				update_todo = lambda { |s, i|
					case s
					when C::Goto
						ns = scope.statements.find { |_s| _s.kind_of? C::Label and _s.name == s.target }
						reused = true if not ns		# failsafe on out of scope jump
						todo << scope.statements.index(ns) if ns
					when C::If
						if s.belse or not s.bthen.kind_of? C::Goto
							reused = true 
							trivial = false
							next
						end
						update_todo[s.bthen, nil]
						todo << i+1
					when C::Return
					when C::CExpression, C::Label, C::Declaration
						todo << i+1
					else
						reused = true	# safe > sorry
					end
				}

				if not sideeffect(st.rexpr, scope) and not stmt_access(nt, var, :write) and st.complexity < 10	# XXX should take complexity of the whole resulting CExpr
					# var_0 = var_4 + 12;
					trivial = []	# list of vars var depends on
					decompile_walk_ce(st.rexpr) { |ce_|
						trivial << ce_.lexpr if ce_.lexpr.kind_of? C::Variable
						trivial << ce_.rexpr if ce_.rexpr.kind_of? C::Variable
					}
				end

				# we have a local variable assignment

				if stmt_access(nt, var, :read)
					# x=1 ; f(x) => f(1)
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
					if not stmt_access(e, var, :write)
						update_todo[nt, sti+1] if nt
						while i = todo.pop
							next if done.include? i
							done << i
							next if not nnt = scope.statements[i]
							reused = true if stmt_access(nnt, var, :access)
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
					if nv.kind_of? C::CExpression
						nv = C::CExpression[nv.reduce(@c_parser)]
					end
					replace_var nt, var, nv

					finished = false
					if reused	# swap instead of deleting
						scope.statements[sti], scope.statements[sti+1] = scope.statements[sti+1], scope.statements[sti]
					else
						scope.statements.delete_at(sti)
						ndel += 1
						redo
					end
					next
				elsif swapcount > 0 and not sideeffect(st.rexpr, scope) and ri = (sti+1..sti+10).find { |ri_|
					case n = scope.statements[ri_]
					when C::CExpression; e = n
					when C::If, C::While; e = n.test
					when C::Return; e = n.value
					else break
					end
					if stmt_access(e, var, :access)
						true
					elsif not n.kind_of? C::CExpression or stmt_access(e, var, :write) or
							(not trivial and sideeffect(e, scope)) or
							(trivial and trivial.find { |tv| stmt_access(e, tv, :write) })
						break
					end
				} and ri != sti+1
					swapcount -= 1
					scope.statements.insert(ri-1, scope.statements.delete_at(sti))
					finished = false
					redo
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
					# TODO suppress other sideeffectless toplevel CExpr
					st.rexpr = st.rexpr.rexpr while st.rexpr.kind_of? C::CExpression and not st.rexpr.op and st.rexpr.kind_of? C::CExpression

					scope.statements[sti] = st.rexpr

					if not sideeffect(st.rexpr, scope)
						finished = false
						scope.statements.delete_at(sti)
						ndel += 1
						redo
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

			# useless casts
			if not ce.op and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr.kind_of? C::CExpression
				ce.rexpr = ce.rexpr.rexpr
			end
			if not ce.op and ce.rexpr.kind_of? C::CExpression and (ce.type == ce.rexpr.type or (ce.type.integral? and ce.rexpr.type.integral?))
				ce.lexpr, ce.op, ce.rexpr = ce.rexpr.lexpr, ce.rexpr.op, ce.rexpr.rexpr
			end
			# conditions often are x & 0xffffff which may cast pointers to ints, remove those casts
			if ce.op == :== and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr == 0
				ce.lexpr, ce.op, ce.rexpr = nil, :'!', ce.lexpr
			end
			if ce.op == :'!' and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr.kind_of? C::CExpression
				ce.rexpr = ce.rexpr.rexpr
			end
			if ce.op == :< and ce.rexpr.kind_of? C::CExpression and ce.lexpr.kind_of? C::CExpression and not ce.rexpr.op and not ce.lexpr.op and
				ce.rexpr.rexpr.kind_of? C::CExpression and ce.rexpr.rexpr.type.pointer? and ce.lexpr.rexpr.kind_of? C::CExpression and ce.lexpr.rexpr.type.pointer?
				ce.rexpr = ce.rexpr.rexpr
				ce.lexpr = ce.lexpr.rexpr
			end

			# a & 3 & 1
			while (ce.op == :& or ce.op == :|) and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr.kind_of? ::Integer and
					ce.lexpr.kind_of? C::CExpression and ce.lexpr.op == ce.op and ce.lexpr.lexpr and
					ce.lexpr.rexpr.kind_of? C::CExpression and ce.lexpr.rexpr.rexpr.kind_of? ::Integer
				ce.lexpr, ce.rexpr.rexpr = ce.lexpr.lexpr, ce.lexpr.rexpr.rexpr.send(ce.op, ce.rexpr.rexpr)
			end

			# x = x | 4 => x |= 4
			if ce.op == :'=' and ce.rexpr.kind_of? C::CExpression and [:+, :-, :*, :/, :|, :&, :^, :>>, :<<].include? ce.rexpr.op and ce.rexpr.lexpr == ce.lexpr
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

	def make_static_vars
		# check all global vars (pointers to global data)
		tl = @c_parser.toplevel
		vars = tl.symbol.keys.find_all { |k| not tl.symbol[k].type.kind_of? C::Function }
		countref = Hash.new(0)

		decompile_walk(tl) { |ce_| decompile_walk_ce(ce_) { |ce|
			# XXX int foo; void bar() { int foo; }  =>  false negative
			countref[ce.rexpr.name] += 1 if ce.rexpr.kind_of? C::Variable
			countref[ce.lexpr.name] += 1 if ce.lexpr.kind_of? C::Variable
		} }

		vars.delete_if { |v| countref[v] == 0 }
		countref.delete_if { |k, v| not vars.include? k }

		# by default globals are C::Arrays
		# if all references are *foo, dereference the var type
		# TODO allow foo to appear (change to &foo) (but still disallow casts/foo+12 etc)
		countderef = Hash.new(0)
		decompile_walk(tl) { |ce_| decompile_walk_ce(ce_) { |ce|
			countderef[ce.rexpr.name] += 1 if ce.op == :* and not ce.lexpr and ce.rexpr.kind_of? C::Variable
			countderef[ce.rexpr.rexpr.name] += 1 if ce.op == :* and not ce.lexpr and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and
					# compare type.type cause var is an Array and the cast is a Pointer
					ce.rexpr.rexpr.kind_of? C::Variable and ce.rexpr.type.type == ce.rexpr.rexpr.type.type rescue nil
		} }
		vars.each { |n|
			if countref[n] == countderef[n]
				v = tl.symbol[n]
				target = C::CExpression[:*, [v]]
				v.type = v.type.type
				v.initializer = v.initializer.first if v.initializer.kind_of? ::Array
				decompile_walk(tl) { |ce_| decompile_walk_ce(ce_) { |ce|
					ce.lexpr = v if ce.lexpr == target
					ce.rexpr = v if ce.rexpr == target
					ce.lexpr, ce.op, ce.rexpr = nil, nil, v if ce == target
				} }
			end
		}

		# if a global var appears only in one function, make it a static variable
		tl.statements.each { |st|
			next if not st.kind_of? C::Declaration or not st.var.type.kind_of? C::Function or not scope = st.var.initializer
			localcountref = Hash.new(0)
			decompile_walk(scope) { |ce_| decompile_walk_ce(ce_) { |ce|
				localcountref[ce.rexpr.name] += 1 if ce.rexpr.kind_of? C::Variable
				localcountref[ce.lexpr.name] += 1 if ce.lexpr.kind_of? C::Variable
			} }

			vars.delete_if { |n|
				next if scope.symbol[n]
				next if localcountref[n] != countref[n]
				v = scope.symbol[n] = tl.symbol.delete(n)
				v.storage = :static
				tl.statements.delete_if { |d|
					if d.kind_of? C::Declaration and d.var.name == n
						scope.statements.unshift d
						true
					end
				}
				true
			}
		}

		vars.sort.each { |v| puts "#{v} #{countref[v]} #{countderef[v]}" }
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
			yield scope if not post
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
			yield scope if post
		when C::Declaration
			decompile_walk(scope.var.initializer, post, &b) if scope.var.initializer
		end
	end
end
end
