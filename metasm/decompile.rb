require 'metasm/decode'
require 'metasm/parse_c'

module Metasm
class C::Variable; attr_accessor :stackoff; end
class Decompiler
	# TODO add methods to C::CExpr
	AssignOp = [:'=', :'+=', :'-=', :'*=', :'/=', :'%=', :'^=', :'&=', :'|=', :'>>=', :'<<=', :'++', :'--']

	attr_accessor :dasm, :c_parser
	attr_accessor :forbid_optimize_dataflow, :forbid_optimize_code, :forbid_decompile_while, :forbid_decompile_types, :forbid_optimize_labels

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
		optimize_global
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
		func.type = C::Function.new C::BaseType.new(:int), []
		if @c_parser.toplevel.symbol[func.name]
			if not @c_parser.toplevel.statements.grep(C::Declaration).find { |decl| decl.var.name == func.name }
				# recursive dependency: declare prototype
				@c_parser.toplevel.statements << C::Declaration.new(func)
			end
			return
		end
		@c_parser.toplevel.symbol[func.name] = func
		puts "decompiling #{func.name}" if $VERBOSE

		while catch(:restart) { do_decompile_func(entry, func) } == :restart
			retval = :restart
		end

		@c_parser.toplevel.statements << C::Declaration.new(func)

		puts " decompiled #{func.name}" if $VERBOSE

		retval
	end

	def do_decompile_func(entry, func)
		# TODO check ABI conformance between func start&end (saved regs, stack offset, __declspec, ...)
		# TODO handle jmp tables

		# find decodedinstruction blocks constituing the function
		# TODO merge sequencial blocks with useless jmp (poeut) to improve dependency graph later
		myblocks = listblocks_func(entry)

		# [esp+8] => [:frameptr-12]
		makestackvars entry, myblocks.map { |b, to| @dasm.decoded[b].block }

		# find registry dependencies between blocks
		deps = @dasm.cpu.decompile_func_finddeps(self, myblocks, func)

		scope = func.initializer = C::Block.new(@c_parser.toplevel)
		# di blocks => raw c statements, declare variables
		@dasm.cpu.decompile_blocks(self, myblocks, deps, func)

		# goto bla ; bla: goto blo => goto blo ;; goto bla ; bla: return => return
		simplify_goto(scope)

		namestackvars(scope)

		# use different C vars for any reg used in different domain (allows type to change over time)
		unalias_vars(scope)

		# infer variable types
		decompile_c_types(scope)

		# cleanup C
		optimize(scope)

		# make function prototype with local arg_XX
		args = func.type.args
		decl = []
		scope.statements.delete_if { |sm|
			next if not sm.kind_of? C::Declaration
			if sm.var.stackoff.to_i > 0
				args << sm.var
			else
				decl << sm
			end
			true
		}
		# reorder declarations
		scope.statements[0, 0] = decl.sort_by { |sm| [-sm.var.stackoff.to_i, sm.var.name] }

		# ensure arglist has no hole (create&add unreferenced args)
		func.type.args = []
		argoff = @c_parser.typesize[:ptr]
		args.sort_by { |sm| sm.stackoff.to_i }.each { |a|
			# XXX misalignment ?
			if not curoff = a.stackoff
				func.type.args << a	# __fastcall
				next
			end
			while curoff > argoff
				wantarg = C::Variable.new
				wantarg.name = stackoff_to_varname(argoff)
				wantarg.type = C::BaseType.new(:int)
				wantarg.attributes = ['unused']
				func.type.args << wantarg
				scope.symbol[wantarg.name] = wantarg
				argoff += @c_parser.typesize[:ptr]
			end
			func.type.args << a
			argoff += @c_parser.typesize[:ptr]
		}

		# change if() goto to if, if/else, while
		decompile_controlseq(scope)

		optimize_vars(scope)

		optimize_ctrl(scope)
		
		optimize_vars(scope)

		remove_unreferenced_vars(scope)

		simplify_varname_noalias(scope)

		@dasm.cpu.decompile_check_abi(self, entry, func)

		case ret = scope.statements.last
		when C::CExpression; puts "no return at end of func" if $VERBOSE
		when C::Return
			if not ret.value
				scope.statements.pop
			else
				v = ret.value
				v = v.rexpr if v.kind_of? C::CExpression and not v.op and (v.rexpr.kind_of? C::CExpression or v.rexpr.kind_of? C::Variable)
				func.type.type = v.type
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
				# TODO do not overlap other statics (but labels may refer to elements of the array...)
				data = (0..256).map {
					v = s[0].decode_imm("u#{tsz*8}".to_sym, @dasm.cpu.endianness)
					v = decompile_cexpr(v, @c_parser.toplevel) if v.kind_of? Expression	# relocation
					v
				}
				if (tsz == 1 or tsz == 2) and eos = data.index(0) and (0..3).all? { |i| data[i] >= 0x20 and data[i] < 0x7f }	# printable str
					# XXX 0x80 with ruby1.9...
					var.initializer = C::CExpression[data[0, eos].pack('C*'), C::Pointer.new(ptype)] rescue nil
				end
				var.initializer ||= data.map { |v| C::CExpression[v, C::BaseType.new(:int)] } unless (data - [0]).empty?
			end
		end

		# TODO patch existing references to addr ? (or would they have already triggered new_global_var?)

		# return the object to use to replace the raw addr
		var
	end

	# return an array of [address of block start, list of block to]]
	# decompile subfunctions
	def listblocks_func(entry)
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
			return expr if n == Expression::Unknown
			n = Expression[n].reduce_rec
			n = @dasm.prog_binding.index(n) || n
			n = $1 if n.kind_of? ::String and n =~ /^thunk_(.*)/
			n
		end
	end

	# patches instruction's backtrace_binding to replace things referring to a static stack offset from func start by :frameptr+off
	def makestackvars(funcstart, blocks)
		blockstart = nil
		cache_di = nil
		cache = {}	# [i_s, e, type] => backtrace
		tovar = lambda { |di, e, i_s|
			case e
			when Expression; Expression[tovar[di, e.lexpr, i_s], e.op, tovar[di, e.rexpr, i_s]].reduce
			when Indirection; Indirection[tovar[di, e.target, i_s], e.len]
			when :frameptr; e
			when ::Symbol
				cache.clear if cache_di != di ; cache_di = di
				vals = cache[[e, i_s, 0]] ||= @dasm.backtrace(e, di.address, :snapshot_addr => blockstart,
						:include_start => i_s, :no_check => true, :terminals => [:frameptr])
				# backtrace only to blockstart first
				if vals.length == 1 and ee = vals.first and ee.kind_of? Expression and (ee == Expression[:frameptr] or
						(ee.lexpr == :frameptr and ee.op == :+ and ee.rexpr.kind_of? ::Integer) or
						(not ee.lexpr and ee.op == :+ and ee.rexpr.kind_of? Indirection and eep = ee.rexpr.pointer and
						(eep == Expression[:frameptr] or (eep.lexpr == :frameptr and eep.op == :+ and eep.rexpr.kind_of? ::Integer))))
					ee
				else
				# fallback on full run (could restart from blockstart with ee, but may reevaluate addr_binding..
				vals = cache[[e, i_s, 1]] ||= @dasm.backtrace(e, di.address, :snapshot_addr => funcstart,
						:include_start => i_s, :no_check => true, :terminals => [:frameptr])
				if vals.length == 1 and ee = vals.first and (ee.reduce.kind_of? Integer or
						(ee.kind_of? Expression and (ee == Expression[:frameptr] or
						(ee.lexpr == :frameptr and ee.op == :+ and ee.rexpr.kind_of? ::Integer))))
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
	# TODO do not encode off in varname, use a hash in e.g. DecodedFunction (allows user-defined varnames & more robust)
	def stackoff_to_varname(off)
		if off >= @c_parser.typesize[:ptr]; 'arg_%X' % ( off-@c_parser.typesize[:ptr])	#  4 => arg_0,  8 => arg_4..
		elsif off > 0; 'arg_0%X' % off
		elsif off == 0; 'retaddr'
		elsif off <= -@dasm.cpu.size/8; 'var_%X' % (-off-@dasm.cpu.size/8)	# -4 => var_0, -8 => var_4..
		else 'var_0%X' % -off
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
				case e
				when ::String; s.storage = :static
				when ::Symbol; s.storage = :register
				else s.type.qualifier = [:volatile]
					puts "decompile_cexpr unhandled #{e.inspect}, using #{e.to_s.inspect}" if $VERBOSE
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
	def simplify_goto(scope)
		cntr = -1

		simpler_goto = lambda { |g|
			case ret = g
			when C::Goto
				# return a new goto
				walk(scope) { |s|
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

		walk(scope) { |s|
			case s
			when C::Block
				s.statements.each_with_index { |ss, i|
					s.statements[i] = simpler_goto[ss]
				}
			when C::If
				s.bthen = simpler_goto[s.bthen]
			end
		}

		remove_labels(scope)
	end

	# changes ifgoto, goto to while/ifelse..
	def decompile_controlseq(scope)
		scope.statements = decompile_cseq_if(scope.statements, scope)
		# TODO harmonize _if/_while
		decompile_cseq_while(scope.statements, scope)
		decompile_cseq_switch(scope)
	end

	# optimize if() { a; } to if() a;
	def optimize_ctrl(scope)
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

		remove_labels(scope)

		# while (1) { a; if(b) { c; return; }; d; }  =>  while (1) { a; if (b) break; d; } c;
		while st = scope.statements.last and st.kind_of? C::While and st.test.kind_of? C::CExpression and
				not st.test.op and st.test.rexpr == 1 and st.body.kind_of? C::Block
			break if not i = st.body.statements.find { |ist|
				ist.kind_of? C::If and not ist.belse and ist.bthen.kind_of? C::Block and ist.bthen.statements.last.kind_of? C::Return
			}
			walk(i.bthen.statements) { |sst| sst.outer = i.bthen.outer if sst.kind_of? C::Block and sst.outer == i.bthen }
			scope.statements.concat i.bthen.statements
			i.bthen = C::Break.new
		end

		walk(scope) { |ce|
			case ce
			when C::If
				if ce.bthen.kind_of? C::Block
 					case ce.bthen.statements.length
					when 1
						walk(ce.bthen.statements) { |sst| sst.outer = ce.bthen.outer if sst.kind_of? C::Block and sst.outer == ce.bthen }
						ce.bthen = ce.bthen.statements.first
					when 0
 						if not ce.belse and i = ce.bthen.outer.statements.index(ce)
							ce.bthen.outer.statements[i] = ce.test	# TODO remove sideeffectless parts
						end
					end
				end
				if ce.belse.kind_of? C::Block and ce.belse.statements.length == 1
					walk(ce.belse.statements) { |sst| sst.outer = ce.belse.outer if sst.kind_of? C::Block and sst.outer == ce.belse }
					ce.belse = ce.belse.statements.first
				end
			when C::While, C::DoWhile
				if ce.body.kind_of? C::Block
				       case ce.body.statements.length
				       when 1
					       walk(ce.body.statements) { |sst| sst.outer = ce.body.outer if sst.kind_of? C::Block and sst.outer == ce.body }
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
		walk(scope) { |ce|
			next if not ce.kind_of? C::Block
			st = ce.statements
			st.length.times { |n|
				while st[n].kind_of? C::If and st[n+1].kind_of? C::If and not st[n].belse and not st[n+1].belse and (
						(st[n].bthen.kind_of? C::Return and st[n+1].bthen.kind_of? C::Return and st[n].bthen.value == st[n+1].bthen.value) or
						(st[n].bthen.kind_of? C::Break and st[n+1].bthen.kind_of? C::Break) or
						(st[n].bthen.kind_of? C::Continue and st[n+1].bthen.kind_of? C::Continue))
					# if (a) return x; if (b) return x; => if (a || b) return x;
					st[n].test = C::CExpression[st[n].test, :'||', st[n+1].test]
					st.delete_at(n+1)
				end
			}
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
				s.bthen.statements = decompile_cseq_if(ary[0..ary.index(l)], s.bthen)
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

			# l1: l2: if () goto l1; goto l2;  =>  if(!) goto l2; goto l1;
			if s.kind_of? C::If
				ls = s.bthen
				ls = ls.statements.last if ls.kind_of? C::Block
				if ls.kind_of? C::Goto
					if li = inner_labels.index(ls.target)
						table = inner_labels
					else
						table = ary.map { |st| st.name if st.kind_of? C::Label }.compact.reverse
						li = table.index(ls.target) || table.length
					end
					g = ary.find { |ss|
						break if ss.kind_of? C::Return
						next if not ss.kind_of? C::Goto
						table.index(ss.target).to_i > li
					}
					if g
						s.test = C::CExpression.negate s.test
						if not s.bthen.kind_of? C::Block
							ls = C::Block.new(scope)
							ls.statements << s.bthen
							s.bthen = ls
						end
						ary[0..ary.index(g)], s.bthen.statements = s.bthen.statements, decompile_cseq_if(ary[0..ary.index(g)], scope)
					end
				end
			end

			ret << s
		end
		ret
	end

	def decompile_cseq_while(ary, scope)
		return if forbid_decompile_while

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

	# TODO
	def decompile_cseq_switch(scope)
		uncast = lambda { |e| e = e.rexpr while e.kind_of? C::CExpression and not e.op ; e }
		walk(scope) { |s|
			# XXX pfff...
			next if not s.kind_of? C::If
			# if (v < 12) return ((void(*)())(tableaddr+4*v))();
			t = s.bthen
			t = t.statements.first if t.kind_of? C::Block and t.statements.length == 1
			next if not t.kind_of? C::Return or not t.respond_to? :from_instr
			next if t.from_instr.comment.to_a.include? 'switch'
			next if not t.value.kind_of? C::CExpression or t.value.op != :funcall or t.value.rexpr != [] or not t.value.lexpr.kind_of? C::CExpression or t.value.lexpr.op
			p = uncast[t.value.lexpr.rexpr]
			next if not p.kind_of? C::CExpression or p.op != :* or p.lexpr
			p = uncast[p.rexpr]
			next if not p.kind_of? C::CExpression or p.op != :+
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

	# remove unused labels
	def remove_labels(scope)
		return if forbid_optimize_labels

		walk(scope) { |s|
			next if not s.kind_of? C::Block
			s.statements.delete_if { |l|
				if l.kind_of? C::Label
					notfound = true
					walk(scope) { |ss| notfound = false if ss.kind_of? C::Goto and ss.target == l.name}
				end
				notfound
			}
		}
		# remove implicit continue; at end of loop
		walk(scope) { |s|
			next if not s.kind_of? C::While
			if s.body.kind_of? C::Block and s.body.statements.last.kind_of? C::Continue
				s.body.statements.pop
			end
		}
	end

	# duplicate vars per domain value
	# eg  eax = 1; foo(eax); eax = 2; bar(eax);  =>  eax = 1; foo(eax) eax_1 = 2; bar(eax_1);
	#     eax = 1; if (bla) eax = 2; foo(eax);   =>  no change
	def unalias_vars(scope)
		g = c_to_graph(scope)

		isvar = lambda { |ce, var|
			if var.stackoff
				next unless ce.kind_of? C::CExpression and ce.op == :* and not ce.lexpr
				ce = ce.rexpr
				ce = ce.rexpr while ce.kind_of? C::CExpression and not ce.op
				next unless ce.kind_of? C::CExpression and ce.op == :& and not ce.lexpr
				ce = ce.rexpr
			end
			ce == var
		}

		ce_read = lambda { |ce_, var|
			isvar[ce_, var] or
			walk_ce(ce_) { |ce|
				case ce.op
				when :funcall; break true if isvar[ce.lexpr, var] or ce.rexpr.find { |a| isvar[a, var] }
				when :'='; break true if isvar[ce.rexpr, var]
				else break true if isvar[ce.lexpr, var] or isvar[ce.rexpr, var]
				end
			} or (var.stackoff and cnt = 0 and !walk_ce(ce_) { |ce|	# ptr to var
				cnt -= 1 if ce.op == :'=' and isvar[ce.lexpr, var]
				cnt += 1 if ce.lexpr == var
				cnt += 1 if ce.rexpr == var
			} and cnt > 0)
		}

		ce_write = lambda { |ce_, var|
			walk_ce(ce_) { |ce|
				if AssignOp.include? ce.op
					break true if isvar[ce.lexpr, var]
					break true if isvar[ce.rexpr, var] and (ce.op == :'++' or ce.op == :'--')
				end
			}
		}

		patch = lambda { |oldvar, occurences|
			next if occurences.empty?

			n_i = 0
			n_i += 1 while scope.symbol_ancestors[newvarname = "#{oldvar.name}_a#{n_i}"]

			nv = oldvar.dup
			nv.name = newvarname
			scope.statements << C::Declaration.new(nv)
			scope.symbol[nv.name] = nv

			occurences.each { |e|
				walk_ce(e) { |ce|
					case ce.op
					when :funcall
						ce.lexpr = nv if ce.lexpr == oldvar
						ce.rexpr.each_with_index { |a, i| ce.rexpr[i] = nv if a == oldvar }
					else
						ce.lexpr = nv if ce.lexpr == oldvar
						ce.rexpr = nv if ce.rexpr == oldvar
					end
				}
			}

		}

		# list of labels accessible from g.start without going through label
		badlab = {}
		badlabel = lambda { |label|
			if not badlab[label]
				badlab[label] = []
				todo = [g.start]
				while l = todo.pop
					next if l == label or badlab[label].include? l
					badlab[label] << l
					todo.concat g.to_optim[l].to_a
				end
			end
			badlab[label]
		}

		# reachable labels from a point in the graph
		can_reach = lambda { |start, want, forbid|
			todo = g.to_optim[start].to_a.dup
			done = []
			while l = todo.pop
				next if done.include? l
				done << l
				break true if want.include? l
				todo.concat g.to_optim[l].to_a if not forbid.include? l
			end
		}

		check_domain = lambda { |var, label, idx, badlabels|
			ce = g.exprs[label][idx]
			next if ce_read[ce, var]

			init_label = label
			readers = []
			writers = []
			occurences = [ce]	# list all appearances of var for this domain (to patch)
			idx += 1
			todo = [label]
			done = []
			postponed = []
			done_p = []
			while label = todo.pop or ppd = postponed.pop
				if label
					next if done.include? label
					done << label if idx == 0
				else
					next if done_p.include? ppd
					done_p << ppd
					label, idx = ppd
					next if not can_reach[label, readers, writers]
					# the written var belongs to the same domain (maybe not, but it's best to include too much than not enough)
					writers.delete label
					occurences << g.exprs[label][idx]
					idx += 1
				end
				case while ce = g.exprs[label].to_a[idx]
					if ce_read[ce, var]
						break :abort if badlabels.include? label	# not a domain
						occurences << ce
						readers << label
					elsif ce_write[ce, var]
						# eax=1; if() goto l1; eax=2; goto l2; l1: nop; l2: ebx=eax;
						# postpone this path until all readers are found, then check if it merges with one
						writers << label
						break :postpone
					end
					idx += 1
				end
				when :abort
					occurences.clear
					break
				when :postpone
					postponed << [label, idx]
				else
					todo.concat g.to_optim[label].to_a
				end
				idx = 0
			end

			patch[var, occurences]
		}

		walk = lambda { |var|
			done = []
			todo = [g.start]
			while label = todo.pop and not done.include? label
				done << label
				idx = 0
				while ce = g.exprs[label].to_a[idx]
					check_domain[var, label, idx, badlabel[label]] if ce_write[ce, var]
					idx += 1
				end
				todo.concat g.to_optim[label].to_a
			end
		}

		scope.symbol.dup.each_value { |var| walk[var] }
	end

	# revert the unaliasing namechange of vars where no alias subsists
	def simplify_varname_noalias(scope)
		names = scope.symbol.keys
		names.delete_if { |k|
			next if not b = k[/^(.*)_a\d+$/, 1]
			if not names.find { |n| n != k and (n == b or n[/^(.*)_a\d+$/, 1] == b) }
				scope.symbol[b] = scope.symbol.delete(k)
				scope.symbol[b].name = b
			end
		}
	end

	# patch scope to transform :frameoff-x into &var_x
	def namestackvars(scope)
		off2var = {}
		walk_ce(scope) { |e|
			next if e.op != :+ and e.op != :-
			next if not e.lexpr.kind_of? C::Variable or e.lexpr.name != 'frameptr'
			next if not e.rexpr.kind_of? C::CExpression or e.rexpr.op or not e.rexpr.rexpr.kind_of? ::Integer
			off = e.rexpr.rexpr
			off = -off if e.op == :-
			if not v = off2var[off]
				v = off2var[off] = C::Variable.new
				v.type = C::BaseType.new(:void)
				v.name = stackoff_to_varname(off)
				v.stackoff = off
				scope.symbol[v.name] = v
				scope.statements << C::Declaration.new(v)
			end
			e.replace C::CExpression[:&, v]
		}
	end

	# assign type to vars (regs, stack & global)
	# types are found by subfunction argument types & indirections, and propagated through assignments etc
	def decompile_c_types(scope)
		return if forbid_decompile_types

		# TODO allow user-predefined types (args/local vars) (XXX how does that mix with aliases ?)
		# TODO *(int8*)(ptr+8); *(int32*)(ptr+12) => automatic struct

		# name => type
		types = {}

		pscopevar = lambda { |e|
			e = e.rexpr while e.kind_of? C::CExpression and not e.op and e.rexpr.kind_of? C::CExpression
			if e.kind_of? C::CExpression and e.op == :& and not e.lexpr and e.rexpr.kind_of? C::Variable
				e.rexpr.name if scope.symbol[e.rexpr.name]
			end
		}
		scopevar = lambda { |e|
			if e.kind_of? C::Variable and scope.symbol[e.name]
				e.name
			elsif e.kind_of? C::CExpression and e.op == :* and not e.lexpr
				pscopevar[e.rexpr]
			end
		}
		globalvar = lambda { |e|
			e if e.kind_of? ::Integer and @dasm.get_section_at(e)
		}
		update_global_type = lambda { |e, t|
			# TODO check for better_type (&rename?)
			if ne = new_global_var(e, t)
				walk_ce(scope) { |ce|
					ce.lexpr = ne if ce.lexpr == e
					ce.rexpr = ne if ce.rexpr == e
					if ce.lexpr == ne or ce.rexpr == ne
						# set ce type according to l/r
						# TODO set ce.parent type etc
						ce.type = C::CExpression[ce.lexpr, ce.op, ce.rexpr].type
					end
				}
			end
		}

		propagate_type = nil	# fwd declaration
		propagating = []	# recursion guard (x = &x)

		# check if a newly found type for o is better than current type
		# order: foo* > void* > foo
		# propagate_type if type is updated
		better_type = lambda { |t0, t1|
			t1 == C::BaseType.new(:void) or (t0.pointer? and t1.kind_of? C::BaseType) or t0.untypedef.kind_of? C::Union or
			(t0.kind_of? C::BaseType and t1.kind_of? C::BaseType and (@c_parser.typesize[t0.name] > @c_parser.typesize[t1.name] or (t0.name == t1.name and t0.qualifier))) or
			(t0.pointer? and t1.pointer? and better_type[t0.untypedef.type, t1.untypedef.type])
		}
		update_type = lambda { |n, t|
			next if propagating.include? n
			o = scope.symbol[n].stackoff
			next if t0 = types[n] and not better_type[t, t0]
			next if o and (t.integral? or t.pointer?) and o % @c_parser.sizeof(nil, t) != 0 # keep vars aligned
			types[n] = t
			next if t == t0
			propagating << n
			propagate_type[n, t]
			propagating.delete n
			next if not o
			t = t.untypedef
			if t.kind_of? C::Struct
				t.members.each { |m|
					mo = t.offsetof(@c_parser, m.name)
					next if mo == 0
					scope.symbol.each { |vn, vv|
						update_type[vn, m.type] if vv.stackoff == o+mo
					}
				}
			end
		}

		# try to update the type of a var from knowing the type of an expr (through dereferences etc)
		known_type = lambda { |e, t|
			loop do
				e = e.rexpr while e.kind_of? C::CExpression and not e.op
				if o = scopevar[e]
					update_type[o, t]
				elsif o = globalvar[e]
					update_global_type[o, t]
				elsif not e.kind_of? C::CExpression
				elsif o = pscopevar[e] and t.pointer?
					update_type[o, t.untypedef.type]
				elsif e.op == :* and not e.lexpr
					e = e.rexpr
					t = C::Pointer.new(t)
					next
				elsif e.op == :+ and e.lexpr and e.rexpr.kind_of? C::CExpression
					if not e.rexpr.op and e.rexpr.rexpr.kind_of? ::Integer
						if e.rexpr.rexpr < 0x1000	# XXX relocatable + base=0..
							e = e.lexpr	# (int)*(x+2) === (int) *x
							next
						elsif globalvar[e.rexpr.rexpr]
							known_type[e.lexpr, C::BaseType.new(:int)]
							e = e.rexpr
							next
						end
					elsif t.pointer? and e.lexpr.kind_of? C::CExpression
						if (e.lexpr.lexpr and [:<<, :>>, :*, :&].include? e.lexpr.op) or
								(o = scopevar[e.lexpr] and types[o] and types[o].integral? and
								 !(o = scopevar[e.rexpr] and types[o] and types[o].integral?))
							e.lexpr, e.rexpr = e.rexpr, e.lexpr
							e = e.lexpr
							next
						elsif o = scopevar[e.rexpr] and types[o] and types[o].integral? and
								!(o = scopevar[e.lexpr] and types[o] and types[o].integral?)
							e = e.lexpr
							next
						end
					end
				end
				break
			end
		}

		# we found a type for a var, propagate it through affectations
		propagate_type = lambda { |var, type|
			walk_ce(scope) { |ce|
				# char x; x & 255 => uchar x
				if ce.op == :'&' and ce.lexpr and ce.lexpr.type.integral? and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr == (1 << (8*@c_parser.sizeof(ce.lexpr))) - 1
					known_type[ce.lexpr, C::BaseType.new(ce.lexpr.type.name, :unsigned)]
				end

				next if ce.op != :'='

				# int **x; y = **x  =>  int y
				t = type
				l = ce.lexpr
				while l.kind_of? C::CExpression and l.op == :* and not l.lexpr
					if var == pscopevar[l.rexpr]
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
					if var == pscopevar[r.rexpr]
						known_type[ce.lexpr, t]
						break
					elsif t.pointer?
						r = r.rexpr
						t = t.untypedef.type
					else break
					end
				end

				# TODO int *x; *x = *y; ?
			}
		}

		# put all those macros in use
		walk_ce(scope) { |ce|
			if ce.op == :'=' and ce.rexpr.kind_of? C::CExpression and ce.rexpr.op == nil and ce.rexpr.rexpr.kind_of? ::Integer and ce.rexpr.rexpr.abs < 0x10000 and (not ce.lexpr.kind_of? C::CExpression or ce.lexpr.op != :'*' or ce.lexpr.lexpr)
				# var = int
				known_type[ce.lexpr, ce.rexpr.type]
			elsif ce.op == :funcall and ce.lexpr.type.kind_of? C::Function
				# cast func args to arg prototypes
				ce.lexpr.type.args.to_a.zip(ce.rexpr).each { |proto, arg| known_type[arg, proto.type] }
			elsif ce.op == :* and not ce.lexpr
				known_type[ce.rexpr, C::Pointer.new(ce.type)]
			end
		}

		# offsets have types now
		types.each { |v, t|
			# keep var type qualifiers
			q = scope.symbol[v].type.qualifier
			scope.symbol[v].type = t
			t.qualifier = q if q
		}


		# remove offsets to struct members
		# XXX this defeats antialiasing
		# off => [structoff, membername, membertype]
		memb = {}
		types.dup.each { |n, t|
			v = scope.symbol[n]
			next if not o = v.stackoff
			t = t.untypedef
			if t.kind_of? C::Struct
				t.members.each { |tm|
					moff = t.offsetof(@c_parser, tm.name)
					next if moff == 0
					types.delete_if { |vv, tt| scope.symbol[vv].stackoff == o+moff }
					memb[o+moff] = [v, tm.name, tm.type]
				}
			end
		}

		# patch local variables into the CExprs, incl unknown offsets
		varat = lambda { |n|
			v = scope.symbol[n]
			if s = memb[v.stackoff]
				v = C::CExpression[s[0], :'.', s[1], s[2]]
			else
				v.type = types[n] || C::BaseType.new(:int)
			end
			v
		}

		maycast = lambda { |v, e|
			if @c_parser.sizeof(v) != @c_parser.sizeof(e)
				v = C::CExpression[:*, [[:&, v], C::Pointer.new(e.type)]]
			end
			v
		}
		maycast_p = lambda { |v, e|
			if not e.type.pointer? or @c_parser.sizeof(v) != @c_parser.sizeof(nil, e.type.untypedef.type)
				C::CExpression[[:&, v], e.type]
			else
				C::CExpression[:&, v]
			end
		}

		walk_ce(scope) { |ce|
			case
			when ce.op == :funcall
				ce.rexpr.map! { |re|
					if o = scopevar[re]; C::CExpression[maycast[varat[o], re]]
					elsif o = pscopevar[re]; C::CExpression[maycast_p[varat[o], re]]
					else re
					end
				}
			when o = scopevar[ce.lexpr]; ce.lexpr = maycast[varat[o], ce.lexpr]
			when o = scopevar[ce.rexpr]; ce.rexpr = maycast[varat[o], ce.rexpr]
			when o = pscopevar[ce.lexpr]; ce.lexpr = maycast_p[varat[o], ce.lexpr]
			when o = pscopevar[ce.rexpr]; ce.rexpr = maycast_p[varat[o], ce.rexpr]
			when o = scopevar[ce]; ce.replace C::CExpression[maycast[varat[o], ce]]
			when o = pscopevar[ce]; ce.replace C::CExpression[maycast_p[varat[o], ce]]
			end
		}

		fix_type_overlap(scope)
		fix_pointer_arithmetic(scope)

		# if int32 var_4 is always var_4 & 255, change type to int8
		varuse = Hash.new(0)
		varandff = Hash.new(0)
		varandffff = Hash.new(0)
		walk_ce(scope) { |ce|
			if ce.op == :& and ce.lexpr.kind_of? C::Variable and ce.lexpr.type.integral? and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr.kind_of? ::Integer
				case ce.rexpr.rexpr
				when 0xff; varandff[ce.lexpr.name] += 1
				when 0xffff; varandffff[ce.lexpr.name] += 1
				end
			end
			varuse[ce.lexpr.name] += 1 if ce.lexpr.kind_of? C::Variable
			varuse[ce.rexpr.name] += 1 if ce.rexpr.kind_of? C::Variable
		}
		varandff.each { |k, v|
			scope.symbol[k].type = C::BaseType.new(:__int8, :unsigned) if varuse[k] == v
		}
		varandffff.each { |k, v|
			scope.symbol[k].type = C::BaseType.new(:__int16, :unsigned) if varuse[k] == v
		}

		# propagate types to cexprs
		walk_ce(scope, true) { |ce|
			if ce.op
				ce.type = C::CExpression[ce.lexpr, ce.op, ce.rexpr].type
				if ce.op == :'=' and ce.rexpr.type != ce.type and (not ce.rexpr.type.integral? or not ce.type.integral?)
					ce.rexpr = C::CExpression[ce.rexpr, ce.type]
				end
			end
		}
	end

	# fix pointer arithmetic (eg int foo += 4  =>  int* foo += 1)
	# use struct member access (eg *(structptr+8)  =>  structptr->bla)
	# must be run only once, right after type setting
	def fix_pointer_arithmetic(scope)
		# struct foo { int i; int j; struct { int k; int l; } m; };     bla+12 => &bla->m.l
		# st is a struct, ptr is an expr pointing to a struct, off is a numeric offset from ptr
		# TODO unions
		structoffset = lambda { |st, ptr, off|
			tabidx = off / @c_parser.sizeof(nil, st)
			off -= tabidx * @c_parser.sizeof(nil, st)

			suboff = 0
			submemb = lambda { |sm| sm.name ? sm : sm.kind_of?(C::Union) ? sm.members.map { |ssm| submemb[ssm] } : [] }
			mbs = st.members.map { |m| submemb[m] }.flatten 
			if not sm = mbs.find { |m|
				mo = st.offsetof(@c_parser, m.name)
				suboff = off - mo
				true if mo <= off and mo+@c_parser.sizeof(m) > off
			}
				# not in a member, just derivate from the struct ptr
				ptr = C::CExpression[:&, [ptr, :'[]', [tabidx]]] if tabidx != 0
				C::CExpression[[[ptr], C::Pointer.new(C::BaseType.new(:__int8))], :+, [off]]
				#C::CExpression[[[ptr], C::Pointer.new(C::BaseType.new(:__int8))], :+, off + tabidx * @c_parser.sizeof(nil, st)]
			else
				if tabidx != 0
					ptr = C::CExpression[[ptr, :'[]', [tabidx]], :'.', sm.name]
				else
					ptr = C::CExpression[ptr, :'->', sm.name]
				end
				ptr = C::CExpression[ptr, :'[]', [0]] if ptr.type.untypedef.kind_of? C::Array	# foo.bar[0].baz better than foo.bar->baz
				ptr = C::CExpression[:&, ptr]
				if suboff != 0
					st = sm.type.untypedef
					if st.pointer? and st.type.untypedef.kind_of? C::Struct
						ptr = structoffset[st.type.untypedef, ptr, suboff]
					else
						ptr = C::CExpression[[ptr, C::Pointer.new(C::BaseType.new(:__int8))], :+, [suboff]]
					end
				end
				ptr
			end
		}

		walk_ce(scope, true) { |ce|
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

			if ce.op == :& and not ce.lexpr and ce.rexpr.kind_of? C::CExpression and ce.rexpr.op == :* and not ce.rexpr.lexpr
				ce.replace C::CExpression[ce.rexpr.rexpr]
			end

			next if not ce.lexpr or not ce.lexpr.type.pointer?
			if ce.op == :+ and (s = ce.lexpr.type.untypedef.type.untypedef).kind_of? C::Struct and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and
					ce.rexpr.rexpr.kind_of? ::Integer and o = ce.rexpr.rexpr and x = structoffset[s, ce.lexpr, o]
				# structptr + 4 => &structptr->member
				ce.replace x
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
					p = C::CExpression[[ce.lexpr], C::Pointer.new(C::BaseType.new(:__int8))]
					ce.replace C::CExpression[[p, ce.op, ce.rexpr, p.type], ptype]
				end
			end
		}
	end

	# handling of var overlapping (eg __int32 var_10; __int8 var_F  =>  replace all var_F by *(&var_10 + 1))
	# must be done before fix_pointer_arithmetic
	def fix_type_overlap(scope)
		varinfo = {}
		scope.symbol.each_value { |var|
			next if not off = var.stackoff
			len = @c_parser.sizeof(var)
			varinfo[var] = [off, len]
		}

		varinfo.each { |v1, (o1, l1)|
			next if not v1.type.integral?
			varinfo.each { |v2, (o2, l2)|
				# XXX o1 may overlap o2 AND another (int32 v_10; int32 v_E; int32 v_C;)
				# TODO should check stuff with aliasing domains
				next if v1.name == v2.name or o1 >= o2+l2 or o1+l1 <= o2 or l1 > l2 or (l2 == l1 and o2 >= o1)
				# v1 => *(&v2+delta)
				p = C::CExpression[:&, v2]
				p = C::CExpression[p, :+,  [o1-o2]]
				p = C::CExpression[p, C::Pointer.new(v1.type)] if v1.type != p.type.type
				p = C::CExpression[:*, p]
				walk_ce(scope) { |ce|
					ce.lexpr = p if ce.lexpr == v1
					ce.rexpr = p if ce.rexpr == v1
				}
			}
		
		}
	end

	# to be run with scope = function body with only CExpr/Decl/Label/Goto/IfGoto/Return, with correct variables types
	# will transform += 1 to ++, inline them to prev/next statement ('++x; if (x)..' => 'if (++x)..')
 	# remove useless variables ('int i;', i never used or 'i = 1; j = i;', i never read after => 'j = 1;')
	# remove useless casts ('(int)i' with 'int i;' => 'i')
	def optimize(scope)
		optimize_code(scope)
		optimize_vars(scope)
		optimize_vars(scope)	# 1st run may transform i = i+1 into i++ which second run may coalesce into if(i)
	end

	# simplify cexpressions (char & 255, redundant casts, etc)
	def optimize_code(scope)
		return if forbid_optimize_code

		sametype = lambda { |t1, t2|
			t1 = t1.untypedef
			t2 = t2.untypedef
			t1 == t2 or
			(t1.kind_of? C::BaseType and t1.integral? and t2.kind_of? C::BaseType and t2.integral? and @c_parser.sizeof(nil, t1) == @c_parser.sizeof(nil, t2)) or
			(t1.pointer? and t2.pointer? and sametype[t1.type, t2.type])
		}

		# most of this is a CExpr#reduce
		future_array = []
		walk_ce(scope, true) { |ce|
			# *&bla => bla if types ok
			if ce.op == :* and not ce.lexpr and ce.rexpr.kind_of? C::CExpression and ce.rexpr.op == :& and not ce.rexpr.lexpr and sametype[ce.rexpr.type.untypedef.type, ce.rexpr.rexpr.type]
				ce.replace C::CExpression[ce.rexpr.rexpr]
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
				ce.replace C::CExpression[ce.lexpr]
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

			# (1stmember*)structptr => &structptr->1stmember	TODO anonymous substruct..
			if not ce.op and ce.type.pointer? and ce.rexpr.type.pointer? and (s = ce.rexpr.type.untypedef.type.untypedef).kind_of? C::Struct and
					m = s.members.first and m.name and sametype[ce.type.untypedef.type, m.type]
				if ce.rexpr.kind_of? C::CExpression and ((ce.rexpr.op == :'.' and s = ce.rexpr.lexpr.type) or (ce.rexpr.op == :'->' and
							s = ce.rexpr.lexpr.type.untypedef.type)) and s.members.find { |om| om.name == ce.rexpr.rexpr and om.type.kind_of? C::Array }
					# ary->bla => ary[0].bla
					ce.replace C::CExpression[:&, [[ce.rexpr, :'[]', [0]], :'.', m.name]]
				else
					ce.replace C::CExpression[:&, [ce.rexpr, :'->', m.name]]
				end
			end

			# (&foo)->bar => foo.bar
			if ce.op == :'->' and ce.lexpr.kind_of? C::CExpression and ce.lexpr.op == :& and not ce.lexpr.lexpr
				ce.lexpr = ce.lexpr.rexpr
				ce.op = :'.'
			end
		}

		# if there is a ptr[4], change all *ptr to ptr[0] for consistency
		# do this after the first pass, which may change &*ptr to ptr
		walk_ce(scope) { |ce|
			if ce.op == :* and not ce.lexpr and ce.rexpr.kind_of? C::Variable and future_array.include? ce.rexpr.name
				ce.lexpr, ce.op, ce.rexpr = ce.rexpr, :'[]', C::CExpression[0]
			end
		} if not future_array.empty?

		# if (x != 0) => if (x)
		walk(scope) { |st|
			if st.kind_of? C::If and st.test.kind_of? C::CExpression and st.test.op == :'!=' and
					st.test.rexpr.kind_of? C::CExpression and not st.test.rexpr.op and st.test.rexpr.rexpr == 0
				st.test = C::CExpression[st.test.lexpr]
			end
		}
	end

	# checks if an expr has sideeffects (funcall, var assignment, mem dereference, use var out of scope if specified)
	def sideeffect(exp, scope=nil)
		case exp
		when nil, ::Numeric, ::String; false
		when ::Array; exp.any? { |_e| sideeffect _e, scope }
		when C::Variable; (scope and not scope.symbol[exp.name]) or exp.type.qualifier.to_a.include? :volatile
		when C::CExpression; (exp.op == :* and not exp.lexpr) or exp.op == :funcall or AssignOp.include?(exp.op) or
		       		sideeffect(exp.lexpr, scope) or sideeffect(exp.rexpr, scope)
		else true	# failsafe
		end
	end

	# converts C code to a graph of cexprs (nodes = cexprs, edges = codepaths)
	# returns a CGraph
	class CGraph
		# exprs: label => [exprs], to: label => [labels], block: label => are exprs standalone (vs If#test), start: 1st label
		attr_accessor :exprs, :to, :block, :start, :to_optim, :from_optim
	end
	def c_to_graph(st)
		g = CGraph.new
		g.exprs = {}	# label => [exprs]
		g.to = {}	# label => [labels]
		g.block = {}	# label => is label in a block? (vs If#test)
		anon_label = 0	# when no label is there, use anon_label++
		# converts C code to a graph of codepath of cexprs
		to_graph = lambda { |stmt, l_cur, l_after, l_cont, l_break|
			case stmt
			when C::Label; g.to[l_cur] = [stmt.name] ; g.to[stmt.name] = [l_after]
			when C::Goto; g.to[l_cur] = [stmt.target]
			when C::Continue; g.to[l_cur] = [l_cont]
			when C::Break; g.to[l_cur] = [l_break]
			when C::CExpression
				g.exprs[l_cur] = [stmt]
				g.to[l_cur] = [l_after]
			when C::Return
				g.exprs[l_cur] = [stmt.value] if stmt.value
				g.to[l_cur] = []
			when C::Block
				to_graph[stmt.statements, l_cur, l_after, l_cont, l_break]
			when ::Array
				g.exprs[l_cur] = []
				g.block[l_cur] = true
				stmt.each_with_index { |s, i|
					case s
					when C::Declaration
					when C::CExpression
						g.exprs[l_cur] << s
					else
						l = anon_label += 1
						ll = anon_label += 1
						g.to[l_cur] = [l]
						g.block[l_cur] = true
						to_graph[stmt[i], l, ll, l_cont, l_break]
						l_cur = ll
						g.exprs[l_cur] = []
					end
				}
				g.to[l_cur] = [l_after].compact
			when C::If
				g.exprs[l_cur] = [stmt.test]
				lt = anon_label += 1
				to_graph[stmt.bthen, lt, l_after, l_cont, l_break]
				le = anon_label += 1
				to_graph[stmt.belse, le, l_after, l_cont, l_break]
				g.to[l_cur] = [lt, le]
			when C::While, C::DoWhile
				la = anon_label += 1
				if stmt.kind_of? C::DoWhile
					lt, lb = la, l_cur
				else
					lt, lb = l_cur, la
				end
				g.exprs[lt] = [stmt.test]
				g.to[lt] = [lb, l_after]
				to_graph[stmt.body, lb, lt, lt, l_after]
			when C::Asm, nil; g.to[l_cur] = [l_after]
			else puts "to_graph unhandled #{stmt.class}: #{stmt}" if $VERBOSE
			end
		}

		g.start = anon_label
		to_graph[st, g.start, nil, nil, nil]

		# optimize graph
		g.to_optim = {}
		g.to.each { |k, v| g.to_optim[k] = v.uniq }
		g.exprs.delete_if { |k, v| v == [] }
		g.to_optim.delete_if { |k, v|
			if v.length == 1 and not g.exprs[k] and v != [k]
				g.to_optim.each_value { |t| if i = t.index(k) ; t[i] = v.first ; end }
				true
			elsif v.length == 0 and not g.exprs[k]
				g.to_optim.each_value { |t| t.delete k }
				true
			end
		}

		g.from_optim = {}
		g.to_optim.each { |k, v| v.each { |t| (g.from_optim[t] ||= []) << k } }

		g
	end

	# dataflow optimization
	# condenses expressions (++x; if (x)  =>  if (++x))
	# remove local var assignment (x = 1; f(x); x = 2; g(x);  =>  f(1); g(2); etc)
	def optimize_vars(scope)
		return if forbid_optimize_dataflow

		g = c_to_graph(scope)

		# walks a cexpr in evaluation order (not strictly, but this is not strictly defined anyway..)
		# returns the first subexpr to read var in ce
		# returns :write if var is rewritten
		# returns nil if var not read
		# may return a cexpr var += 2
		find_next_read_ce = lambda { |ce_, var|
			walk_ce(ce_, true) { |ce|
				case ce.op
				when :funcall
					break ce if ce.lexpr == var or ce.rexpr.find { |a| a == var }
				when :'='
					# a=a  /  a=a+1  => yield a, not :write
					break ce if ce.rexpr == var
					break :write if ce.lexpr == var
				else
					break ce if ce.lexpr == var or ce.rexpr == var
				end
			}
		}

		# badlabels is a list of labels that may be reached without passing through the first invocation block
		find_next_read_rec = lambda { |label, idx, var, done, badlabels|
			next if done.include? label
			done << label if idx == 0

			idx += 1 while ce = g.exprs[label].to_a[idx] and not ret = find_next_read_ce[ce, var]
			next ret if ret

			to = g.to_optim[label].to_a.map { |t|
				break [:split] if badlabels.include? t
				find_next_read_rec[t, 0, var, done, badlabels]
			}.compact

			tw = to - [:write]
 			if to.include? :split or tw.length > 1
				:split
			elsif tw.length == 1
				tw.first
			elsif to.include? :write
				:write
			end
		}
		# return the previous subexpr reading var with no fwd path to another reading (otherwise split), see loop comment for reason
		find_next_read = nil
		find_prev_read_rec = lambda { |label, idx, var, done|
			next if done.include? label
			done << label if idx == g.exprs[label].length-1

			idx -= 1 while idx >= 0 and ce = g.exprs[label].to_a[idx] and not ret = find_next_read_ce[ce, var]
			if ret.kind_of? C::CExpression
				fwchk = find_next_read[label, idx+1, var]
				ret = fwchk if not fwchk.kind_of? C::CExpression
			end
			next ret if ret

			from = g.from_optim[label].to_a.map { |f|
				find_prev_read_rec[f, g.exprs[f].to_a.length-1, var, done]
			}.compact

			next :split if from.include? :split
			fw = from - [:write]
			if fw.length == 1
				fw.first
			elsif fw.length > 1
				:split
			elsif from.include? :write
				:write
			end
		}

		# list of labels reachable without using a label
		badlab = {}
		build_badlabel = lambda { |label|
			next if badlab[label]
			badlab[label] = []
			todo = [g.start]
			while l = todo.pop
				next if l == label or badlab[label].include? l
				badlab[label] << l
				todo.concat g.to_optim[l].to_a
			end
		}

		# returns the next subexpr where var is read
		# returns :write if var is written before being read
		# returns :split if the codepath splits with both subpath reading or codepath merges with another
		# returns nil if var is never read
		# idx is the index of the first cexpr at g.exprs[label] to look at
		find_next_read = lambda { |label, idx, var|
			find_next_read_rec[label, idx, var, [], []]
		}
		find_prev_read = lambda { |label, idx, var|
			find_prev_read_rec[label, idx, var, []]
		}
		# same as find_next_read, but returns :split if there exist a path from g.start to the read without passing through label
		find_next_read_bl = lambda { |label, idx, var|
			build_badlabel[label]
			find_next_read_rec[label, idx, var, [], badlab[label]]
		}

		# walk each node, optimize data accesses there
		# replace no more useful exprs by CExpr[nil, nil, nil], those are wiped later.
		g.exprs.each { |label, exprs|
			next if not g.block[label]
			i = 0
			while i < exprs.length
				e = exprs[i]
				i += 1

				# TODO x = x + 1  =>  x += 1  =>  ++x	here, move all other optimizations after (in optim_code)
				# needs also int & 0xffffffff -> int, *&var  etc (decomp_type? optim_type?)
				if (e.op == :'++' or e.op == :'--') and v = (e.lexpr || e.rexpr) and v.kind_of? C::Variable and
						scope.symbol[v.name] and not v.type.qualifier.to_a.include? :volatile
					next if !(pos = :post and oe = find_next_read_bl[label, i, v] and oe.kind_of? C::CExpression) and
				   		!(pos = :prev and oe = find_prev_read[label, i-2, v] and oe.kind_of? C::CExpression)

					# merge pre/postincrement into next/prev var usage
					# find_prev_read must fwd check when it finds something, to avoid
					#  while(x) x++; return x; to be converted to while(x++); return x;  (return wrong value)
					case oe.op
					when e.op
						# bla(i--); --i   bla(--i); --i   ++i; bla(i++)  =>  ignore
						next if pos == :pre or oe.lexpr
						# ++i; bla(++i)  =>  bla(i += 2)
						oe.lexpr = oe.rexpr
						oe.op = ((oe.op == :'++') ? :'+=' : :'-=')
						oe.rexpr = C::CExpression[2]

					when :'++', :'--'	# opposite of e.op
						if (pos == :post and not oe.lexpr) or (pos == :pre and not oe.rexpr)
							# ++i; bla(--i)  =>  bla(i)
							# bla(i--); ++i  =>  bla(i)
							oe.op = nil
						elsif pos == :post
							# ++i; bla(i--)  =>  bla(i+1)
							oe.op = ((oe.op == :'++') ? :- : :+)
							oe.rexpr = C::CExpression[1]
						elsif pos == :pre
							# bla(--i); ++i  =>  bla(i-1)
							oe.lexpr = oe.rexpr
							oe.op = ((oe.op == :'++') ? :+ : :-)
							oe.rexpr = C::CExpression[1]
						end
					when :'+=', :'-='
						# TODO i++; i += 4  =>  i += 5
						next
					when *AssignOp
						next	# ++i; i |= 4  =>  ignore
					else
						if    pos == :post and v == oe.lexpr; oe.lexpr = C::CExpression[e.op, v]
						elsif pos == :post and v == oe.rexpr; oe.rexpr = C::CExpression[e.op, v]
						elsif pos == :prev and v == oe.rexpr; oe.rexpr = C::CExpression[v, e.op]
						elsif pos == :prev and v == oe.lexpr; oe.lexpr = C::CExpression[v, e.op]
						else raise 'foobar'	# find_dir_read failed
						end
					end

					i -= 1
					exprs.delete_at(i)
					e.lexpr = e.op = e.rexpr = nil


				elsif e.op == :'=' and v = e.lexpr and v.kind_of? C::Variable and scope.symbol[v.name] and
						not v.type.qualifier.to_a.include? :volatile and not find_next_read_ce[e.rexpr, v]

					case nr = find_next_read[label, i, v]
					when C::CExpression
						# read in one place only, try to patch rexpr in there
						r = e.rexpr

						# must check for conflicts (x = y; y += 1; foo(x)  =!>  foo(y))
						# XXX x = a[1]; *(a+1) = 28; foo(x)...
						isfunc = false
						depend_vars = []
						walk_ce(C::CExpression[r]) { |ce|
							isfunc = true if ce.op == :func and (not ce.lexpr.kind_of? C::Variable or
									not ce.lexpr.has_attribute('pure'))	# XXX is there a C attr for func depending only on staticvars+param ?
							depend_vars << ce.lexpr if ce.lexpr.kind_of? C::Variable
							depend_vars << ce.rexpr if ce.rexpr.kind_of? C::Variable
							depend_vars << ce if ce.lvalue?
							depend_vars.concat(ce.rexpr.grep(C::Variable)) if ce.rexpr.kind_of? ::Array
						}
						depend_vars.uniq!

						# XXX x = 1; if () { x = 2; } foo(x)  =!>  foo(1)  (find_next_read will return this)
						#     we'll just redo a find_next_read like
						# XXX b = &a; a = 1; *b = 2; foo(a)  unhandled & generate bad C
						l_l = label
						l_i = i
						while g.exprs[l_l].to_a.each_with_index { |ce_, n_i|
							next if n_i < l_i
							# count occurences of read v in ce_
							cnt = 0
							bad = false
							walk_ce(ce_) { |ce|
								case ce.op
								when :funcall
									bad = true if isfunc
									ce.rexpr.each { |a| cnt += 1 if a == v }
									cnt += 1 if ce.lexpr == v
								when :'='
									bad = true if depend_vars.include? ce.lexpr
									cnt += 1 if ce.rexpr == v
								else
									bad = true if (ce.op == :'++' or ce.op == :'--') and depend_vars.include? ce.rexpr
									bad = true if AssignOp.include? ce.op and depend_vars.include? ce.lexpr
									cnt += 1 if ce.lexpr == v
									cnt += 1 if ce.rexpr == v
								end
							}
							case cnt
							when 0
 								break if bad
								next
							when 1	# good
								break if e.complexity > 10 and ce_.complexity > 3	# try to keep the C readable
								# x = 1; y = x; z = x;  =>  cannot suppress x
								nr = find_next_read[l_l, n_i+1, v]
								break if (nr.kind_of? C::CExpression or nr == :split) and not walk_ce(ce_) { |ce| break true if ce.op == :'=' and ce.lexpr == v }
							else break	# a = 1; b = a + a  => fail
							end

							# TODO XXX x = 1; y = x; z = x;
							res = walk_ce(ce_, true) { |ce|
								case ce.op
								when :funcall
									if ce.rexpr.to_a.each_with_index { |a,i_|
										next if a != v
										ce.rexpr[i_] = r
										break :done
									} == :done
										break :done
									elsif ce.lexpr == v
										ce.lexpr = r
										break :done
									elsif isfunc
										break :fail
									end
								when *AssignOp
									break :fail if not ce.lexpr and depend_vars.include? ce.rexpr	# ++depend
									if ce.rexpr == v
										ce.rexpr = r
										break :done
									elsif ce.lexpr == v or depend_vars.include? ce.lexpr
										break :fail
									end
								else
									break :fail if ce.op == :& and not ce.lexpr and ce.rexpr == v
									if ce.lexpr == v
										ce.lexpr = r
										break :done
									elsif ce.rexpr == v
										ce_.type = r.type if not ce_.op and ce_.rexpr == v	# return (int32)eax
										ce.rexpr = r
										break :done
									end
								end
							}
							case res
							when :done
								i -= 1
								exprs.delete_at(i)
								e.lexpr = e.op = e.rexpr = nil
								break
							when :fail
								break
							end
						}
							# ignore branches that will never reuse v
							may_to = g.to_optim[l_l].find_all { |to| find_next_read[to, 0, v].kind_of? C::CExpression }
							if may_to.length == 1 and to = may_to.first and to != l_l and g.from_optim[to] == [l_l]
								l_i = 0
								l_l = to
							else break
							end
						end

					when nil, :write
						# useless assignment (value never read later)
						# XXX foo = &bar; bar = 12; baz(*foo)
						e.replace(C::CExpression[e.rexpr])
						# remove sideeffectless subexprs
						loop do
							case e.op
							when :funcall, *AssignOp
							else
								l = (e.lexpr.kind_of? C::CExpression and sideeffect(e.lexpr))
								r = (e.rexpr.kind_of? C::CExpression and sideeffect(e.rexpr))
								if l and r	# could split...
								elsif l
									e.replace(e.lexpr)
									next
								elsif r
									e.replace(e.rexpr)
									next
								else # remove the assignment altogether
									i -= 1
									exprs.delete_at(i)
									e.lexpr = e.op = e.rexpr = nil
								end
							end
							break
						end
					end
				end
			end
		}

		# wipe cexprs marked in the previous step
		walk(scope) { |st|
			next if not st.kind_of? C::Block
			st.statements.delete_if { |e| e.kind_of? C::CExpression and not e.lexpr and not e.op and not e.rexpr }
		}

		# reoptimize cexprs
		walk_ce(scope, true) { |ce|
			# redo some simplification that may become available after variable propagation
			# int8 & 255  =>  int8
			if ce.op == :& and ce.lexpr and ce.lexpr.type.integral? and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr == (1 << (8*@c_parser.sizeof(ce.lexpr))) - 1
				ce.replace C::CExpression[ce.lexpr]
			end

			# useless casts
			if not ce.op and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and (ce.rexpr.rexpr.kind_of? C::CExpression or
					(ce.type.pointer? and ce.rexpr.rexpr == 0))
				ce.rexpr = ce.rexpr.rexpr
			end
			if not ce.op and ce.rexpr.kind_of? C::CExpression and (ce.type == ce.rexpr.type or (ce.type.integral? and ce.rexpr.type.integral?))
				ce.replace ce.rexpr
			end
			# conditions often are x & 0xffffff which may cast pointers to ints, remove those casts
			if ce.op == :== and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr == 0
				ce.replace C::CExpression[:'!', ce.lexpr]
			end
			if ce.op == :'!' and ce.rexpr.kind_of? C::CExpression and not ce.rexpr.op and ce.rexpr.rexpr.kind_of? C::CExpression
				ce.rexpr = ce.rexpr.rexpr
			end
			if [:<, :<=, :>, :>=].include? ce.op and ce.rexpr.kind_of? C::CExpression and ce.lexpr.kind_of? C::CExpression and not ce.rexpr.op and not ce.lexpr.op and
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
		}
	end

	def remove_unreferenced_vars(scope)
		used = {}
		walk_ce(scope) { |ce|
			# remove unreferenced local vars
			used[ce.rexpr.name] = true if ce.rexpr.kind_of? C::Variable
			used[ce.lexpr.name] = true if ce.lexpr.kind_of? C::Variable
			ce.rexpr.each { |v| used[v.name] = true if v.kind_of? C::Variable } if ce.rexpr.kind_of?(::Array)
		}
		unused = scope.symbol.keys.find_all { |n| not used[n] }
		unused.each { |v| scope.symbol[v].add_attribute 'unused' }	# fastcall args need it
		scope.statements.delete_if { |sm| sm.kind_of? C::Declaration and unused.include? sm.var.name }
		scope.symbol.delete_if { |n, v| unused.include? n }
	end

	def optimize_global
		# check all global vars (pointers to global data)
		tl = @c_parser.toplevel
		vars = tl.symbol.keys.find_all { |k| not tl.symbol[k].type.kind_of? C::Function }
		countref = Hash.new(0)

		walk_ce(tl) { |ce|
			# XXX int foo; void bar() { int foo; }  =>  false negative
			countref[ce.rexpr.name] += 1 if ce.rexpr.kind_of? C::Variable
			countref[ce.lexpr.name] += 1 if ce.lexpr.kind_of? C::Variable
		}

		vars.delete_if { |v| countref[v] == 0 }
		countref.delete_if { |k, v| not vars.include? k }

		# by default globals are C::Arrays
		# if all references are *foo, dereference the var type
		# TODO allow foo to appear (change to &foo) (but still disallow casts/foo+12 etc)
		countderef = Hash.new(0)
		walk_ce(tl) { |ce|
			next if ce.op != :* or ce.lexpr
			r = ce.rexpr
			# compare type.type cause var is an Array and the cast is a Pointer
			countderef[r.rexpr.name] += 1 if r.kind_of? C::CExpression and not r.op and r.rexpr.kind_of? C::Variable and
		       			@c_parser.sizeof(nil, r.type.type) == @c_parser.sizeof(nil, r.rexpr.type.type) rescue nil
		}
		vars.each { |n|
			if countref[n] == countderef[n]
				v = tl.symbol[n]
				target = C::CExpression[:*, [v]]
				v.type = v.type.type
				v.initializer = v.initializer.first if v.initializer.kind_of? ::Array
				walk_ce(tl) { |ce|
					ce.lexpr = v if ce.lexpr == target
					ce.rexpr = v if ce.rexpr == target
					ce.lexpr, ce.op, ce.rexpr = nil, nil, v if ce == target
				}
			end
		}

		# if a global var appears only in one function, make it a static variable
		tl.statements.each { |st|
			next if not st.kind_of? C::Declaration or not st.var.type.kind_of? C::Function or not scope = st.var.initializer
			localcountref = Hash.new(0)
			walk_ce(scope) { |ce|
				localcountref[ce.rexpr.name] += 1 if ce.rexpr.kind_of? C::Variable
				localcountref[ce.lexpr.name] += 1 if ce.lexpr.kind_of? C::Variable
			}

			vars.delete_if { |n|
				next if scope.symbol[n]
				next if localcountref[n] != countref[n]
				v = tl.symbol.delete(n)
				tl.statements.delete_if { |d| d.kind_of? C::Declaration and d.var.name == n }

				if countref[n] == 1 and v.initializer.kind_of? C::CExpression and v.initializer.rexpr.kind_of? String
					walk_ce(scope) { |ce|
						if ce.rexpr.kind_of? C::Variable and ce.rexpr.name == n
							if not ce.op
								ce.replace v.initializer
							else
								ce.rexpr = v.initializer
							end
						elsif ce.lexpr.kind_of? C::Variable and ce.lexpr.name == n
							ce.lexpr = v.initializer
						end
					}
				else
					v.storage = :static
					scope.symbol[v.name] = v
					scope.statements.unshift C::Declaration.new(v)
				end

				true
			}
		}
	end

	# yield each CExpr member (recursive, allows arrays, order: self(!post), lexpr, rexpr, self(post))
	# if given a non-CExpr, walks it until it finds a CExpr to yield
	def walk_ce(ce, post=false, &b)
		case ce
		when C::CExpression
			yield ce if not post
			walk_ce(ce.lexpr, post, &b)
			walk_ce(ce.rexpr, post, &b)
			yield ce if post
		when ::Array
			ce.each { |ce_| walk_ce(ce_, post, &b) }
		when C::Statement
			case ce
			when C::Block; walk_ce(ce.statements, post, &b)
			when C::If
				walk_ce(ce.test, post, &b)
				walk_ce(ce.bthen, post, &b)
				walk_ce(ce.belse, post, &b) if ce.belse
			when C::While, C::DoWhile
				walk_ce(ce.test, post, &b)
				walk_ce(ce.body, post, &b)
			when C::Return
				walk_ce(ce.value, post, &b) if ce.value
			end
		when C::Declaration
			walk_ce(ce.var.initializer, post, &b) if ce.var.initializer
		end
		nil
	end

	# yields each statement (recursive)
	def walk(scope, post=false, &b)
		case scope
		when ::Array; scope.each { |s| walk(s, post, &b) }
		when C::Statement
			yield scope if not post
			case scope
			when C::Block; walk(scope.statements, post, &b)
			when C::If
				yield scope.test
				walk(scope.bthen, post, &b)
				walk(scope.belse, post, &b) if scope.belse
			when C::While, C::DoWhile
				yield scope.test
				walk(scope.body, post, &b)
			when C::Return
				yield scope.value
			end
			yield scope if post
		when C::Declaration
			walk(scope.var.initializer, post, &b) if scope.var.initializer
		end
	end
end
end
