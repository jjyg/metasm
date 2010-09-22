#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# This sample hacks in the ruby interpreter to allow dynamic loading of shellcodes as object methods
# Also it allows raw modifications to the ruby interpreter memory, for all kind of purposes
# Includes methods to dump the ruby parser AST from the interpreter memory
# elf/linux/x86 only

require 'metasm'


module Metasm
class RubyHack < DynLdr
	# basic C defs for ruby AST - ruby1.8 only !
	RUBY_INTERN_NODE = <<EOS
struct node {
	long flags;
	char *file;
	long a1;
	long a2;
	long a3;
};
#define FL_USHIFT 11
#define nd_type(n) ((((struct node*)n)->flags >> FL_USHIFT) & 0xff)
EOS
        NODETYPE = [
		:method, :fbody, :cfunc, :scope, :block,
		:if, :case, :when, :opt_n, :while,
		:until, :iter, :for, :break, :next,
		:redo, :retry, :begin, :rescue, :resbody,
		:ensure, :and, :or, :not, :masgn,
		:lasgn, :dasgn, :dasgn_curr, :gasgn, :iasgn,
		:cdecl, :cvasgn, :cvdecl, :op_asgn1, :op_asgn2,
		:op_asgn_and, :op_asgn_or, :call, :fcall, :vcall,
		:super, :zsuper, :array, :zarray, :hash,
		:return, :yield, :lvar, :dvar, :gvar, # 50
		:ivar, :const, :cvar, :nth_ref, :back_ref,
		:match, :match2, :match3, :lit, :str,
		:dstr, :xstr, :dxstr, :evstr, :dregx,
		:dregx_once, :args, :argscat, :argspush, :splat,
		:to_ary, :svalue, :block_arg, :block_pass, :defn,
		:defs, :alias, :valias, :undef, :class,
		:module, :sclass, :colon2, :colon3, :cref,
		:dot2, :dot3, :flip2, :flip3, :attrset,
		:self, :nil, :true, :false, :defined,
		:newline, :postexe, :alloca, :dmethod, :bmethod, # 100
		:memo, :ifunc, :dsym, :attrasgn, :last
	]

	new_api_c 'void rb_define_method(uintptr_t, char *, void *, int)'
	new_api_c 'void *rb_method_node(uintptr_t, unsigned id)'

class << self
	def set_class_method_raw(klass, meth, code, nparams)
		memory_perm(str_ptr(code), code.length, 'rwx')
		rb_define_method(rb_obj_to_value(klass), meth, code, nparams)
	end

	def get_method_node_ptr(klass, meth)
		raise if not klass.kind_of? Class
		rb_method_node(rb_obj_to_value(klass), meth.to_sym.to_i)
	end

	# sets up rawopcodes as the method implementation for class klass
	# rawopcodes must implement the expected ABI or things will break horribly
	# this method is VERY UNSAFE, and breaks everything put in place by the ruby interpreter
	# use with EXTREME CAUTION
	# nargs  arglist
	# -2     self, arg_ary
	# -1     argc, VALUE*argv, self
	# >=0    self, arg0, arg1..
	def set_method_binary(klass, methodname, raw, nargs=nil)
		nargs ||= klass.instance_method(methodname).arity
		if raw.kind_of? EncodedData
			baseaddr = str_ptr(raw.data)
			bd = raw.binding(baseaddr)
			raw.reloc_externals.uniq.each { |ext| bd[ext] = sym_addr(0, ext) or raise "unknown symbol #{ext}" }
			raw.fixup(bd)
			raw = raw.data
		end
		(@@prevent_gc ||= {})[[klass, methodname]] = raw
		set_class_method_raw(klass, methodname.to_s, raw, nargs)
	end

	# same as load_binary_method but with an object and not a class
	def set_object_method_binary(obj, *a)
		set_method_binary((class << obj ; self ; end), *a)
	end

	def read_node(ptr, cur=nil)
		return if ptr == 0

		type = NODETYPE[(memory_read_int(ptr) >> 11) & 0xff]
		v1 = memory_read_int(ptr+8)
		v2 = memory_read_int(ptr+12)
		v3 = memory_read_int(ptr+16)

		case type
		when :block, :array, :hash
			cur = nil if cur and cur[0] != type
			cur ||= [type]
			cur << read_node(v1)
			n = read_node(v3, cur)
			raise "block->next = #{n.inspect}" if n and n[0] != type
			cur
		when :newline
			read_node(v3)	# debug/trace usage only
		when :if
			[type, read_node(v1), read_node(v2), read_node(v3)]
		when :cfunc
			v2 = {0xffffffff => -1, 0xfffffffe => -2, 0xffffffffffffffff => -1, 0xfffffffffffffffe => -2}[v2] || v2
			[type, {:fptr => v1,	# c func pointer
				:arity => v2}]
		when :scope
			[type, {:localnr => (v1 != 0 ? memory_read_int(v1) : 0),	# nr of local vars (+2 for $_/$~)
				:cref => v2},	# node, starting point for const resolution
				read_node(v3)]
		when :call, :fcall, :vcall
			ret = [type, read_node(v1), v2.id2name]
			if args = read_node(v3)
				raise "#{ret.inspect} with args != array: #{args.inspect}" if args[0] != :array
				ret.concat args[1..-1]
			end
			ret
		when :dstr
			ret = [type, [:str, rb_value_to_obj(v1)]]
			if args = read_node(v3)
				raise "#{ret.inspect} with args != array: #{args.inspect}" if args[0] != :array
				ret.concat args[1..-1]
			end
			ret
		when :zarray
			[:array]
		when :lasgn
			[type, v3, read_node(v2)]
		when :iasgn, :dasgn, :dasgn_curr, :gasgn, :cvasgn
			[type, v1.id2name, read_node(v2)]
		when :masgn
			# multiple assignment: a, b = 42 / lambda { |x, y| }.call(1, 2)
			# v3 = remainder storage (a, b, *c = ary => v3=c)
			[type, read_node(v1), read_node(v2), read_node(v3)]
		when :attrasgn
			[type, ((v1 == 1) ? :self : read_node(v1)), v2.id2name, read_node(v3)]
		when :lvar
			[type, v3]
		when :ivar, :dvar, :gvar, :cvar, :const
			[type, v1.id2name]
		when :str
			# cannot use _id2ref here, probably the parser does not use standard alloced objects
			s = memory_read(memory_read_int(v1+12), memory_read_int(v1+16))
			[type, s]
		when :lit
			[type, rb_value_to_obj(v1)]
		when :args	# specialcased by rb_call0, invalid in rb_eval
			cnt = v3	# nr of required args, copied directly to local_vars
			opt = read_node(v1)	# :block to execute for each missing arg / with N optargs specified, skip N 1st statements
			rest = read_node(v2)	# catchall arg in def foo(rq1, rq2, *rest)
			[type, cnt, opt, rest]
		when :and, :or
			[type, read_node(v1), read_node(v2)]	# shortcircuit
		when :not
			[type, read_node(v2)]
		when :nil, :true, :false, :self
			[type]
		when :redo, :retry
			[type]
		when :case
			#    [:case, var_test, [:when, cnd, action, [:when, cnd2, action2, else]]]
			# => [:case, var_test, [:when, cnd, action], [:when, cnd2, action], else]
			cs = [type, read_node(v1), read_node(v2)]
			cs << cs[-1].pop while cs[-1][0] == :when and cs[-1][3]
			cs
		when :when
			# [:when, [:array, [test]], then, else]
			[type, read_node(v1), read_node(v2), read_node(v3)]
		when :iter
			# save a block for the following funcall
			args = read_node(v1)	# assignments with nil, not realized, just to store the arg list (multi args -> :masgn)
			body = read_node(v2)	# the body statements (multi -> :block)
			subj = read_node(v3)	# the stuff which is passed the block, probably a :call
			[type, args, body, subj]
		when :while, :until
			[type, read_node(v1), read_node(v2), v3]
		when :return, :break, :next, :defined
			[type, read_node(v1)]
		when :to_ary
			[type, read_node(v1)]
		when :colon2
			[type, read_node(v1), v2.id2name]
		when :colon3	# ::Stuff
			[type, v2.id2name]
		when :method
			[type, v1, read_node(v2), v3]
		when :alias
			[type, v1, v2, v3]	# ?
		when :evstr
			[type, read_node(v2)]
		when :dot2, :dot3
			[type, read_node(v1), read_node(v2)]
		when :splat
			[type, read_node(v1)]
		else
			puts "unhandled #{type.inspect}"
			[type, v1, v2, v3]
		end
	end

	def compile_ruby(klass, meth)
		ast = read_node get_method_node_ptr(klass, meth)

		if $VERBOSE
			require 'pp'
			pp ast
		end

		return if not c = ruby_ast_to_c(ast, klass, meth)

		if $VERBOSE
			puts c
		end

		raw = compile_c(c).encoded
		set_method_binary(klass, meth, raw)
	end

	def ruby_ast_to_c(ast, klass, meth)
		return if not ast or ast[0] != :scope
		cp = host_cpu.new_cparser
		mname = RubyLiveCompiler.new(cp).compile(ast, klass, meth)
		cp.dump_definition(mname)
	end
end	# class << self
end

# a ruby2c C generator for use in the current ruby interpreter
# generates C suitable for shellcode compilation & insertion in the current interpreter
# has hardcoded addresses etc
class RubyLiveCompiler
	attr_accessor :cp

	RUBY_H = <<EOS
#{DynLdr::RUBY_H}

VALUE rb_iv_get(VALUE, const char*);
VALUE rb_iv_set(VALUE, const char*, VALUE);
VALUE rb_ivar_defined(VALUE, unsigned);
VALUE rb_cvar_get(VALUE, unsigned);
VALUE rb_cvar_set(VALUE, unsigned, VALUE, int);
VALUE rb_gv_get(const char*);
VALUE rb_gv_set(const char*, VALUE);

VALUE rb_ary_new(void);
VALUE rb_ary_new4(long, VALUE*);
VALUE rb_ary_push(VALUE, VALUE);
VALUE rb_ary_pop(VALUE);
VALUE rb_hash_new(void);
VALUE rb_hash_aset(VALUE, VALUE, VALUE);
VALUE rb_str_new(const char*, long);
VALUE rb_str_new2(const char*);
VALUE rb_str_cat2(VALUE, const char*);
VALUE rb_str_concat(VALUE, VALUE);
VALUE rb_str_append(VALUE, VALUE);
VALUE rb_obj_as_string(VALUE);
VALUE rb_range_new(VALUE, VALUE, int exclude_end);
VALUE rb_Array(VALUE);	// :splat
VALUE rb_ary_to_ary(VALUE);
VALUE rb_hash_aref(VALUE, VALUE);

void rb_define_method(VALUE, char *, void *, int);
void *rb_method_node(VALUE, unsigned);
EOS

	class Fail < RuntimeError
	end

	def self.compile(klass, *methlist)
		@rcp ||= new
		methlist.each { |meth|
			ast = RubyHack.read_node(RubyHack.get_method_node_ptr(klass, meth))
			next if not ast or ast[0] != :scope
			n = @rcp.compile(ast, klass, meth)
			raw = RubyHack.compile_c(@rcp.cp.dump_definition(n)).encoded
			RubyHack.set_method_binary(klass, meth, raw)
		}
		self
	end

	def initialize(cp=nil)
		@cp = cp || DynLdr.host_cpu.new_cparser
		@cp.parse RUBY_H
		@iter_break = nil
	end

	# convert a ruby AST to a new C function
	# returns the new function name
	def compile(ast, klass, meth)
		# TODO handle arbitrary block/yield constructs
		# TODO analyse to find/optimize numeric locals that never need a ruby VALUE (ie native int vs INT2FIX)
		# TODO detect block/closure exported out of the func & abort compilation

		@klass = klass
		@meth = meth

		mname = escape_varname("m_#{@klass}##{@meth}".gsub('::', '_'))
		@cp.parse "static void #{mname}(VALUE self) { }"
		@cur_cfunc = @cp.toplevel.symbol[mname]
		@cur_cfunc.type.type = value	# return type = VALUE, w/o 'missing return statement' warning

		@scope = @cur_cfunc.initializer

		if ast[0] == :scope and ast[2] and ast[2][0] == :block and ast[2][1] and ast[2][1][0] == :args
			compile_args(@cur_cfunc, ast[2][1])
		end
		ret = ast_to_c(ast[2], @scope)

		@scope.statements << C::Return.new(ret)

		mname
	end

	def compile_args(func, args)
		case @klass.instance_method(@meth).arity
		when -1	# args[1] == 0 and (args[2] or args[3])
			compile_args_m1(func, args)
		when -2	# args[1] > 0 and (args[2] or args[3])
			compile_args_m2(func, args)
		else
			# fixed arity = args[1]: VALUE func(VALUE self, VALUE local_2, VALUE local_3)
			args[1].times { |i|
				v = C::Variable.new("local_#{i+2}", value)
				@scope.symbol[v.name] = v
				func.type.args << v
			}
		end
	end

	# update func prototype to reflect arity -1
	# VALUE func(int argc, VALUE *argv, VALUE self)
	def compile_args_m1(func, args)
		c = C::Variable.new("arg_c", C::BaseType.new(:int, :unsigned))
		v = C::Variable.new("arg_v", C::Pointer.new(value))
		@scope.symbol[c.name] = c
		@scope.symbol[v.name] = v
		func.type.args.unshift v
		func.type.args.unshift c

		args[1].times { |i|
			local(i+2, C::CExpression[v, :'[]', [i]])
		}

		if args[2]
			# [:block, [:lasgn, 2, [:lit, 4]]]
			raise Fail, "unhandled vararglist #{args.inspect}" if args[2][0] != :block
			args[2][1..-1].each_with_index { |a, i|
				raise Fail, "unhandled arg #{a.inspect}" if a[0] != :lasgn
				cnd = C::CExpression[c, :>, i]
				thn = C::CExpression[local(a[1], :none), :'=', [v, :'[]', [i]]]
				els = C::Block.new(@scope)
				ast_to_c(a, els, false)
				@scope.statements << C::If.new(cnd, thn, els)
			}
		end

		if args[3]
			raise Fail, "unhandled vararglist3 #{args.inspect}" if args[3][0] != :lasgn
			skiplen = args[1] + args[2].length - 1
			alloc = fcall('rb_ary_new4', [c, :-, [skiplen]], [v, :+, [skiplen]])
			local(args[3][1], C::CExpression[[c, :>, skiplen], :'?:', [alloc, fcall('rb_ary_new')]])
		end
	end

	# update func prototype to reflect arity -2
	# VALUE func(VALUE self, VALUE arg_array)
	def compile_args_m2(func, args)
		v = C::Variable.new("arglist", value)
		@scope.symbol[v.name] = v
		func.type.args << v

		args[1].times { |i|
			local(i+2, rb_funcall(v, 'shift'))
		}

		# populate arguments with default values
		if args[2]
			# [:block, [:lasgn, 2, [:lit, 4]]]
			raise Fail, "unhandled vararglist #{args.inspect}" if args[2][0] != :block
			args[2][1..-1].each { |a|
				raise Fail, "unhandled arg #{a.inspect}" if a[0] != :lasgn
				t = C::Block.new(@scope)
				ast_to_c([:lasgn, a[1], [:call, [:rb2cvar, v.name], 'shift']], t, false)
				e = C::Block.new(@scope)
				ast_to_c([:lasgn, a[1], a[2]], e, false)
				@scope.statements << C::If.new(rb_ary_len(v), t, e)
			}
		end

		if args[3]
			raise Fail, "unhandled vararglist3 #{args.inspect}" if args[3][0] != :lasgn
			local(args[3][1], C::CExpression[v])
		end
	end

	# compile a case/when
	# create a real C switch() for Fixnums, and put the others === in the default case
	# XXX will get the wrong order for "case x; when 1; when Fixnum; when 3;" ...
	def compile_case(ast, scope, want_value)
		# this generates
		# var = stuff_to_test()
		# if (var & 1)
		#   switch (var >> 1) {
		#      case 12:
		#          stuff();
		#          break;
		#      default:
		#          goto default_case;
		#   }
		# else
		# default_case:
		#   if (var == true.object_id || rb_test(rb_funcall(bla, '===', var)))
		#      foo();
		#   else {
		#      default();
		#   }
		#      
		ret = get_new_tmp_var('case', want_value)
		var = ast_to_c(ast[1], scope, ret)
		if not var.kind_of? C::Variable
			scope.statements << C::CExpression[ret, :'=', var]
			var = ret
		end

		# the scope to put all case int in
		body_int = C::Block.new(scope)
		# the scope to put the if (cs === var) cascade
		body_other_head = body_other = nil
		default = nil

		ast[2..-1].each { |cs|
			if cs[0] == :when
				raise Fail if cs[1][0] != :array

				# numeric case, add a case to body_int
				if cs[1][1..-1].all? { |cd| cd[0] == :lit and (cd[1].kind_of? Fixnum or cd[1].kind_of? Range) }
					cs[1][1..-1].each { |cd|
						if cd[1].kind_of? Range
							b = cd[1].begin
							e = cd[1].end
							e -= 1 if cd[1].exclude_end?
							raise Fail unless b.kind_of? Integer and e.kind_of? Integer
							body_int.statements << C::Case.new(b, e, nil)
						else
							body_int.statements << C::Case.new(cd[1], nil, nil)
						end
					}
					cb = C::Block.new(scope)
					v = ast_to_c(cs[2], cb, want_value)
					cb.statements << C::CExpression[ret, :'=', v] if want_value
					cb.statements << C::Break.new
					body_int.statements << cb

				# non-numeric (or mixed) case, add if ( cs === var )
				else
					cnd = nil
					cs[1][1..-1].each { |cd|
						if (cd[0] == :lit and (cd[1].kind_of?(Fixnum) or cd[1].kind_of?(Symbol))) or
							[:nil, :true, :false].include?(cd[0])
							# true C equality
							cd = C::CExpression[var, :==, ast_to_c(cd, scope)]
						else
							# own block for ast_to_c to honor lazy evaluation
							tb = C::Block.new(scope)
							test = rb_test(rb_funcall(ast_to_c(cd, tb), '===', var), tb)
							# discard own block unless needed
							if tb.statements.empty?
								cd = test
							else
								tb.statements << test
								cd = C::CExpression[tb, value]
							end
						end
						cnd = (cnd ? C::CExpression[cnd, :'||', cd] : cd)
					}
					cb = C::Block.new(scope)
					v = ast_to_c(cs[2], cb, want_value)
					cb.statements << C::CExpression[ret, :'=', v] if want_value
					
					fu = C::If.new(cnd, cb, nil)

					if body_other
						body_other.belse = fu
					else
						body_other_head = fu
					end
					body_other = fu
				end

			# default case statement
			else
				cb = C::Block.new(scope)
				v = ast_to_c(cs, cb, want_value)
				cb.statements << C::CExpression[ret, :'=', v] if want_value
				default = cb
			end
		}

		# assemble everything
		scope.statements <<
		if body_int.statements.empty?
			if body_other
				body_other.belse = default
				body_other_head
			else
				raise Fail, "empty case? #{ast.inspect}" if not default
				default
			end
		else
			if body_other_head
				@default_label_cnt ||= 0
				dfl = "default_label_#{@default_label_cnt += 1}"
				body_other_head = C::Label.new(dfl, body_other_head)
				body_int.statements << C::Case.new('default', nil, C::Goto.new(dfl))
				body_other.belse = default if default
			end
			body_int = C::Switch.new(C::CExpression[var, :>>, 1], body_int)
			C::If.new(C::CExpression[var, :&, 1], body_int, body_other_head)
		end

		ret
	end

	# create a C::CExpr[toplevel.symbol[name], :funcall, args]
	# casts int/strings in arglist to CExpr
	def fcall(fname, *arglist)
		args = arglist.map { |a| (a.kind_of?(Integer) or a.kind_of?(String)) ? [a] : a }
		fv = @cp.toplevel.symbol[fname]
		raise "need prototype for #{fname}!" if not fv
		C::CExpression[fv, :funcall, args]
	end

	# the VALUE typedef
	def value
		@cp.toplevel.symbol['VALUE']
	end

	# declare a new function variable
	# no initializer if init == :none
	def declare_newvar(name, initializer)
		v = C::Variable.new(name, value)
		v.initializer = initializer if initializer != :none
		@scope.symbol[v.name] = v
		@scope.statements << C::Declaration.new(v)
		v
	end

	# return a string suitable for use as a variable name
	# hexencode any char not in [A-z0-9_]
	def escape_varname(n)
		n.gsub(/[^\w]/) { |c| c.unpack('H*')[0] }
	end

	# retrieve or create a local var
	# pass :none to avoid initializer
	def get_var(name, initializer=:none)
		name = escape_varname(name)
		@scope.symbol[name] ||= declare_newvar(name, initializer || C::CExpression[[nil.object_id], value])
	end

	# create a new temporary variable
	# XXX put_var ?
	def get_new_tmp_var(base=nil, var=nil)
		return var if var.kind_of? C::Variable
		@tmp_var_id ||= 0
		get_var("tmp_#{"#{base}_" if base}#{@tmp_var_id += 1}")
	end

	# retrieve/create a new local variable with optionnal initializer
	def local(n, init=nil)
		get_var "local_#{n}", init
	end

	# retrieve/create a new dynamic variable (block argument/variable)
	# pass :none to avoid initializer
	def dvar(n, init=nil)
		get_var "dvar_#{n}", init
	end

	# retrieve self (1st func arg)
	def rb_self
		@scope.symbol['self']
	end

	# returns a CExpr casting expr to a VALUE*
	def rb_cast_pvalue(expr, idx)
		C::CExpression[[[expr], C::Pointer.new(value)], :'[]', [idx]]
	end

	# retrieve the current class, from self->klass
	# XXX will segfault with self.kind_of? Fixnum/true/false/nil/sym
	def rb_selfclass
		rb_cast_pvalue(rb_self, 1)
	end

	# call rb_intern on a string
	def rb_intern(n)
		# use the current interpreter's value
		C::CExpression[n.to_sym.to_i]
	end

	# create a rb_funcall construct
	def rb_funcall(recv, meth, *args)
		fcall('rb_funcall', recv, rb_intern(meth), args.length, *args)
	end

	# ruby bool test of a var
	# assigns to a temporary var, and check against false/nil
	def rb_test(expr, scope)
		if nil.object_id == 0 or false.object_id == 0	# just to be sure
			nf = nil.object_id | false.object_id
			C::CExpression[[expr, :|, nf], :'!=', nf]
		else
			if expr.kind_of? C::Variable
				tmp = expr
			else
				tmp = get_new_tmp_var('test')
				scope.statements << C::CExpression[tmp, :'=', expr]
			end
			C::CExpression[[tmp, :'!=', nil.object_id], :'&&', [tmp, :'!=', false.object_id]]
		end
	end

	# generate C code to raise a RuntimeError, reason
	def rb_raise(reason)
		fcall('rb_raise', @cp.toplevel.symbol['rb_eRuntimeError'], reason)
	end

	# return a C expr equivallent to TYPE(expr) == type for non-immediate types
	# XXX expr evaluated 3 times
	def rb_test_class_type(expr, type)
		C::CExpression[[[expr, :>, [7]], :'&&', [[expr, :&, [3]], :==, [0]]], :'&&', [[rb_cast_pvalue(expr, 0), :&, [0x3f]], :'==', [type]]]
	end

	# return a C expr equivallent to TYPE(expr) == T_ARRAY
	def rb_test_class_ary(expr)
		rb_test_class_type(expr, 9)
	end
	# ARY_PTR(expr)
	def rb_ary_ptr(expr, idx=nil)
		p = C::CExpression[[rb_cast_pvalue(expr, 4)], C::Pointer.new(value)]
		idx ? C::CExpression[p, :'[]', [idx]] : p
	end
	# ARY_LEN(expr)
	def rb_ary_len(expr)
		rb_cast_pvalue(expr, 2)
	end

	# TYPE(expr) == T_STRING
	def rb_test_class_string(expr)
		rb_test_class_type(expr, 7)
	end
	# STR_PTR(expr)
	def rb_str_ptr(expr, idx=nil)
		p = C::CExpression[[rb_cast_pvalue(expr, 3)], C::Pointer.new(C::BaseType.new(:char))]
		idx ? C::CExpression[p, :'[]', [idx]] : p
	end
	# STR_LEN(expr)
	def rb_str_len(expr)
		rb_cast_pvalue(expr, 2)
	end

	def rb_test_class_hash(expr)
		rb_test_class_type(expr, 0xb)
	end


	# compile a :masgn
	def rb_masgn(ast, scope, want_value)
		raise Fail, "masgn with no rhs #{ast.inspect}" if not ast[2]
		raise Fail, "masgn with no lhs array #{ast.inspect}" if not ast[1] or ast[1][0] != :array
		if not want_value and ast[2][0] == :array and not ast[3] and ast[2].length == ast[1].length
			rb_masgn_optimized(ast, scope)
			return nil.object_id
		end
		full = get_new_tmp_var('masgn', want_value)
		ary = ast_to_c(ast[2], scope, full)
		scope.statements << C::CExpression[full, :'=', ary] if full != ary
		ast[1][1..-1].each_with_index { |e, i|
			raise Fail, "weird masgn lhs #{e.inspect} in #{ast.inspect}" if e[-1] != nil
			# local_42 = full[i]
			e = e.dup
			e[-1] = [:call, [:rb2cvar, full.name], '[]', [:lit, i]]
			ast_to_c(e, scope, false)
		}
		if ast[3]
			raise Fail, "weird masgn lhs #{e.inspect} in #{ast.inspect}" if ast[3][-1] != nil
			# local_28 = full[12..-1].to_a
			e = ast[3].dup
			e[-1] = [:call, [:call, [:rb2cvar, full.name], '[]', [:dot2, [:lit, ast[1].length-1], [:lit, -1]]], 'to_a']
			ast_to_c(e, scope, false)
		end

		full
	end

	def rb_cstget(cname)
		fcall('rb_const_get', @cp.toplevel.symbol['rb_cObject'], rb_intern(cname))
	end

	# compile an optimized :masgn with rhs.length == lhs.length (no need of a ruby array)
	def rb_masgn_optimized(ast, scope)
		vars = []
		ast[2][1..-1].each { |rhs|
			var = get_new_tmp_var('masgn_opt')
			vars << var
			r = ast_to_c(rhs, scope, var)
			scope.statements << C::CExpression[var, :'=', r] if var != r
		}
		ast[1][1..-1].each { |lhs|
			var = vars.shift
			lhs = lhs.dup
			raise Fail, "weird masgn lhs #{lhs.inspect} in #{ast.inspect}" if lhs[-1] != nil
			lhs[-1] = [:rb2cvar, var.name]
			ast_to_c(lhs, scope, false)
		}
	end

	# the recursive AST to C compiler
	# may append C statements to scope
	# returns the C::CExpr holding the VALUE of the current ruby statement
	# want_value is an optionnal hint as to the returned VALUE is needed or not
	# if want_value is a C::Variable, the statements should try to populate this var instead of some random tmp var
	# eg to simplify :if encoding unless we have 'foo = if 42;..'
	def ast_to_c(ast, scope, want_value = true)
		ret = 
		case ast.to_a[0]
		when :block
			if ast[1]
				ast[1..-2].each { |a| ast_to_c(a, scope, false) }
				ast_to_c(ast.last, scope, want_value)
			end

		when :lvar
			local(ast[1])
		when :lasgn
			if scope == @scope
				l = local(ast[1], :none)
			else
				# w = 4 if false ; p w  => should be nil
				l = local(ast[1])
			end
			st = ast_to_c(ast[2], scope, l)
			scope.statements << C::CExpression[l, :'=', st] if st != l
			l
		when :dvar
			dvar(ast[1])
		when :dasgn_curr
			l = dvar(ast[1])
			st = ast_to_c(ast[2], scope, l)
			scope.statements << C::CExpression[l, :'=', st] if st != l
			l
		when :ivar
			fcall('rb_iv_get', rb_self, ast[1])
		when :iasgn
			if want_value
				tmp = get_new_tmp_var("ivar_#{ast[1]}", want_value)
				scope.statements << C::CExpression[tmp, :'=', ast_to_c(ast[2], scope)]
				scope.statements << fcall('rb_iv_set', rb_self, ast[1], tmp)
				tmp
			else
				scope.statements << fcall('rb_iv_set', rb_self, ast[1], ast_to_c(ast[2], scope))
			end
		when :cvar
			fcall('rb_cvar_get', rb_selfclass, rb_intern(ast[1]))
		when :cvasgn
			if want_value
				tmp = get_new_tmp_var("cvar_#{ast[1]}", want_value)
				scope.statements << C::CExpression[tmp, :'=', ast_to_c(ast[2], scope)]
				scope.statements << fcall('rb_cvar_set', rb_selfclass, rb_intern(ast[1]), tmp, false.object_id)
				tmp
			else
				scope.statements << fcall('rb_cvar_set', rb_selfclass, rb_intern(ast[1]), ast_to_c(ast[2], scope), false.object_id)
			end
		when :gvar
			fcall('rb_gv_get', ast[1])
		when :gasgn
			if want_value
				tmp = get_new_tmp_var("gvar_#{ast[1]}", want_value)
				scope.statements << C::CExpression[tmp, :'=', ast_to_c(ast[2], scope)]
				scope.statements << fcall('rb_gv_set', ast[1], tmp)
				tmp
			else
				scope.statements << fcall('rb_gv_set', ast[1], ast_to_c(ast[2], scope))
			end
		when :attrasgn	# foo.bar= 42 (same as :call, except for return value)
			recv = ast_to_c(ast[1], scope)
			raise Fail, "unsupported #{ast.inspect}" if not ast[3] or ast[3][0] != :array or ast[3].length != 2
			arg = ast_to_c(ast[3][1], scope)
			if want_value
				tmp = get_new_tmp_var('call', want_value)
				scope.statements << C::CExpression[tmp, :'=', arg]
			end
			scope.statements << rb_funcall(recv, ast[2], arg)
			tmp

		when :rb2cvar	# hax, used in vararg parsing
			get_var(ast[1])

		when :lit
			case ast[1]
			when Symbol
				# XXX ID2SYM
				C::CExpression[[rb_intern(ast[1].to_s), :<<, 8], :|, 0xe]
			when Range
				fcall('rb_range_new', ast[1].begin.object_id, ast[1].end.object_id, ast[1].exclude_end? ? 0 : 1)
			else	# true/false/nil/fixnum
				ast[1].object_id
			end
		when :self
			rb_self
		when :str
			fcall('rb_str_new2', ast[1])
		when :array
			tmp = get_new_tmp_var('ary', want_value)
			scope.statements << C::CExpression[tmp, :'=', fcall('rb_ary_new')]
			ast[1..-1].each { |e|
				scope.statements << fcall('rb_ary_push', tmp, ast_to_c(e, scope))
			}
			tmp
		when :hash
			raise Fail, "bad #{ast.inspect}" if ast[1][0] != :array
			tmp = get_new_tmp_var('hash', want_value)
			scope.statements << C::CExpression[tmp, :'=', fcall('rb_hash_new')]
			ki = nil
			ast[1][1..-1].each { |k|
				if not ki
					ki = k
				else
					scope.statements << fcall('rb_hash_aset', tmp, ast_to_c(ki, scope), ast_to_c(k, scope))
					ki = nil
				end
			}
			tmp

		when :iter
			if v = optimize_iter(ast, scope, want_value)
				return v
			end
			# for full support of :iter, we need access to the interpreter's ruby_block private global variable in eval.c
			# we can find it by analysing rb_block_given_p, but this won't work with a static precompiled rubyhack...
			# even with access to ruby_block, there we would need to redo PUSH_BLOCK, create a temporary dvar list,
			# handle [:break, lol], and do all the stack magic reused in rb_yield (probably incl setjmp etc)
			raise Fail, "unsupported iter #{ast[1].inspect}   -   #{ast[3].inspect}   -   #{ast[2].inspect}"

		when :call, :vcall, :fcall
			if v = optimize_call(ast, scope, want_value)
				return v
			end
			recv = ((ast[0] == :call) ? ast_to_c(ast[1], scope) : rb_self)
			args = ast[3..-1].map { |a| ast_to_c(a, scope) }
			f = rb_funcall(recv, ast[2], *args)
			if want_value
				tmp = get_new_tmp_var('call', want_value)
				scope.statements << C::CExpression[tmp, :'=', f]
				tmp
			else
				scope.statements << f
			end

		when :if, :when
			if ast[0] == :when and ast[1][0] == :array
				cnd = nil
				ast[1][1..-1].map { |cd| rb_test(ast_to_c(cd, scope), scope) }.each { |cd|
					cnd = (cnd ? C::CExpression[cnd, :'||', cd] : cd)
				}
			else
				cnd = rb_test(ast_to_c(ast[1], scope), scope)
			end

			tbdy = C::Block.new(scope)
			thn = ast_to_c(ast[2], tbdy, want_value)
			ebdy = C::Block.new(scope) if ast[3]
			els = ast_to_c(ast[3], ebdy, want_value)

			tmp = get_new_tmp_var('if', want_value) if want_value

			scope.statements << C::If.new(cnd, tbdy, ebdy)

			if want_value
				tbdy.statements << C::CExpression[tmp, :'=', thn] if tmp != thn
				ebdy.statements << C::CExpression[tmp, :'=', els] if ast[3] and tmp != els
				tmp
			end

		when :while, :until
			pib = @iter_break
			@iter_break = nil	# XXX foo = while ()...

			body = C::Block.new(scope)
			if ast[3] == 0	# do .. while();
				ast_to_c(ast[2], body, false)
			end
			t = nil
			e = C::Break.new
			t, e = e, t if ast[0] == :until
			body.statements << C::If.new(rb_test(ast_to_c(ast[1], body), body), t, e)
			if ast[3] != 0	# do .. while();
				ast_to_c(ast[2], body, false)
			end
			scope.statements << C::For.new(nil, nil, nil, body)

			@iter_break = pib
			nil.object_id

		when :and, :or, :not
			# beware lazy evaluation !
			tmp = get_new_tmp_var('and', want_value)
			v1 = ast_to_c(ast[1], scope, tmp)
			# and/or need that tmp has the actual v1 value (returned when shortcircuit)
			scope.statements << C::CExpression[tmp, :'=', v1] if v1 != tmp
			v1 = tmp
			case ast[0]
			when :and
				t = C::Block.new(scope)
				v2 = ast_to_c(ast[2], t, tmp)
				t.statements << C::CExpression[tmp, :'=', v2] if v2 != tmp
			when :or
				e = C::Block.new(scope)
				v2 = ast_to_c(ast[2], e, tmp)
				e.statements << C::CExpression[tmp, :'=', v2] if v2 != tmp
			when :not
				t = C::CExpression[tmp, :'=', [[false.object_id], value]]
				e = C::CExpression[tmp, :'=', [[true.object_id], value]]
			end
			scope.statements << C::If.new(rb_test(v1, scope), t, e)
			tmp
		when :return
			scope.statements << C::Return.new(ast_to_c(ast[1], scope))
			nil.object_id
		when :break
			if @iter_break
				v = (ast[1] ? ast_to_c(ast[1], scope, @iter_break) : nil.object_id)
				scope.statements << C::CExpression[@iter_break, :'=', [[v], value]] if @iter_break != v
			end
			scope.statements << C::Break.new
			nil.object_id

		when nil, :args
			nil.object_id
		when :nil
			C::CExpression[[nil.object_id], value]
		when :false
			C::CExpression[[false.object_id], value]
		when :true
			C::CExpression[[true.object_id], value]
		when :const
			# XXX use scope.cref ?
			fcall('rb_const_get', rb_selfclass, rb_intern(ast[1]))
		when :colon2
			fcall('rb_const_get', ast_to_c(ast[1], scope), rb_intern(ast[2]))
		when :colon3
			rb_cstget(ast[1])
		when :defined
			case ast[1][0]
			when :ivar
				fcall('rb_ivar_defined', rb_self, rb_intern(ast[1][1]))
			else 
				raise Fail, "unsupported #{ast.inspect}"
			end
		when :masgn
			# parallel assignment: put everything in an Array, then pop everything back?
			rb_masgn(ast, scope, want_value)
			
		when :evstr
			fcall('rb_obj_as_string', ast_to_c(ast[1], scope))
		when :dot2, :dot3
			fcall('rb_range_new', ast_to_c(ast[1], scope), ast_to_c(ast[2], scope), ast[0] == :dot2 ? 0 : 1)
		when :splat
			fcall('rb_Array', ast_to_c(ast[1], scope))
		when :to_ary
			fcall('rb_ary_to_ary', ast_to_c(ast[1], scope))
		when :dstr
			# dynamic string: "foo#{bar}baz"
			tmp = get_new_tmp_var('dstr')
			scope.statements << C::CExpression[tmp, :'=', fcall('rb_str_new2', ast[1][1])]
			ast[2..-1].compact.each { |s|
				if s[0] == :str # directly append the char*
					scope.statements << fcall('rb_str_cat2', tmp, s[1])
				else
					scope.statements << fcall('rb_str_append', tmp, ast_to_c(s, scope))
				end
			}
			tmp
		when :case
			compile_case(ast, scope, want_value)
		else
			raise Fail, "unsupported #{ast.inspect}"
		end

		if want_value
			ret = C::CExpression[[ret], value] if ret.kind_of? Integer or ret.kind_of? String
			ret
		end
	end

	# optional optimization of a call (eg a == 1, c+2, ...)
	# return nil for normal rb_funcall, or a C::CExpr to use as retval.
	def optimize_call(ast, scope, want_value)
		ce = C::CExpression
		op = ast[2]
		int = C::BaseType.new(:ptr)	# signed VALUE

		if ast.length == 4 and ast[3][0] == :lit and ast[3][1].kind_of? Fixnum
			# optimize 'x==42', 'x+42', 'x-42'
			o2 = ast[3][1]
			return if not %w[== > < >= <= + -].include? op
			if o2 < 0 and ['+', '-'].include? op
				# need o2 >= 0 for overflow detection
				op = {'+' => '-', '-' => '+'}[op]
				o2 = -o2
				return if not o2.kind_of? Fixnum	# -0x40000000
			end

			int_v = o2.object_id
			recv = ast_to_c(ast[1], scope)
			tmp = get_new_tmp_var('opt', want_value)
			if not recv.kind_of? C::Variable
				scope.statements << ce[tmp, :'=', recv]
				recv = tmp
			end

			case op
			when '=='
				# XXX assume == only return true for full equality: if not Fixnum, then always false
				# which breaks 1.0 == 1 and maybe others, but its ok
				scope.statements << C::If.new(ce[recv, :'==', [int_v]], ce[tmp, :'=', [[true.object_id], value]], ce[tmp, :'=', [[false.object_id], value]])
			when '>', '<', '>=', '<='
				# do the actual comparison on signed >>1 if both Fixnum
				t = C::If.new(
					ce[[[[recv], int], :>>, [1]], op.to_sym, [[[int_v], int], :>>, [1]]],
					ce[tmp, :'=', [[true.object_id], value]],
					ce[tmp, :'=', [[false.object_id], value]])
				# fallback to actual rb_funcall
				e = ce[tmp, :'=', rb_funcall(recv, op, o2.object_id)]
				scope.statements << C::If.new(ce[recv, :&, 1], t, e)
			when '+'
				e = ce[recv, :+, [int_v-1]] # overflow to Bignum ?
				cnd = ce[[recv, :&, [1]], :'&&', [[[recv], int], :<, [[e], int]]]
				t = ce[tmp, :'=', e]
				e = ce[tmp, :'=', rb_funcall(recv, op, o2.object_id)]
				scope.statements << C::If.new(cnd, t, e)
			when '-'
				e = ce[recv, :-, [int_v-1]]
				cnd = ce[[recv, :&, [1]], :'&&', [[[recv], int], :>, [[e], int]]]
				t = ce[tmp, :'=', e]
				e = ce[tmp, :'=', rb_funcall(recv, op, o2.object_id)]
				scope.statements << C::If.new(cnd, t, e)
			end
			tmp
		
		# Symbol#==
		elsif ast.length == 4 and ast[3][0] == :lit and ast[3][1].kind_of? Symbol and op == '=='
			s_v = ast_to_c(ast[3], scope)
			tmp = get_new_tmp_var('opt', want_value)
			recv = ast_to_c(ast[1], scope, tmp)
			if not recv.kind_of? C::Variable
				scope.statements << ce[tmp, :'=', recv]
				recv = tmp
			end

			scope.statements << C::If.new(ce[recv, :'==', [s_v]], ce[tmp, :'=', [[true.object_id], value]], ce[tmp, :'=', [[false.object_id], value]])
			tmp

		elsif ast.length == 4 and op == '<<'
			tmp = get_new_tmp_var('opt', want_value)
			recv = ast_to_c(ast[1], scope, tmp)
			arg = ast_to_c(ast[3], scope)
			if recv != tmp
				scope.statements << ce[tmp, :'=', recv]
				recv = tmp
			end

			ar = fcall('rb_ary_push', recv, arg)
			st = fcall('rb_str_concat', recv, arg)
			oth = rb_funcall(recv, op, arg)
			oth = ce[tmp, :'=', oth] if want_value
			scope.statements << C::If.new(rb_test_class_ary(recv), ar,
						C::If.new(rb_test_class_string(recv), st, oth))
			tmp

		elsif ast.length == 4 and op == '[]'
			tmp = get_new_tmp_var('opt', want_value)
			recv = ast_to_c(ast[1], scope, tmp)
			if not recv.kind_of? C::Variable
				scope.statements << ce[tmp, :'=', recv]
				recv = tmp
			end

			idx = get_new_tmp_var('idx')
			arg = ast_to_c(ast[3], scope, idx)
			if not arg.kind_of? C::Variable
				scope.statements << ce[idx, :'=', arg]
				arg = idx
			end
			idx = ce[[idx], int]

			ar = C::Block.new(scope)
			ar.statements << ce[idx, :'=', [[[arg], int], :>>, [1]]]
			ar.statements << C::If.new(ce[idx, :<, [0]], ce[idx, :'=', [idx, :+, rb_ary_len(recv)]], nil) 
			ar.statements << C::If.new(ce[[idx, :<, [0]], :'||', [idx, :>=, [[rb_ary_len(recv)], int]]],
					ce[tmp, :'=', [[nil.object_id], value]],
					ce[tmp, :'=', rb_ary_ptr(recv, idx)])
			st = C::Block.new(scope)
			st.statements << ce[idx, :'=', [[[arg], int], :>>, [1]]]
			st.statements << C::If.new(ce[idx, :<, [0]], ce[idx, :'=', [idx, :+, rb_str_len(recv)]], nil) 
			st.statements << C::If.new(ce[[idx, :<, [0]], :'||', [idx, :>=, [[rb_str_len(recv)], int]]],
					ce[tmp, :'=', [[nil.object_id], value]],
					ce[tmp, :'=', [[[[rb_str_ptr(recv, idx), :&, [0xff]], :<<, [1]], :|, [1]], value]])
			hsh = ce[tmp, :'=', fcall('rb_hash_aref', recv, arg)]
			oth = ce[tmp, :'=', rb_funcall(recv, op, arg)]
			scope.statements << C::If.new(rb_test_class_hash(recv), hsh,
						C::If.new(ce[[arg, :&, 1], :'&&', rb_test_class_ary(recv)], ar,
						C::If.new(ce[[arg, :&, 1], :'&&', rb_test_class_string(recv)], st, oth)))
			tmp

		elsif ast[1] and ast.length == 3 and op == 'empty?'
			tmp = get_new_tmp_var('opt', want_value)
			recv = ast_to_c(ast[1], scope, tmp)
			if not recv.kind_of? C::Variable
				scope.statements << ce[tmp, :'=', recv]
				recv = tmp
			end

			scope.statements << C::If.new(rb_test_class_ary(recv),
						      C::If.new(rb_ary_len(recv),
								ce[tmp, :'=', [[false.object_id], value]],
								ce[tmp, :'=', [[true.object_id], value]]),
						      ce[tmp, :'=', rb_funcall(recv, op)])
			tmp

		elsif ast[1] and ast.length == 3 and op == 'pop'
			tmp = get_new_tmp_var('opt', want_value)
			recv = ast_to_c(ast[1], scope, tmp)
			if not recv.kind_of? C::Variable
				scope.statements << ce[tmp, :'=', recv]
				recv = tmp
			end

			t = fcall('rb_ary_pop', recv)
			e = rb_funcall(recv, op)
			if want_value
				t = ce[tmp, :'=', t]
				e = ce[tmp, :'=', e]
			end
			scope.statements << C::If.new(rb_test_class_ary(recv), t, e)

			tmp

		elsif not ast[1]
			optimize_call_static(ast, scope, want_value)
		end
	end

	# return ptr, arity
	# ptr is a CExpr pointing to the C func implementing klass#method
	def get_cfuncptr(klass, method)
		ptr = RubyHack.get_method_node_ptr(@klass, method)
		return if ptr == 0
		ftype = RubyHack::NODETYPE[(RubyHack.memory_read_int(ptr) >> 11) & 0xff]
		return if ftype != :cfunc
		fast = RubyHack.read_node(ptr)
		arity = fast[1][:arity]
		fptr = fast[1][:fptr]

		fproto = C::Function.new(value, [])
		case arity
		when -1; fproto.args << C::Variable.new(nil, C::BaseType.new(:int)) << C::Variable.new(nil, C::Pointer.new(value)) << C::Variable.new(nil, value)
		when -2; fproto.args << C::Variable.new(nil, value) << C::Variable.new(nil, value)
		else (arity+1).times { fproto.args << C::Variable.new(nil, value) }
		end

		C::CExpression[[fptr], C::Pointer.new(fproto)]
	end

	# call C funcs directly
	# assume private function calls are not virtual and hardlink them here
	def optimize_call_static(ast, scope, want_value)
		# TODO a = [lol, zor]; foo(*a)
		arity = @klass.instance_method(ast[2]).arity rescue return
		if ast[2].to_s == @meth.to_s
			# self is recursive
			fptr = @cur_cfunc
		else
			fptr = get_cfuncptr(@klass, ast[2])
			return if not fptr
		end

		ret = get_new_tmp_var('ccall', want_value)
		c_arglist = []

		case arity
		when -2
			arg = get_new_tmp_var('arg')
			scope.statements << C::CExpression[arg, :'=', fcall('rb_ary_new')]
			ast[3..-1].each { |a|
				scope.statements << fcall('rb_ary_push', arg, ast_to_c(a, scope))
			}
			c_arglist << rb_self << arg

		when -1
			case ast.length
			when 3	# no args
				argv = C::CExpression[[0], C::Pointer.new(value)]
			when 4	# 1 arg
				argv = get_new_tmp_var('argv')
				val = ast_to_c(ast[3], scope, argv)
				scope.statements << C::CExpression[argv, :'=', val] if argv != val
				argv = C::CExpression[:'&', argv]
			else
				argv = get_new_tmp_var('argv')
				argv.type = C::Array.new(value, ast.length-3)
				ast[3..-1].each_with_index { |a, i|
					val = ast_to_c(a, scope)
					scope.statements << C::CExpression[[argv, :'[]', [i]], :'=', val]
				}
			end
			c_arglist << [ast.length - 3] << argv << rb_self

		else
			c_arglist << rb_self
			ast[3..-1].each { |a|
				va = get_new_tmp_var('arg')
				val = ast_to_c(a, scope, va)
				scope.statements << C::CExpression[va, :'=', val] if val != va
				c_arglist << va
			}
		end

		scope.statements << C::CExpression[ret, :'=', [fptr, :funcall, c_arglist]]
		ret
	end

	def optimize_iter(ast, scope, want_value)
		b_args, b_body, b_recv = ast[1, 3]

		old_ib = @iter_break
		if want_value
			# a new tmpvar, so we can overwrite it in 'break :foo'
			@iter_break = get_new_tmp_var('iterbreak')
		else
			@iter_break = nil
		end

		if b_recv[0] == :call and b_recv[2] == 'reverse_each'
			# convert ary.reverse_each to ary.reverse.each
			b_recv = b_recv.dup
			b_recv[1] = [:call, b_recv[1], 'reverse']
			b_recv[2] = 'each'
		elsif b_recv[0] == :call and b_recv[2] == 'each_key'
			# convert hash.each_key to hash.keys.each
			b_recv = b_recv.dup
			b_recv[1] = [:call, b_recv[1], 'keys']
			b_recv[2] = 'each'
		end

		# loop { }
		if b_recv[0] == :fcall and b_recv[2] == 'loop'
			body = C::Block.new(scope)
			ast_to_c(b_body, body)
			scope.statements << C::For.new(nil, nil, nil, body)

		# int.times { |i| }
		elsif b_recv[0] == :call and b_recv.length == 3 and b_recv[2] == 'times'
			limit = get_new_tmp_var('limit')
			recv = ast_to_c(b_recv[1], scope, limit)
			scope.statements << C::If.new(C::CExpression[:'!', [recv, :&, 1]], rb_raise('only Fixnum#times handled'), nil)
			if want_value
				scope.statements << C::CExpression[@iter_break, :'=', recv]
			end
			scope.statements << C::CExpression[limit, :'=', [recv, :>>, 1]]
			cntr = get_new_tmp_var('cntr')
			cntr.type = C::BaseType.new(:int, :unsigned)
			body = C::Block.new(scope)
			if b_args and b_args[0] == :dasgn_curr
				body.statements << C::CExpression[dvar(b_args[1]), :'=', [[cntr, :<<, 1], :|, 1]]
			end
			ast_to_c(b_body, body)
			scope.statements << C::For.new(C::CExpression[cntr, :'=', [[0], cntr.type]], C::CExpression[cntr, :<, limit], C::CExpression[:'++', cntr], body)

		# ary.each { |e| }
		elsif b_recv[0] == :call and b_recv.length == 3 and b_recv[2] == 'each' and b_args and
				b_args[0] == :dasgn_curr
			ary = get_new_tmp_var('ary')
			recv = ast_to_c(b_recv[1], scope, ary)
			scope.statements << C::CExpression[ary, :'=', recv] if ary != recv
			scope.statements << C::If.new(rb_test_class_ary(ary), nil, rb_raise('only Array#each { |e| } handled'))
			if want_value
				scope.statements << C::CExpression[@iter_break, :'=', ary]
			end
			cntr = get_new_tmp_var('cntr')
			cntr.type = C::BaseType.new(:int, :unsigned)
			body = C::Block.new(scope)
			if b_args and b_args[0] == :dasgn_curr
				body.statements << C::CExpression[dvar(b_args[1]), :'=', [rb_ary_ptr(ary), :'[]', [cntr]]]
			end
			ast_to_c(b_body, body)
			scope.statements << C::For.new(C::CExpression[cntr, :'=', [[0], cntr.type]], C::CExpression[cntr, :<, rb_ary_len(ary)], C::CExpression[:'++', cntr], body)

		# ary.find { |e| }
		elsif b_recv[0] == :call and b_recv.length == 3 and b_recv[2] == 'find' and b_args and
				b_args[0] == :dasgn_curr
			ary = get_new_tmp_var('ary')
			recv = ast_to_c(b_recv[1], scope, ary)
			scope.statements << C::CExpression[ary, :'=', recv] if ary != recv
			scope.statements << C::If.new(rb_test_class_ary(ary), nil, rb_raise('only Array#find { |e| } handled'))
			if want_value
				scope.statements << C::CExpression[@iter_break, :'=', [[nil.object_id], value]]
			end
			cntr = get_new_tmp_var('cntr')
			cntr.type = C::BaseType.new(:int, :unsigned)
			body = C::Block.new(scope)
			if b_args and b_args[0] == :dasgn_curr
				body.statements << C::CExpression[dvar(b_args[1]), :'=', [rb_ary_ptr(ary), :'[]', [cntr]]]
			end
			# same as #each up to this point (except default retval), now add a 'if (body_value) break ary[cntr];'
			# XXX 'find { next true }' 

			found = ast_to_c(b_body, body)
			t = C::Block.new(body)
			t.statements << C::CExpression[@iter_break, :'=', rb_ary_ptr(ary, cntr)]
			t.statements << C::Break.new
			body.statements << C::If.new(rb_test(found, body), t, nil)

			scope.statements << C::For.new(C::CExpression[cntr, :'=', [[0], cntr.type]], C::CExpression[cntr, :<, rb_ary_len(ary)], C::CExpression[:'++', cntr], body)

		# ary.map { |e| }
		elsif b_recv[0] == :call and b_recv.length == 3 and b_recv[2] == 'map' and b_args and
				b_args[0] == :dasgn_curr
			ary = get_new_tmp_var('ary')
			recv = ast_to_c(b_recv[1], scope, ary)
			scope.statements << C::CExpression[ary, :'=', recv] if ary != recv
			scope.statements << C::If.new(rb_test_class_ary(ary), nil, rb_raise('only Array#map { |e| } handled'))
			if want_value
				scope.statements << C::CExpression[@iter_break, :'=', fcall('rb_ary_new')]
			end
			cntr = get_new_tmp_var('cntr')
			cntr.type = C::BaseType.new(:int, :unsigned)
			body = C::Block.new(scope)
			if b_args and b_args[0] == :dasgn_curr
				body.statements << C::CExpression[dvar(b_args[1]), :'=', [rb_ary_ptr(ary), :'[]', [cntr]]]
			end
			# same as #each up to this point (except default retval), now add a '@iter_break << body_value'
			# XXX 'next' unhandled 

			val = ast_to_c(b_body, body)
			body.statements << fcall('rb_ary_push', @iter_break, val)

			scope.statements << C::For.new(C::CExpression[cntr, :'=', [[0], cntr.type]], C::CExpression[cntr, :<, rb_ary_len(ary)], C::CExpression[:'++', cntr], body)

		else
			@iter_break = old_ib
			return
		end

		ret = @iter_break
		@iter_break = old_ib
		ret || nil.object_id
	end
end

# a ruby2c C generator for use in the any ruby interpreter (generates C suitable for use as a standard Ruby extension)
class RubyStaticCompiler < RubyLiveCompiler
	# add a new ruby function to the current @cp
	def self.compile(klass, *methlist)
		@rcp ||= new
		methlist.each { |meth|
			ast = RubyHack.read_node(RubyHack.get_method_node_ptr(klass, meth))
			@rcp.compile(ast, klass, meth) if ast and ast[0] == :scope
		}
		self
	end

	def self.dump
		<<EOS + @rcp.cp.dump_definition('Init_compiledruby')
#ifdef __ELF__
asm .soname 'compiledruby';
asm .pt_gnu_stack rw;
#endif
EOS
	end


	def initialize(cp=nil)
		super(cp)

		@cp.parse <<EOS
// static VALUE method(VALUE self, VALUE arg0, VALUE arg1) { return (VALUE)0; }
// static int intern_Lol;
static void do_init_once(void) {
	VALUE class;

	// intern_lol = rb_intern("Lol");
	// class = rb_const_get(*rb_cObject, intern_Lol);
	// rb_define_method(class, "method", method, 2);
}

int Init_compiledruby(void) __attribute__((export)) { 
	// use a separate func to avoid having to append statements before the 'return'
	do_init_once();
	return 0;
}
EOS
		# current value of the 'class' variable (avoid consecutive search of Foo::Bar::Baz)
		@init_scope_class_value = nil
	end

	def compile(ast, klass, method)
		@compiled_func_cache ||= {}

		mname = super(ast, klass, method)

		@compiled_func_cache[[klass, method.to_s]] = @cur_cfunc

		init = @cp.toplevel.symbol['do_init_once'].initializer
		var = init.symbol['class']
		if @init_scope_class_value == klass
			cls = var
		else
			cls = C::CExpression[:'*', @cp.toplevel.symbol['rb_cObject']]
			klass.name.split('::').each { |n|
				init.statements << C::CExpression[var, :'=', fcall('rb_const_get', cls, rb_intern(n))]
				cls = var
			}
			@init_scope_class_value = klass
		end
		
		init.statements << fcall('rb_define_method', cls, method.to_s, @cur_cfunc, klass.instance_method(method).arity)

		mname
	end

	def declare_newtopvar(name)
		v = C::Variable.new(name, value)
		@cp.toplevel.symbol[v.name] = v
		pos = @cp.toplevel.statements.index @cp.toplevel.statements.find { |st|
			st.kind_of? C::Declaration and st.var.type.kind_of? C::Function and st.var.initializer
		} || -1
		@cp.toplevel.statements.insert pos, C::Declaration.new(v)
		v
	end

	def rb_intern(sym)
		n = escape_varname("intern_#{sym}")
		if not v = @cp.toplevel.symbol[n]
			v = declare_newtopvar(n)
			v.type = C::BaseType.new(:int, :unsigned)
			v.storage = :static
			@cp.toplevel.symbol['do_init_once'].initializer.statements << C::CExpression[v, :'=', fcall('rb_intern', sym.to_s)]
		end
		v
	end

	def rb_cstget(cname)
		fcall('rb_const_get', C::CExpression[:*, @cp.toplevel.symbol['rb_cObject']], rb_intern(cname))
	end

	def rb_raise(reason)
		fcall('rb_raise', C::CExpression[:*, @cp.toplevel.symbol['rb_eRuntimeError']], reason)
	end

	def get_cfuncptr(klass, method)
		# is it a func we have in the current cparser ?
		if ptr = @compiled_func_cache[[klass, method.to_s]]
			return ptr
		end

		# check if it's a C or ruby func in the current interpreter
		ptr = RubyHack.get_method_node_ptr(@klass, method)
		return if ptr == 0
		ftype = RubyHack::NODETYPE[(RubyHack.memory_read_int(ptr) >> 11) & 0xff]
		return if ftype != :cfunc

		# ok, so assume it will be the same next time
		n = escape_varname "fptr_#{klass.name}##{method}".gsub('::', '_')
		if not v = @cp.toplevel.symbol[n]
			v = get_cfuncptr_dyn(klass, method, n)
		end

		v
	end

	def get_cfuncptr_dyn(klass, method, n)
		arity = klass.instance_method(method).arity
		fproto = C::Function.new(value, [])
		case arity
		when -1; fproto.args << C::Variable.new(nil, C::BaseType.new(:int)) << C::Variable.new(nil, C::Pointer.new(value)) << C::Variable.new(nil, value)
		when -2; fproto.args << C::Variable.new(nil, value) << C::Variable.new(nil, value)
		else (arity+1).times { fproto.args << C::Variable.new(nil, value) }
		end

		v = declare_newtopvar(n)
		v.type = C::Pointer.new(fproto)
		v.storage = :static

		init = @cp.toplevel.symbol['do_init_once'].initializer
		if not ptr = init.symbol['ptr']
			ptr = C::Variable.new('ptr', C::Pointer.new(C::BaseType.new(:int)))
			init.symbol[ptr.name] = ptr
			init.statements << C::Declaration.new(ptr)
		end

		var = init.symbol['class']
		if @init_scope_class_value == klass
			cls = var
		else
			cls = C::CExpression[:'*', @cp.toplevel.symbol['rb_cObject']]
			klass.name.split('::').each { |n|
				init.statements << C::CExpression[var, :'=', fcall('rb_const_get', cls, rb_intern(n))]
				cls = var
			}
			@init_scope_class_value = klass
		end
		init.statements << C::CExpression[ptr, :'=', fcall('rb_method_node', cls, rb_intern(method))]

		# dynamically recheck that klass#method is a :cfunc
		cnd = C::CExpression[[[[ptr, :'[]', [0]], :>>, [11]], :&, [0xff]], :'!=', [RubyHack::NODETYPE.index(:cfunc)]]
		init.statements << C::If.new(cnd, rb_raise("CFunc expected at #{klass}##{method}"), nil)

		init.statements << C::CExpression[v, :'=', [[ptr, :'[]', [1]], v.type]]

		v
	end

	if defined? $trace_rbfuncall and $trace_rbfuncall
	# dynamic trace of all rb_funcall made from our module
	def rb_funcall(recv, meth, *args)
		if not defined? @rb_fcid
			@rb_fcid = -1
			@cp.parse 'int atexit(void(*)(void)); int printf(char*, ...); static unsigned rb_fcid_max = 1; static unsigned rb_fcntr[1]; ' +
				'static void rb_fcstat(void) { for (unsigned i=0; i<rb_fcid_max; ++i) if (rb_fcntr[i]) printf("%u %u\\n", i, rb_fcntr[i]); }'
			@rb_fcntr = @cp.toplevel.symbol['rb_fcntr']
			@rb_fcid_max = @cp.toplevel.symbol['rb_fcid_max']
			@cp.toplevel.symbol['do_init_once'].initializer.statements << fcall('atexit', @cp.toplevel.symbol['rb_fcstat'])
		end
		@rb_fcid += 1
		@rb_fcid_max.initializer = C::CExpression[[@rb_fcid+1], @rb_fcid_max.type]
		@rb_fcntr.type.length = @rb_fcid+1

		ctr = C::CExpression[:'++', [@rb_fcntr, :'[]', [@rb_fcid]]]
		C::CExpression[ctr, :',', super(recv, meth, *args)]
	end
	end
end
end




if __FILE__ == $0

demo = ARGV.empty? ? :test_jit : ARGV.first == 'asm' ? :inlineasm : ARGV.first == 'generate' ? :generate_persistent : :compile_ruby

case demo	# chose your use case !
when :inlineasm
	# cnt.times { sys_write str }
	src_asm = <<EOS
mov ecx, [ebp+8]
again:
push ecx
mov eax, 4
mov ebx, 1
mov ecx, [ebp+12]
mov edx, [ebp+16]
int 80h
pop ecx
loop again
EOS

	src = <<EOS
#{Metasm::RubyLiveCompiler::RUBY_H}

void doit(int, char*, int);
VALUE foo(VALUE self, VALUE count, VALUE str) {
	doit(VAL2INT(count), STR_PTR(str), STR_LEN(str));
	return count;
}

void doit(int count, char *str, int strlen) { asm(#{src_asm.inspect}); }
EOS

	m = Metasm::RubyHack.compile_c(src).encoded

	o = Object.new
	Metasm::RubyHack.set_object_method_binary(o, 'bar', m, 2)

	puts "test1"
	o.bar(4, "blabla\n")

	puts "test2"
	o.bar(2, "foo\n")


when :compile_ruby
	abort 'need <class> <method>' if ARGV.length != 2
	c = Metasm.const_get(ARGV.shift)
	m = ARGV.shift
	ptr = Metasm::RubyHack.get_method_node_ptr(c, m)
	ast = Metasm::RubyHack.read_node(ptr)
	require 'pp'
	pp ast
	c = Metasm::RubyHack.ruby_ast_to_c(ast, c, m)
	puts c


when :test_jit
	class Foo
		def bla(x=500)
			i = 0
			x.times { i += 16 }
			i
		end
	end

	t0 = Time.now
	Metasm::RubyHack.compile_ruby(Foo, :bla)
	t1 = Time.now
	ret = Foo.new.bla(0x401_0000)
	puts ret.to_s(16), ret.class
	t2 = Time.now

	puts "compile %.3fs  run %.3fs" % [t1-t0, t2-t1]

when :generate_persistent
	c_src = Metasm::RubyStaticCompiler.compile(Metasm::Preprocessor, :getchar, :ungetchar, :unreadtok, :readtok_nopp_str, :readtok_nopp, :readtok).dump
	File.open('compiledruby.c', 'w') { |fd| fd.puts c_src } if $VERBOSE
	puts 'compiling..'
	# To encode to a different file, you must also rename the Init_compliedruby() function to match the lib name
	Metasm::ELF.compile_c(Metasm::Ia32.new, c_src).encode_file('compiledruby.so')
	puts 'ruby -r metasm -r compiledruby ftw'
end

end
