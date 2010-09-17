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
	RUBY_H = <<EOS
#{DynLdr::RUBY_H}

VALUE rb_iv_get(VALUE, char*);
VALUE rb_iv_set(VALUE, char*, VALUE);
VALUE rb_ivar_defined(VALUE, int);
VALUE rb_cvar_get(VALUE, int);
VALUE rb_cvar_set(VALUE, int, VALUE, int);
VALUE rb_gvar_get(char*);
VALUE rb_gvar_set(char*, VALUE);

VALUE rb_ary_new(void);
VALUE rb_ary_new4(long, VALUE*);
VALUE rb_ary_push(VALUE, VALUE);
VALUE rb_hash_new(void);
VALUE rb_hash_aset(VALUE, VALUE, VALUE);
VALUE rb_str_new(char*, int);
VALUE rb_str_new2(char*);
VALUE rb_str_cat2(VALUE, char*);
VALUE rb_str_append(VALUE, VALUE);
VALUE rb_obj_as_string(VALUE);
VALUE rb_range_new(VALUE, VALUE, int exclude_end);
VALUE rb_Array(VALUE);	// :splat
VALUE rb_ary_to_ary(VALUE);
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
	new_api_c 'void *rb_method_node(uintptr_t, int id)'

class << self
	def set_class_method_raw(klass, meth, code, nparams)
		memory_perm(str_ptr(code), code.length, 'rwx')
		rb_define_method(rb_obj_to_value(klass), meth, code, nparams)
	end

	def get_method_node_ptr(klass, meth)
		raise if not klass.kind_of? Class
		rb_method_node(rb_obj_to_value(klass), meth.to_sym.to_int)
	end

	# sets up rawopcodes as the method implementation for class klass
	# rawopcodes must implement the expected ABI or things will break horribly
	# this method is VERY UNSAFE, and breaks everything put in place by the ruby interpreter
	# use with EXTREME CAUTION
	# nargs  arglist
	# -2     self, arg_ary
	# -1     argc, VALUE*argv, self
	# >=0    self, arg0, arg1..
	def set_method_binary(klass, methodname, raw, nargs=-2)
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
			[type, {:fptr => v1,	# c func pointer
				:arity => v2}]
		when :scope
			[type, {:localnr => (v1 != 0 ? memory_read_int(v1) : 0),	# nr of local vars (+2 for $_/$~)
				:cref => v2},	# node, starting point for const resolution
				read_node(v3)]
		when :call, :fcall, :vcall
			# TODO check fcall/vcall
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
		when :case, :when
			[type, read_node(v1), read_node(v2), read_node(v3)]
		when :iter
			# save a block for the following funcall
			args = read_node(v1)	# assignments with nil, not realized, just to store the arg list (multi args -> :masgn)
			body = read_node(v2)	# the body statements (multi -> :block)
			subj = read_node(v3)	# the stuff which is passed the block, probably a :call
			[type, args, body, subj]
		when :while
			[type, read_node(v1), read_node(v2), v3]
		when :return, :break, :next, :defined
			[type, read_node(v1)]
		when :to_ary
			[type, read_node(v1)]
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
		ptr = get_method_node_ptr(klass, meth)
		ast = read_node(ptr)
		require 'pp'
		pp ast
		return if not c = ruby_ast_to_c(ast)
		puts c
		raw = compile_c(c).encoded
		set_method_binary(klass, meth, raw, klass.instance_method(meth).arity)
	end

	def ruby_ast_to_c(ast)
		return if ast[0] != :scope
		cp = host_cpu.new_cparser
		cp.parse RUBY_H
		cp.parse 'void meth(VALUE self) { }'
		cp.toplevel.symbol['meth'].type.type = cp.toplevel.symbol['VALUE']	# return type = VALUE, avoid 'missing return statement' warning
		RubyCompiler.new(cp).compile(ast, cp.toplevel.symbol['meth'])
		cp.dump_definition('meth')
	end
end
end

class RubyCompiler
	class Fail < RuntimeError
	end

	def initialize(cp)
		@cp = cp
	end

	def compile(ast, func)
		# TODO func args (incl varargs etc)
		# TODO handle arbitrary block/yield constructs
		# TODO analyse to find/optimize numeric locals that never need a ruby VALUE (ie native int vs INT2FIX)
		# TODO detect block/closure exported out of the func & abort compilation

		@scope = func.initializer

		if ast[0] == :scope and ast[2] and ast[2][0] == :block and ast[2][1] and ast[2][1][0] == :args
			compile_args(func, ast[2][1])
		end
		ret = ast_to_c(ast[2], @scope)

		@scope.statements << C::Return.new(ret)
	end

	def compile_args(func, args)
		if args[1] == 0 and (args[2] or args[3])
			compile_args_m1(func, args)
		elsif args[1] > 0 and (args[2] or args[3])
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

	# create a C::CExpr[toplevel.symbol[name], :funcall, args]
	# casts int/strings in arglist to CExpr
	def fcall(fname, *arglist)
		args = arglist.map { |a| (a.kind_of?(Integer) or a.kind_of?(String)) ? [a] : a }
		C::CExpression[@cp.toplevel.symbol[fname], :funcall, args]
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

	# retrieve or create a local var
	# pass :none to avoid initializer
	def get_var(name, initializer=:none)
		name = name.gsub(/[^\w]/) { |c| c.unpack('H*')[0] }
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
		get_var("intern_#{n}", fcall('rb_intern', n))
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
		C::CExpression[[[expr, :>, [7]], :'&&', [[expr, :&, [3]], :==, [0]]], :'&&', [rb_cast_pvalue(expr, 0), :'==', [type]]]
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
			l = local(ast[1], :none)
			st = ast_to_c(ast[2], scope, l)
			scope.statements << C::CExpression[l, :'=', st] if st != l
			l
		when :dvar
			dvar(ast[1])
		when :dasgn_curr
			l = dvar(ast[1], :none)
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
			fcall('rb_gvar_get', ast[1])
		when :gasgn
			if want_value
				tmp = get_new_tmp_var("gvar_#{ast[1]}", want_value)
				scope.statements << C::CExpression[tmp, :'=', ast_to_c(ast[2], scope)]
				scope.statements << fcall('rb_gvar_set', ast[1], tmp)
				tmp
			else
				scope.statements << fcall('rb_gvar_set', ast[1], ast_to_c(ast[2], scope))
			end

		when :rb2cvar	# hax, used in vararg parsing
			get_var(ast[1], :none)

		when :lit
			case ast[1]
			when Symbol
				# XXX ID2SYM
				C::CExpression[[rb_intern(ast[1].to_s), :<<, 8], :|, 0xe]
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

		when :if
			cnd = rb_test(ast_to_c(ast[1], scope), scope)

			tbdy = C::Block.new(scope)
			thn = ast_to_c(ast[2], tbdy, want_value)
			ebdy = C::Block.new(scope) if ast[3]
			els = ast_to_c(ast[3], ebdy, want_value)

			scope.statements << C::If.new(cnd, tbdy, ebdy)

			if want_value
				tmp = get_new_tmp_var('if', want_value)
				tbdy.statements << C::CExpression[tmp, :'=', thn] if tmp != thn
				ebdy.statements << C::CExpression[tmp, :'=', els] if ast[3] and tmp != els
				tmp
			end
		when :and
			tmp = get_new_tmp_var('and', want_value)
			scope.statements << C::CExpression[tmp, :'=', ast_to_c(ast[1], scope)]
			t = C::Block.new(scope)
			t.statements << C::CExpression[tmp, :'=', ast_to_c(ast[2], t)]
			scope.statements << C::If.new(rb_test(tmp, scope), t, nil)
			tmp
		when :or
			tmp = get_new_tmp_var('or', want_value)
			scope.statements << C::CExpression[tmp, :'=', ast_to_c(ast[1], scope)]
			t = C::Block.new(scope)
			e = C::Block.new(scope)
			e.statements << C::CExpression[tmp, :'=', ast_to_c(ast[2], e)]
			scope.statements << C::If.new(rb_test(tmp, scope), t, e)
			tmp
		when :not
			tmp = get_new_tmp_var('not', want_value)
			scope.statements << C::CExpression[tmp, :'=', ast_to_c(ast[1], scope)]
			t = C::CExpression[tmp, :'=', [[false.object_id], value]]
			e = C::CExpression[tmp, :'=', [[true.object_id], value]]
			scope.statements << C::If.new(rb_test(tmp, scope), t, e)
			tmp
		when :return
			scope.statements << C::Return.new(ast_to_c(ast[1], scope))
			nil.object_id
		when :break
			if @iter_break ||= nil
				v = (ast[1] ? ast_to_c(ast[1], scope, @iter_break) : nil.object_id)
				scope.statements << C::CExpression[@iter_break, :'=', [v]] if @iter_break != v
			end
			scope.statements << C::Break.new
			nil.object_id

		when nil, :args
			nil.object_id
		when :nil
			nil.object_id
		when :false
			false.object_id
		when :true
			true.object_id
		when :const
			fcall('rb_const_get', rb_selfclass, rb_intern(ast[1]))
		when :colon3
			# XXX rb_cObj need indirection when compiled in an ELF
			fcall('rb_const_get', @cp.toplevel.symbol['rb_cObject'], rb_intern(ast[1]))
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
		else
			raise Fail, "unsupported #{ast.inspect}"
		end

		if want_value
			ret = C::CExpression[[ret], value] if ret.kind_of? Integer or ret.kind_of? String
			ret
		end
	end

	# optional optimization of a call (eg a == 1, c+2, ...)
	# return nil for normal rb_funcall, or C::CExpr to use as retval.
	def optimize_call(ast, scope, want_value)
		if ast.length == 4 and ast[3][0] == :lit and ast[3][1].kind_of? Fixnum
			# optimize 'x==42', 'x+42', 'x-42'
			op = ast[2]
			o2 = ast[3][1]
			return if not %w[== > < >= <= + -].include? op
			if o2 < 0 and ['+', '-'].include? op
				# need o2 >= 0 for overflow detection
				op = {'+' => '-', '-' => '+'}[op]
				o2 = -o2
				return if not o2.kind_of? Fixnum	# -0x40000000
			end

			ce = C::CExpression
			int = C::BaseType.new(:ptr)	# signed VALUE
			int_v = o2.object_id
			recv = ast_to_c(ast[1], scope)
			case op
			when '=='
				# XXX assume == only return true for full equality: if not Fixnum, then always false
				# which breaks 1.0 == 1 and maybe others, but its ok
				tmp = get_new_tmp_var('opt', want_value)
				scope.statements << C::If.new(ce[recv, :'==', [int_v]], ce[tmp, :'=', [true.object_id]], ce[tmp, :'=', [false.object_id]])
				tmp
			when '>', '<', '>=', '<='
				tmp = get_new_tmp_var('opt', want_value)
				# do the actual comparison on signed >>1 if both Fixnum
				t = C::If.new(
					ce[[[[recv], int], :>>, 1], op.to_sym, [[[int_v], int], :>>, 1]],
					ce[tmp, :'=', [true.object_id]],
					ce[tmp, :'=', [false.object_id]])
				# fallback to actual rb_funcall
				e = ce[tmp, :'=', rb_funcall(recv, op, o2.object_id)]
				scope.statements << C::If.new(ce[recv, :&, 1], t, e)
				tmp
			when '+'
				tmp = get_new_tmp_var('opt', want_value)
				e = ce[recv, :+, [int_v-1]]
				# check overflow to Bignum
				cnd = ce[[recv, :&, [1]], :'&&', [[[recv], int], :<, [[e], int]]]
				t = ce[tmp, :'=', e]
				e = ce[tmp, :'=', rb_funcall(recv, op, o2.object_id)]
				scope.statements << C::If.new(cnd, t, e)
				tmp
			when '-'
				tmp = get_new_tmp_var('opt', want_value)
				e = ce[recv, :-, [int_v-1]]
				# check overflow to Bignum
				cnd = ce[[recv, :&, [1]], :'&&', [[[recv], int], :>, [[e], int]]]
				t = ce[tmp, :'=', e]
				e = ce[tmp, :'=', rb_funcall(recv, op, o2.object_id)]
				scope.statements << C::If.new(cnd, t, e)
				tmp
			end
		end
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
				body.statements << C::CExpression[dvar(b_args[1], :none), :'=', [[cntr, :<<, 1], :|, 1]]
			end
			ast_to_c(b_body, body)
			scope.statements << C::For.new(C::CExpression[cntr, :'=', [0]], C::CExpression[cntr, :<, limit], C::CExpression[:'++', cntr], body)

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
				body.statements << C::CExpression[dvar(b_args[1], :none), :'=', [rb_ary_ptr(ary), :'[]', [cntr]]]
			end
			ast_to_c(b_body, body)
			scope.statements << C::For.new(C::CExpression[cntr, :'=', [0]], C::CExpression[cntr, :<, rb_ary_len(ary)], C::CExpression[:'++', cntr], body)

		# ary.find { |e| }
		elsif b_recv[0] == :call and b_recv.length == 3 and b_recv[2] == 'find' and b_args and
				b_args[0] == :dasgn_curr
			ary = get_new_tmp_var('ary')
			recv = ast_to_c(b_recv[1], scope, ary)
			scope.statements << C::CExpression[ary, :'=', recv] if ary != recv
			scope.statements << C::If.new(rb_test_class_ary(ary), nil, rb_raise('only Array#find { |e| } handled'))
			if want_value
				scope.statements << C::CExpression[@iter_break, :'=', nil.object_id]
			end
			cntr = get_new_tmp_var('cntr')
			cntr.type = C::BaseType.new(:int, :unsigned)
			body = C::Block.new(scope)
			if b_args and b_args[0] == :dasgn_curr
				body.statements << C::CExpression[dvar(b_args[1], :none), :'=', [rb_ary_ptr(ary), :'[]', [cntr]]]
			end
			# same as #each up to this point (except default retval), now add a 'if (body_value) break ary[cntr];'
			# XXX 'find { next true }' 

			found = ast_to_c(b_body, body)
			t = C::Block.new(body)
			t.statements << C::CExpression[@iter_break, :'=', rb_ary_ptr(ary, cntr)]
			t.statements << C::Break.new
			body.statements << C::If.new(rb_test(found, body), t, nil)

			scope.statements << C::For.new(C::CExpression[cntr, :'=', [0]], C::CExpression[cntr, :<, rb_ary_len(ary)], C::CExpression[:'++', cntr], body)

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
				body.statements << C::CExpression[dvar(b_args[1], :none), :'=', [rb_ary_ptr(ary), :'[]', [cntr]]]
			end
			# same as #each up to this point (except default retval), now add a '@iter_break << body_value'
			# XXX 'next' unhandled 

			val = ast_to_c(b_body, body)
			body.statements << fcall('rb_ary_push', @iter_break, val)

			scope.statements << C::For.new(C::CExpression[cntr, :'=', [0]], C::CExpression[cntr, :<, rb_ary_len(ary)], C::CExpression[:'++', cntr], body)

		# hash.each { |k, v| }
		elsif false and b_recv[0] == :call and b_recv.length == 3 and b_recv[2] == 'each' and b_args and
				b_args[0] == :masgn and b_args[1][0] == :array and b_args[1].length == 3 and not b_args[2]

		else
			@iter_break = old_ib
			return
		end

		ret = @iter_break
		@iter_break = old_ib
		ret || nil.object_id
	end
end
end




if __FILE__ == $0

demo = ARGV.empty? ? :test_jit : ARGV.first == 'asm' ? :inlineasm : :compile_ruby

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
#{Metasm::RubyHack::RUBY_H}

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
	c = Metasm::RubyHack.ruby_ast_to_c(ast)
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

end

end
