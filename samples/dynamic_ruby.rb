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

// TODO
VALUE rb_new_ary(char*);
VALUE rb_new_hash(char*);
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
			[type, {:localnr => memory_read_int(v1),	# nr of local vars (+2 for $_/$~)
				:cref => v2},	# node, starting point for const resolution
				read_node(v3)]
		when :call, :dstr, :fcall, :vcall
			# TODO check fcall/vcall
			ret = [type, read_node(v1), v2.id2name]
			if args = read_node(v3)
				raise "#{ret.inspect} with args != array: #{args.inspect}" if args[0] != :array
				ret.concat args[1..-1]
			end
			ret
		when :zarray
			[:array, []]
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
			[type, v1, read_node(v2), v3]
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
		cp.toplevel.symbol['meth'].type.type = cp.toplevel.symbol['VALUE']
		scope = cp.toplevel.symbol['meth'].initializer
		RubyCompiler.new(cp).compile(ast, scope)
		cp.dump_definition('meth')
	end
end
end

class RubyCompiler
	def initialize(cp)
		@cp = cp
	end

	def compile(ast, scope)
		@scope = scope
		ast[1][:localnr].times { |lnr|
			next if lnr < 2	# TODO check usage of $~ / $_
			# TODO args
			# TODO analyse to find numeric locals (to avoid useless INT2FIX)
			l = C::Variable.new("local_#{lnr}", value)
			l.initializer = C::CExpression[[nil.object_id], l.type]
			scope.symbol[l.name] = l
			scope.statements << C::Declaration.new(l)
		}
		scope.statements << C::Return.new(ast_to_c(ast[2], scope))
	end

	def fcall(fname, *arglist)
		args = arglist.map { |a| (a.kind_of?(Integer) or a.kind_of?(String)) ? [a] : a }
		C::CExpression[@cp.toplevel.symbol[fname], :funcall, args]
	end

	def value
		@cp.toplevel.symbol['VALUE']
	end

	def local(n)
		@scope.symbol["local_#{n}"]
	end

	def rb_self
		@scope.symbol['self']
	end

	def rb_intern(n)
		fcall('rb_intern', n)
	end

	def rb_funcall(recv, meth, *args)
		fcall('rb_funcall', recv, rb_intern(meth), args.length, *args)
	end

	def ast_to_c(ast, scope)
		ret = 
		case ast.to_a[0]
		when :block
			ast[1..-1].map { |a| ast_to_c(a, scope) }.last
		when :lasgn
			l = local(ast[1])
			scope.statements << C::CExpression[l, :'=', ast_to_c(ast[2], scope)]
			l
		when :lvar
			local(ast[1])
		when :lit
			case ast[1]
			when Symbol
				rb_intern(ast[1].to_s.inspect)
			else	# true/false/nil/fixnum
				ast[1].object_id
			end
		when :self
			rb_self
		when :str
			fcall('rb_str_new', ast[1], ast[1].length)
		when :ivar
			fcall('rb_iv_get', rb_self, ast[1])
		when :iasgn
			tmp = C::Variable.new('itmp', value)
			if not scope.symbol_ancestors['itmp']
				scope.symbol['itmp'] = tmp
				scope.statements << C::Declaration.new(tmp)
			end
			scope.statements << C::CExpression[tmp, :'=', ast_to_c(ast[2], scope)]
			scope.statements << fcall('rb_iv_set', rb_self, ast[1], tmp)
			tmp
		when :iter
			b_args, b_body, b_recv = ast[1, 3]
			if b_recv[0] == :call and b_recv[2] == 'times'	# TODO check its Fixnum#times
				recv = ast_to_c(b_recv[1], scope)
				cntr = C::Variable.new("cntr", C::BaseType.new(:int))	# TODO uniq name etc
				cntr.initializer = C::CExpression[[0]]
				init = C::Block.new(scope)
				init.symbol[cntr.name] = cntr
				body = C::Block.new(init)
				scope.statements << C::For.new(init, C::CExpression[cntr, :<, [recv, :>>, 1]], C::CExpression[:'++', cntr], body)
				body.symbol[cntr.name] = cntr
				ast_to_c(b_body, body)
				recv
			else
				puts "unsupported iter #{ast.inspect}"
				nil.object_id
			end
		when :call
			f = rb_funcall(ast_to_c(ast[1], scope), ast[2], *ast[3..-1].map { |a| ast_to_c(a, scope) })
			case ast[2]
			when '+', '-'
				tmp = C::Variable.new('tmp', value)
				if not scope.symbol_ancestors['tmp']
					scope.symbol['tmp'] = tmp
					scope.statements << C::Declaration.new(tmp)
				end
				a1 = [ast_to_c(ast[1], scope), C::BaseType.new(:int)]
				a3 = [ast_to_c(ast[3], scope), C::BaseType.new(:int)]
				scope.statements <<
				C::If.new(C::CExpression[[a1, :&, a3], :&, 1],	# XXX overflow to Bignum
					  C::CExpression[tmp, :'=', [a1, ast[2].to_sym, [a3, :-, [1]]]],
					  C::CExpression[tmp, :'=', f])
				tmp
			else
				f
			end
		when :vcall, :fcall
			# function, no explicit receiver (ie can be a private method)
			# vcall = no args, fcall = args?
			rb_funcall(rb_self, ast[2], *ast[3..-1].map { |a| ast_to_c(a, scope) })
		when :if
			# XXX 'tmp' reuse/reentry
			tmp = C::Variable.new('tmp', value)
			if not scope.symbol_ancestors['tmp']
				scope.symbol['tmp'] = tmp
				scope.statements << C::Declaration.new(tmp)
			end

			cnd = ast_to_c(ast[1], scope)
			cnd = C::CExpression[[cnd, :'!=', nil.object_id], :'&&', [cnd, :'!=', false.object_id]]

			tbdy = C::Block.new(scope)
			thn = ast_to_c(ast[2], tbdy)
			tbdy.statements << C::CExpression[tmp, :'=', thn]
			ebdy = C::Block.new(scope)
			els = ast_to_c(ast[3], ebdy)
			tbdy.statements << C::CExpression[tmp, :'=', els]
			scope.statements << C::If.new(cnd, tbdy, ebdy)
			tmp
		when :and
			C::CExpression[ast_to_c(ast[1], scope), :'&&', ast_to_c(ast[2], scope), C::BaseType.new(:int)]
		when :or
			C::CExpression[ast_to_c(ast[1], scope), :'||', ast_to_c(ast[2], scope), C::BaseType.new(:int)]
		when :not
			C::CExpression[:'!', ast_to_c(ast[1], scope)]
		when nil, :args
			nil.object_id
		when :nil, :true, :false
			ast[0].object_id
		when :const
			# XXX NilClass..
			mycls = C::CExpression[[rb_self, C::Pointer.new(@cp.toplevel.struct['rb_string_t'])], :'->', 'klass']
			fcall('rb_const_get', mycls, rb_intern(ast[1]))
		when :array
			# TODO
			#fcall('rb_new_ary')
			#ast[1..-1].each { |e|
			#	ary.concat e
			#}
			scope.statements << fcall('rb_new_ary', ast.inspect)
			nil.object_id
		when :hash
			#fcall('rb_new_hash')
			#k = nil
			#ast[1..-1].each { |e|
			#	if not k
			#		k = e
			#	else
			#		h.assoc[k, e]
			#		k = nil
			#	end
			#}
			scope.statements << fcall('rb_new_hash', ast.inspect)
			nil.object_id
		when :dstr
			#fcall('rb_str_new')
			#rb_str_cat(str, ast[1])
			#ast[3..-1].each { |s| rb_str_cat(str, s) }
			C::CExpression[ast.inspect]
		when :defined
			case ast[1][0]
			when :ivar
				p ast[1][1]
				fcall('rb_ivar_defined', rb_self, rb_intern(ast[1][1]))
			else 
				puts "unsupported defined? #{ast.inspect}"
				fcall('rb_iv_defined', ast[1].inspect)
			end
		#when :masgn # parallel assignment
		else
			puts "unsupported #{ast.inspect}"
			nil.object_id
		end
		ret = [ret] if ret.kind_of? Integer or ret.kind_of? String
		C::CExpression[ret, value]
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
		def bla
			i = 0
			20_000_000.times { i += 1 }
			i
		end
	end

	t0 = Time.now
	Metasm::RubyHack.compile_ruby(Foo, :bla)
	t1 = Time.now
	p Foo.new.bla
	t2 = Time.now

	puts "compile %.3fs  run %.3fs" % [t1-t0, t2-t1]

end

end
