require 'test/unit'
require 'metasm/preprocessor'


# BEWARE OF TEH RUBY PARSER
# use single-quoted source strings
class TestPreproc < Test::Unit::TestCase
	def load txt
		p = Metasm::Preprocessor.new
		p.feed txt
		p
	end

	def test_gettok
		p = load <<'EOS'
test boo
" bla bla \"\\"   \
xx
EOS
		assert_equal \
		['test', :space, ' ', :string, :eol, :quoted, :space, 'xx', :eol, true],
		[p.readtok.raw, p.nexttok.type, p.readtok.raw, p.readtok.type, p.readtok.type, p.readtok.type, p.readtok.type, p.readtok.raw, p.readtok.type, p.eos?]
	end

	def test_comment
		p = load <<'EOS'
foo /* bar * /*/ baz
kikoo // lol \
asv
EOS
		toks = []
		p.skip_space_eol
		until p.eos?
			toks << p.readtok.raw
			p.skip_space_eol
		end
		assert_equal %w[foo baz kikoo], toks
	end

	def test_preproc
		# ignores eol/space at begin/end
		t_preparse = proc { |text, result|
			p = load text
			txt = ''
			txt << p.readtok.raw until p.eos?
			assert_equal(result, txt.strip)
		}
		t_preparse[<<EOS, '']
#if 0  // test # as first char
toto
#endif
EOS
		t_preparse[<<EOS, 'coucou']
#define tutu
#if defined ( tutu )
coucou
#endif
EOS
		t_preparse['a #define b', 'a #define b']
		t_preparse[<<EOS, "// true !\nblu"]
#ifdef toto // this is false
bla
#elif .2_3e-4 > 2 /* this one too */
blo
#elif (1+1)*2 > 2 // true !
blu
#elif 4 > 2 // not you
ble
#else
bli
#endif
EOS
		t_preparse[<<'EOS', 'ab#define x']
a\
b\
#define x
EOS
		p = load('__LINE__')
		assert_equal('0', p.readtok.value)
		t_preparse[<<EOS, 'toto 1 toto 12 toto 3+(3-2) otot hoho']
#define azer(k) 12
# define xxx azer(7)
#define macro(a, b, c) toto a toto b toto c otot
macro(1, xxx, 3+(3-2)) hoho
EOS
		t_preparse[<<EOS, 'c']
#define a b
#define d c
#define c d
#define b c
a
EOS
		t_preparse[<<EOS, 'b']
#define b c
#define a b
#undef b
a
EOS
		t_preparse[<<EOS, 'toto tutu']
#define toto() abcd
toto tutu
EOS
		t_preparse[<<EOS, '"haha"']
#define d(a) #a
d(haha)
EOS
		Metasm::Preprocessor.include_search_path << '.'
		begin
			File.open('tests/prepro_testinclude.asm', 'w') { |fd| fd.puts '#define out in' }
			t_preparse[<<EOS, 'in']
#include <tests/prepro_testinclude.asm>
out
EOS
		ensure
			File.unlink('tests/prepro_testinclude.asm') rescue nil
		end

		p = load <<EOS
#define cct(a, b) a ## _ ## b
cct(toto, tutu)
EOS
		p.skip_space_eol
		assert_equal('toto_tutu', p.readtok.raw)	# check we get only 1 token back

		t_preparse[<<EOS, <<EOS]
#define va1(a, b...) toto(a, ##b)
#define va2(a, b...) toto(a. ##b)
#define va3(a, ...)  toto(a, __VA_ARGS__)
va1(1, 2);
va1(1,2);
va1(1);
va2(1, 2);
va2(1);
va3(1, 2);
va3(1);
EOS
toto(1, 2);
toto(1,2);
toto(1);
toto(1. 2);
toto(1.);
toto(1, 2);
toto(1, );
EOS
	end

	def test_errors
		test_err = proc { |txt| assert_raise(Metasm::ParseError) { load(txt).readtok } }
		test_err["\"abc\n\""]
		test_err['"abc\x"']
		test_err['/*']
		test_err['#if 0']
		test_err["#if 0.\n#end"]
		test_err["#if 0.3e\n#end"]
		test_err["#define toto(tutu,"]
		test_err["#define toto( (tutu, tata)"]
		test_err['#error bla']
		test_err[<<EOS]
#if 0
#elif 1
#else
#if 2
#endif
EOS
		test_err[<<EOS]
#define abc(def)
abc (1, 3)
EOS
		test_err[<<EOS]
#define a
#define a
EOS
		test_err['#define a(b) #c']
	end
end

