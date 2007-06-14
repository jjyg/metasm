require 'test/unit'
require 'metasm/preprocessor'


# BEWARE OF TEH RUBY PARSER
# use single-quoted source strings
class TestPreproc < Test::Unit::TestCase
	def parse txt
		p = Metasm::Preprocessor.new
		p.feed txt
		p
	end

	def test_gettok
		p = parse <<'EOS'
test boo
" bla bla"   \
xx
EOS
		assert_equal \
		['test', :space, ' ', :string, :eol, :quoted, :space, :space, 'xx', :eol, true],
		[p.readtok.raw, p.nexttok.type, p.readtok.raw, p.readtok.type, p.readtok.type, p.readtok.type, p.readtok.type, p.readtok.type, p.readtok.raw, p.readtok.type, p.eos?]
	end

	def test_comment
		p = parse <<'EOS'
foo /* bar */ baz
kikoo // lol \
asv
EOS
		toks = []
		p.skip_space_eol
		until p.eos?
			toks << p.readtok.raw
			p.skip_space_eol
		end
		assert_equal %w[foo baz kikoo asv], toks
	end

	def test_preproc
		p = parse <<'EOS'
#if 0   // test directive as first char
startup
#endif

foo #define toto 42
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

#define tutu
#if defined ( tutu )
coucou
#endif
#define azer(k) 12
# define xxx azer(7)
#define macro(a, b, c) toto a toto b toto c otot
macro(1, xxx, 3+(3-2)) hoho
#undef macro
"abc\"d\x42\0\r"
  #  ifndef macro
#include <tests/prepro_testinclude.asm>
out
#endif
EOS
		p.include_search_path += ['.']
		File.open('tests/prepro_testinclude.asm', 'w') { |fd| fd.puts '#define in cluded', '#define out in' }
		begin
			txt = ''
			txt << p.readtok.raw while not p.eos?
		ensure
			File.unlink('tests/prepro_testinclude.asm')
		end
		assert_equal <<'EOS', txt


foo #define toto 42
// true !
blu




coucou




toto 1 toto 12 toto 3+(3-2) otot hoho

"abc\"d\x42\0\r"
  



cluded

EOS
	end

	def test_errors
		test_err = proc { |txt| assert_raise(Metasm::ParseError) { parse(txt).readtok } }
		test_err['"abc']
		test_err['"abc\x"']
		test_err['/*']
		test_err['#if 0']
		test_err["#if 0.\n#end"]
		test_err["#if 0.3e\n#end"]
		test_err["#define toto(tutu,"]
		test_err[<<EOS]
#if 0
#elif 1
#else
#if 2
#endif
EOS
	end
end

