require 'metasm/preprocessor'
include Metasm
require 'pp'

# traces macro use, returns only the one used (and the one they need)
begin
File.open('foo.h', 'w') { |fd| fd.puts DATA.read }
p = Preprocessor.new
p.include_search_path << '.'
puts p.trace_macros(<<EOS)
#include <foo.h>
#define abc(toto) xxx toto
abc(aaa)
EOS
ensure
File.unlink('foo.h')
end

__END__
#define gugu(zo) (zo+2)
#define x gugu(4)
#define y 2
#define xxx x
#define yyy y
