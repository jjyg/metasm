#!/usr/bin/ruby

require 'metasm/mips/encode'
require 'metasm/mips/parse'
require 'metasm/exe_format/pe'

class Metasm::Instruction
        def to_s
                @opname + ' ' + @args.inspect
        end
end

cpu = Metasm::MIPS.new(:little)
prog = Metasm::Program.new cpu

prog.parse <<EOS
.text
start:
lui r4, 0x42
jal toto
add r4, r1, r2
jr r31
nop

toto:
jr r31
;ldc1 fp12, 28(r4)
nop

.import 'foobar' 'baz'
EOS

prog.encode
data = Metasm::PE.encode prog, 'machine' => 'R4000', 'strip_base_relocs' => true, 'pre_header' => 'MZ'

File.open('mipspe.exe', 'wb') { |fd| fd.write data }

