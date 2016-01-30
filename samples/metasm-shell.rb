#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# modifies the standard ruby class String to add #decode and #encode methods
# they will respectively disassemble binary data / assemble asm source
# the default CPU is x86 32bits, change it using eg String.cpu = Metasm::MIPS.new(:big) (mips bigendian)
#
# it also defines the toplevel 'asm' method, that will start an interactive
# assembler shell (type in assembly statements, they are shown assembled in binary escaped form)
#
# eg:
# ruby metasm-shell
# > nop ; nop
# "\x90\x90"
# > exit

require 'metasm'
require 'readline'

class String
  @@cpu = Metasm::Ia32.new
  class << self
    def cpu()   @@cpu   end
    def cpu=(c)
      c = Metasm.const_get(c).new if c.kind_of? String
      @@cpu=c
    end
  end

  # encodes the current string as a Shellcode, returns the resulting EncodedData
  def encode_edata
    Metasm::Shellcode.assemble(@@cpu, self).encode.encoded
  end

  # encodes the current string as a Shellcode, returns the resulting binary String
  # outputs warnings on unresolved relocations
  def encode
    ed = encode_edata
    if not ed.reloc.empty?
      puts 'W: encoded string has unresolved relocations: ' + ed.reloc.map { |o, r| r.target.inspect }.join(', ')
    end
    ed.fill
    ed.data
  end

  # decodes the current string as a Shellcode, with specified base address
  # returns the resulting Disassembler
  def decode_blocks(base_addr=0, eip=base_addr)
    sc = Metasm::Shellcode.decode(self, @@cpu)
    sc.base_addr = base_addr
    sc.disassemble(eip)
  end

  # decodes the current string as a Shellcode, with specified base address
  # returns the asm source equivallent
  def decode(base_addr=0, eip=base_addr)
    decode_blocks(base_addr, eip).to_s
  end
end

# get in interactive assembler mode
def asm
  puts "[+] Metasm assembly shell"
  puts "type help for usage..\n\n"

  Readline.completion_proc = lambda { |line| %w[help exit quit].find_all { |w| line.downcase == w[0, line.length] } }
  Readline.completion_append_character = ' '

  while line = Readline.readline('asm> ', true)
    case line
    when /^help(\W|$)/
      puts "",
           "Type in opcodes to see their binary form",
           "You can use ';' to type multi-line stuff",
           "e.g. 'nop nop' will display \"\\x90\\x90\"",
           "",
           "exit/quit    Quit the console",
           "help         Show this screen",
           ""
    when /^(quit|exit)(\W|$)/
      break
    else
      begin
        data = line.gsub(';', "\n")
        next if data.strip.empty?
        e_data = data.encode
        puts '"' + e_data.unpack('C*').map { |c| '\\x%02x' % c }.join + '"'
      rescue Metasm::Exception => e
        puts "Error: #{e.class} #{e.message}"
      end
    end
  end

  puts
end

if __FILE__ == $0
  asm
end
