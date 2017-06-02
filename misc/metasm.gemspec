# This can be used to generate a rubygem of the metasm project
# From the root-dir just run "gem build misc/metasm.gemspec"
require 'metasm'

if not File.exist?("lib")
  File.symlink(".", "lib")
end

Gem::Specification.new do |s|
  s.name = "metasm"
  s.version = Metasm::VERSION

  s.date = Time.now.strftime("%Y-%m-%d")
  s.description = s.summary = "Metasm is a cross-architecture assembler, disassembler, compiler, linker and debugger in pure Ruby with no dependencies."
  s.homepage = "http://metasm.cr0.org"
  s.author = "Yoann Guillot"
  s.email = "yoann@ofjj.net"

  s.files = Dir[
    "BUGS", "LICENSE", "CREDITS", "README", "TODO",
    "tests/**",
    "misc/**",
    "doc/**",
    "samples/**",
    "lib/metasm.rb", 
    "lib/metasm/**/*"]

  s.require_paths = ["lib"]
end

