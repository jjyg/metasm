#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm'
require 'optparse'

$VERBOSE = true

# parse arguments
opts = {}
OptionParser.new { |opt|
	opt.banner = 'Usage: bindiff.rb [options] <executable> [<entrypoints>]'
	opt.on('-P <plugin>', '--plugin <plugin>', 'load a metasm disassembler plugin') { |h| (opts[:plugin] ||= []) << h }
	opt.on('-e <code>', '--eval <code>', 'eval a ruby code') { |h| (opts[:hookstr] ||= []) << h }
	opt.on('--map1 <mapfile>', 'load a map file (addr <-> name association)') { |f| opts[:map1] = f }
	opt.on('--map2 <mapfile>', 'load a map file (addr <-> name association)') { |f| opts[:map2] = f }
	opt.on('-c <header>', '--c-header <header>', 'read C function prototypes (for external library functions)') { |h| opts[:cheader] = h }
	opt.on('-a', '--autoload', 'loads all relevant files with same filename (.h, .map..)') { opts[:autoload] = true }
	opt.on('-v', '--verbose') { $VERBOSE = true }	# default
	opt.on('-q', '--no-verbose') { $VERBOSE = false }
	opt.on('-d', '--debug') { $DEBUG = $VERBOSE = true }
}.parse!(ARGV)

exename1 = ARGV.shift
w1 = Metasm::Gui::DasmWindow.new("#{exename1} - bindiff1 - metasm disassembler")
exe1 = w1.loadfile(exename1)
if opts[:autoload]
	basename1 = exename1.sub(/\.\w\w?\w?$/, '')
	opts[:map1] ||= basename1 + '.map' if File.exist?(basename1 + '.map')
	opts[:cheader] ||= basename1 + '.h' if File.exist?(basename1 + '.h')
end

exename2 = ARGV.shift
w2 = Metasm::Gui::DasmWindow.new("#{exename2} - bindiff2 - metasm disassembler")
exe2 = w2.loadfile(exename2)
if opts[:autoload]
	basename2 = exename2.sub(/\.\w\w?\w?$/, '')
	opts[:map2] ||= basename2 + '.map' if File.exist?(basename2 + '.map')
	opts[:cheader] ||= basename2 + '.h' if File.exist?(basename2 + '.h')
end

dasm1 = exe1.init_disassembler
dasm1.load_map opts[:map1] if opts[:map1]
dasm1.parse_c_file opts[:cheader] if opts[:cheader]
dasm2 = exe2.init_disassembler
dasm2.load_map opts[:map2] if opts[:map2]
dasm2.parse_c_file opts[:cheader] if opts[:cheader]

ep = ARGV.dup

w1.dasm_widget.focus_addr ep.first if not ep.empty?
w2.dasm_widget.focus_addr ep.first if not ep.empty?

opts[:plugin].to_a.each { |p| dasm1.load_plugin(p) ; dasm2.load_plugin(p) }
opts[:hookstr].to_a.each { |f| eval f }

ep.each { |e| dasm1.disassemble_fast_deep(e) ; dasm2.disassemble_fast_deep(e) }

Metasm::Gui.main
