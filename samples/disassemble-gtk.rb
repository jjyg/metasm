#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


#
# this script disassembles an executable (elf/pe) using the GTK front-end
# use live:bla to open a running process whose filename contains 'bla'
#
# key binding (non exhaustive):
#  Enter to follow a label (the current hilighted word)
#  Esc to return to the previous position
#  Space to switch between listing and graph views
#  Tab to decompile (on already disassembled code)
#  'c' to start disassembling from the cursor position
#  'g' to go to a specific address (label/042h)
#  'l' to list known labels
#  'f' to list known functions
#  'x' to list xrefs to current address
#  'n' to rename a label (current word or current address)
#  ctrl+'r' to run arbitrary ruby code in the context of the GtkGui objet (access to 'dasm', 'curaddr')
#  ctrl+mousewheel to zoom in graph view ; also doubleclick on the background ('fit to window'/'reset zoom')
#

require 'metasm'
require 'optparse'

$VERBOSE = true

# parse arguments
opts = {}
OptionParser.new { |opt|
	opt.banner = 'Usage: disassemble-gtk.rb [options] <executable> [<entrypoints>]'
	opt.on('--no-data-trace', 'do not backtrace memory read/write accesses') { opts[:nodatatrace] = true }
	opt.on('--debug-backtrace', 'enable backtrace-related debug messages (very verbose)') { opts[:debugbacktrace] = true }
	opt.on('--custom <hookfile>', 'eval a ruby script hookfile') { |h| (opts[:hookfile] ||= []) << h }
	opt.on('--eval <code>', '-e <code>', 'eval a ruby code') { |h| (opts[:hookstr] ||= []) << h }
	opt.on('--map <mapfile>', 'load a map file (addr <-> name association)') { |f| opts[:map] = f }
	opt.on('--fast', 'dasm cli args with disassemble_fast_deep') { opts[:fast] = true }
	opt.on('-c <header>', '--c-header <header>', 'read C function prototypes (for external library functions)') { |h| opts[:cheader] = h }
	opt.on('-a', '--autoload', 'loads all relevant files with same filename (.h, .map..)') { opts[:autoload] = true }
	opt.on('-v', '--verbose') { $VERBOSE = true }	# default
	opt.on('-q', '--no-verbose') { $VERBOSE = false }
	opt.on('-d', '--debug') { $DEBUG = $VERBOSE = true }
}.parse!(ARGV)

require 'metasm/gui/gtk'	# windows version of gtk.rb raises on unknown cli args...

exename = ARGV.shift

if exename =~ /^live:(.*)/
	raise 'no such live target' if not target = Metasm::OS.current.find_process($1)
	p target if $VERBOSE
	w = Metasm::GtkGui::DbgWindow.new(target.debugger, target.modules[0].path.dup)
else
	w = Metasm::GtkGui::MainWindow.new("#{exename + ' - ' if exename}metasm disassembler")
	if exename
		exe = w.loadfile(exename)
		if opts[:autoload]
			basename = exename.sub(/\.\w\w?\w?$/, '')
			opts[:map] ||= basename + '.map' if File.exist?(basename + '.map')
			opts[:cheader] ||= basename + '.h' if File.exist?(basename + '.h')
		end
	end
end

ep = ARGV.map { |arg| (?0..?9).include?(arg[0]) ? Integer(arg) : arg }

if exe
	dasm = exe.init_disassembler

	dasm.load_map opts[:map] if opts[:map]
	dasm.parse_c_file opts[:cheader] if opts[:cheader]
	dasm.backtrace_maxblocks_data = -1 if opts[:nodatatrace]
	dasm.debug_backtrace = true if opts[:debugbacktrace]
	dasm.disassemble_fast_deep(*ep) if opts[:fast]
end

opts[:hookfile].to_a.each { |f| eval File.read(f) }
opts[:hookstr].to_a.each { |f| eval f }

if dasm
	w.display(dasm, ep)
	w.dasm_widget.focus_addr ep.first if not ep.empty?
else
	w.show_all
end
Gtk.main
