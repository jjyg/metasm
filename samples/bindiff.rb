#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm'
require 'optparse'

module Metasm
class BinDiffWidget < Metasm::Gui::DrawableWidget
	attr_accessor :dasm1, :dasm2
	attr_accessor :status

	def initialize_widget(d1, d2)
		@dasm1, @dasm2 = d1, d2
		@status = nil
	end

	def paint
		help = "d: dasm_all  f: find funcs  i: match funcs  r: reload"
		draw_string_color(:grey, @font_width, @font_height, help)
		draw_string_color(:black, @font_width, 3*@font_height, @status || 'idle')
	end

	def set_status(st=nil)
		ost = @status
		@status = st
		redraw
		if block_given?
			protect { yield }
			set_status ost
		end
	end

	def keypress(key)
		case key
		when ?d
			@dasm1.load_plugin 'dasm_all'
			@dasm2.load_plugin 'dasm_all'

			set_status('dasm_all 1') {
				@dasm1.dasm_all_section '.text'
			}

			set_status('dasm_all 2') {
				@dasm2.dasm_all_section '.text'
			}
		when ?f
			set_status('find funcs') {
				@func1 = identify_funcs(@dasm1)
				@func2 = identify_funcs(@dasm2)
			}
		when ?i
			set_status('match funcs') {
				match_funcs
			}
		when ?r
			puts 'reload'
			load __FILE__
		end
	end

	def keypress_ctrl(key)
		case key
		when ?r
			inputbox('code to eval') { |c| messagebox eval(c).inspect[0, 512], 'eval' }
		end
	end

	# func addr => { funcblock => list of funcblock to }
	def identify_funcs(dasm)
		f = {}
		dasm.function.each_key { |a|
			next if not dasm.decoded[a]
			h = f[a] = {}
			todo = [a]
			while a = todo.pop
				next if h[a]
				h[a] = []
				if dasm.decoded[a].kind_of? DecodedInstruction
					dasm.decoded[a].block.each_to_samefunc(dasm) { |ta|
						todo << ta
						h[a] << ta
					}
				end
			end
			Gui.main_iter
		}
		f
	end

	def match_funcs
		return if not @func1 or not @func2
		@matches = {}

		@func1.each { |f1|
			@func2.each { |f2|
				# TODO identify functions with the same graph layout, then
				# compare instr mnemonics (args ?  must ignore address constants)
			}
		}
	end
end

class BinDiffWindow < Gui::Window
	def initialize_window(d1, d2)
		self.widget = BinDiffWidget.new(d1, d2)
	end
end
end

# allow reloading the file
if not defined? $running
$running = true

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

Metasm::BinDiffWindow.new(dasm1, dasm2)

Metasm::Gui.main

end
