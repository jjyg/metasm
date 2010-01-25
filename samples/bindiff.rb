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
		@dasmcol1 = {}
		@dasmcol2 = {}
		col = { :same => 'cfc', :badarg => 'ffc', :badop => 'fcc', :default => 'f88' }
		@dasm1.gui.bg_color_callback = lambda { |a1| col[@dasmcol1[a1] || :default] }
		@dasm2.gui.bg_color_callback = lambda { |a2| col[@dasmcol2[a2] || :default] }
		@status = nil
	end

	def paint
		help = "d: dasm  f: findfuncs  i: matchfuncs"
		draw_string_color(:grey, @font_width, @font_height, help)
		draw_string_color(:black, @font_width, 3*@font_height, @status || 'idle')
	end

	def gui_update
		@dasm1.gui.gui_update rescue nil
		@dasm2.gui.gui_update rescue nil
		redraw
	end

	def set_status(st=nil)
		ost = @status
		@status = st
		redraw
		if block_given?
			ret = protect { yield }
			set_status ost
			ret
		end
	end

	def keypress(key)
		case key
		when ?D
			@dasm1.load_plugin 'dasm_all'
			@dasm2.load_plugin 'dasm_all'

			set_status('dasm_all 1') {
				@dasm1.dasm_all_section '.text'
			}

			set_status('dasm_all 2') {
				@dasm2.dasm_all_section '.text'
			}
			gui_update
		when ?d
			set_status('dasm 1') {
				@dasm1.disassemble_fast_deep(@dasm1.gui.curaddr)
			}
			set_status('dasm 2') {
				@dasm2.disassemble_fast_deep(@dasm2.gui.curaddr)
			}
			gui_update
		when ?f
			set_status('find funcs') {
				@func1 = create_funcs(@dasm1)
				@func2 = create_funcs(@dasm2)
				@funcstat1 = create_func_stats(@func1, @dasm1)
				@funcstat2 = create_func_stats(@func2, @dasm2)
			}
		when ?g
			inputbox('address to go', :text => Expression[@dasm1.gui.curaddr]) { |v|
				@dasm1.gui.focus_addr_autocomplete(v)
				@dasm2.gui.focus_addr_autocomplete(v)
			}
		when ?i
			m = set_status('match funcs') {
				match_funcs
			}
			gui_update
			GUI.main_iter
			list = [['addr 1', 'addr 2', 'score']]
			m.each { |a1, (a2, s)| list << [Expression[a1], Expression[a2], '%.4f' % s] }
			listwindow("matches", list) { |i| @dasm1.gui.focus_addr i[0] ; @dasm2.gui.focus_addr i[1] }
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
	def create_funcs(dasm)
		f = {}
		dasm.function.each_key { |a|
			next if not dasm.decoded[a].kind_of? DecodedInstruction
			h = f[a] = {}
			todo = [a]
			while a = todo.pop
				next if h[a]
				h[a] = []
				dasm.decoded[a].block.each_to_samefunc(dasm) { |ta|
					next if not dasm.decoded[ta].kind_of? DecodedInstruction
					todo << ta
					h[a] << ta
				}
			end
			Gui.main_iter
		}
		f
	end

	def create_func_stats(f, dasm)
		fs = {}
		f.each { |a, g|
			s = fs[a] = {}
			s[:blocks] = g.length

			s[:edges] = 0	# nr of edges
			s[:leaves] = 0	# nr of nodes with no successor
			s[:ext_calls] = 0	# nr of jumps out_of_func
			s[:loops] = 0	# nr of jump back

			todo = [a]
			done = []
			while aa = todo.pop
				next if done.include? aa
				done << aa
				todo.concat g[aa]

				s[:edges] += g[aa].length
				s[:leaves] += 1 if g[aa].empty?
				dasm.decoded[aa].block.each_to_otherfunc(dasm) { s[:ext_calls] += 1 }
				s[:loops] += (g[aa] & done).uniq.length # XXX may depend on the order we walk the graph ?
			end
		}
		fs
	end

	def match_funcs
		return if not @funcstat1
		layout_match = {}

		@funcstat1.each { |a, s|
			layout_match[a] = []
			@funcstat2.each { |aa, ss|
				layout_match[a] << aa if s == ss
			}
			GUI.main_iter
		}

		# refine the layout matching with actual function matching
		# TODO a second pass for instr-level graph coloring once the match is found
		already_matched = []
		match = {}
		match_score = {}
		layout_match.each { |f1, list|
			f2 = (list - already_matched).sort_by { |f| match_func(f1, f) }.first
			if f2
				already_matched << f2
				score = match_func(f1, f2, true)
				match[f1] = [f2, score]
			end
		}

		puts "fu #{match.length} - wat #{@func1.length - match.length}"

		match
	end

	# return how much match a func in d1 and a func in d2
	def match_func(a1, a2, do_colorize=false)
		f1 = @func1[a1]
		f2 = @func2[a2]
		todo1 = [a1]
		todo2 = [a2]
		done1 = []
		done2 = []
		score = 0.0	# average of the (local best) match_block scores
		score_div = [f1.length, f2.length].max.to_f
		# XXX this is stupid and only good for perfect matches (and even then it may fail)
		# TODO handle block split etc (eg instr-level diff VS block-level)
		while a1 = todo1.pop
			next if done1.include? a1
			t = todo2.map { |a| [a, match_block(@dasm1.decoded[a1].block, @dasm2.decoded[a].block)] }
			a2 = t.sort_by { |a, s| s }.first
			if not a2
				break
			end
			score += a2[1] / score_div
			a2 = a2[0]
			done1 << a1
			done2 << a2
			todo1.concat f1[a1]
			todo2.concat f2[a2]
			todo2 -= done2
			colorize_blocks(a1, a2) if do_colorize
		end

		score += (f1.length - f2.length).abs * 3 / score_div	# block count difference -> +3 per block

		score
	end

	def match_block(b1, b2)
		# 0 = perfect match (same opcodes, same args)
		# 1 = same opcodes, same arg type
		# 2 = same opcodes, diff argtypes
		# 3 = some opcode difference
		# 4 = full block difference
		score = 0
		has_same = false
		# TODO should use a diff-style alg to find similar instrs (here inserting a new instr at begin of block gives score=3)
		b1.list.zip(b2.list).each { |di1, di2|
			if not di1 or not di2 or di1.opcode.name != di2.opcode.name
				score = 3 if score < 3
			elsif di1.instruction.args.map { |a| a.class } != di2.instruction.args.map { |a| a.class }
				score = 2 if score < 2
			elsif di1.instruction.to_s != di2.instruction.to_s
				score = 1 if score < 1
				has_same = true
			else
				has_same = true
			end
		}
		score = 3 if score < 3 and b1.list.length != b2.list.length
		score = 4 if score == 3 and not has_same
		score
	end

	def colorize_blocks(a1, a2)
		b1 = @dasm1.decoded[a1].block
		b2 = @dasm2.decoded[a2].block

		has_same = false
		b1.list.zip(b2.list).each { |di1, di2|
			if not di1 or not di2 or di1.opcode.name != di2.opcode.name
				@dasmcol1[di1.address] = :badop if di1
				@dasmcol2[di2.address] = :badop if di2
			elsif di1.instruction.args.map { |a| a.class } != di2.instruction.args.map { |a| a.class }
				@dasmcol1[di1.address] = :badarg
				@dasmcol2[di2.address] = :badarg
			else
				@dasmcol1[di1.address] = :same
				@dasmcol2[di2.address] = :same
			end
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
