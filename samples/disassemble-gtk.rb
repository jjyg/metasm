#!/usr/bin/env ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# 
# this script disassembles an executable (elf/pe) using the GTK front-end
#

require 'metasm'
require 'metasm/gui/gtk'

target = ARGV.shift
if not target
	w = Metasm::GtkGui::OpenFile.new('chose target binary') { |t| target = t }
	w.signal_connect('destroy') { Gtk.main_quit }
	Gtk.main
	exit if not target
end

exe = Metasm::AutoExe.decode_file(target)
dasm = exe.init_disassembler

w = Metasm::GtkGui::MainWindow.new.display(dasm)
w.signal_connect('destroy') { Gtk.main_quit }
Gtk.main
