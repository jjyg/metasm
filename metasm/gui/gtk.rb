#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'gtk2'
require 'metasm/gui/gtk_listing'
require 'metasm/gui/gtk_graph'

module Metasm
module GtkGui
class MainWindow < Gtk::Window
	attr_accessor :dasm, :entrypoints, :view

	def initialize
		super()
		self.default_width = 500
		self.default_height = 500
		self.title = 'testic'
	end

	def display(dasm, ep=[])
		@dasm = dasm

		@entrypoints = ep
		@view = AsmListingWidget.new(@dasm, @entrypoints)

		gui_update_counter = 0
		dasm_working = false
		Gtk.idle_add {
			# metasm disassembler loop
			# update gui once in a while
			dasm_working = true if not @entrypoints.empty? or not @dasm.addrs_todo.empty?
			if dasm_working
				begin
					if not @dasm.disassemble_mainiter(@entrypoints)
						dasm_working = false
						gui_update_counter = 10000
					end
				rescue
					MessageBox.new $!
				end
				gui_update_counter += 1
				if gui_update_counter > 100
					gui_update_counter = 0
					@view.gui_update
				end
			end
			true
		}

		add @view

		show_all
	end
end

class MessageBox < Gtk::MessageDialog
	def initialize(str)
		super(Gtk::Window.toplevels.first, Gtk::Dialog::DESTROY_WITH_PARENT, INFO, BUTTONS_CLOSE, str)
		signal_connect('response') { destroy }
		show_all
		present
	end
end

class InputBox < Gtk::Dialog
	def initialize(str)
		super(nil, Gtk::Window.toplevels.first, Gtk::Dialog::DESTROY_WITH_PARENT,
			[Gtk::Stock::OK, Gtk::Dialog::RESPONSE_ACCEPT], [Gtk::Stock::CANCEL, Gtk::Dialog::RESPONSE_REJECT])

		label = Gtk::Label.new(str)
		text  = Gtk::TextView.new

		text.signal_connect('key_press_event') { |w, ev|
			case ev.keyval
			when Gdk::Keyval::GDK_Escape: response(RESPONSE_REJECT) ; true
			when Gdk::Keyval::GDK_Return, Gdk::Keyval::GDK_KP_Enter: response(RESPONSE_ACCEPT) ; true
			end
		}

		signal_connect('response') { |win, id|
			if id == RESPONSE_ACCEPT
				text = text.buffer.text
				destroy
				yield text
			else
				destroy
			end
			true
		}

		vbox.pack_start label, false, false, 8
		vbox.pack_start text, false, false, 8

		show_all
		present
	end
end

class OpenFile < Gtk::FileChooserDialog
	def initialize(title)
		super(title, Gtk::Window.toplevels.first, Gtk::FileChooser::ACTION_OPEN, nil,
		[Gtk::Stock::CANCEL, Gtk::Dialog::RESPONSE_CANCEL], [Gtk::Stock::OPEN, Gtk::Dialog::RESPONSE_ACCEPT])
		signal_connect('response') { |win, id|
			if id == Gtk::Dialog::RESPONSE_ACCEPT
				file = filename
				destroy
					yield file
			else
				destroy
			end
			true
		}

		show_all
		present
	end
end
end
end
