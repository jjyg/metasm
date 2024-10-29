#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/main'

module Metasm
class Python < CPU
	attr_accessor :py_version

	def initialize(prog = nil, py_ver=nil)
		super()
		@program = prog
		@py_version = py_ver
		@py_version ||= prog.py_version if prog and prog.shortname == 'pyc'
                @py_version ||= 0
		@endianness = (prog.respond_to?(:endianness) ? prog.endianness : :little)
		@size = (prog.respond_to?(:size) ? prog.size : 32)
	end
end
end
