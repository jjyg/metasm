#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


Dir['tests/*.rb'].sort.each { |f| require_relative "../#{f}" if f != 'tests/all.rb' }

