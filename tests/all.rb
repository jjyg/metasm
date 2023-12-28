#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


Dir[File.expand_path('../*.rb', __FILE__)].sort.each do |f|
  # Avoid a circular dependency warning; i.e. don't attempt to run 'require' on the current file again
  next if f == __FILE__

  require f
end
