#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# A script to help finding performance bottlenecks:
# ruby-prof myscript.rb
#  => String#+ gets called 50k times and takes 30s
# ruby -r log_caller -e 'log_caller(String, :+)' myscript.rb
#  => String#+ called 40k times from:
#      stuff.rb:42 in Myclass#uglymethod from
#      stuff.rb:32 in Myclass#initialize
# now you know what to rewrite


def log_caller(cls, meth, histlen=-1)
	eval <<EOS
class #{cls}
 alias #{meth}_log_caller #{meth}
 def #{meth}(*a, &b)
  $log_caller_#{meth}[caller[0..#{histlen}] += 1
  #{meth}_log_caller(*a, &b)
 end
end

$log_caller_#{meth} = Hash.new(0)
at_exit { puts " callers of #{cls} #{meth}:", $log_caller_#{meth}.sort_by { |k, v| -v }[0, 4].map { |k, v| ["\#{v} times from", k, ''] } }
EOS
end

