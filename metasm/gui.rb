backend = case ENV['METASM_GUI']
when 'gtk'; 'gtk'
when 'qt'; 'qt'
else
	puts "Unsupported METASM_GUI #{ENV['METASM_GUI'].inspect}" if $VERBOSE and ENV['METASM_GUI']
	begin
		require 'gtk2'
		'gtk'
	rescue LoadError
		begin
			require 'Qt4'
			'qt'
		rescue LoadError
			raise LoadError, 'No GUI ruby binding installed - please install libgtk2-ruby or libqt4-ruby'
		end
	end
end
require "metasm/gui/#{backend}"
