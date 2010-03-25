# To change this template, choose Tools | Templates
# and open the template in the editor.

module Binascii
  def self.hex2bin(hex_str)
    unless hex_str.instance_of?(String) && hex_str.length % 2 == 0
      raise ArgumentError, "hex_str param must be a hex string."
    end

    hex_str.gsub!(/[^0-9a-f]/i, '')
    [hex_str].pack("H*")
  end

  def self.bin2hex(bin_str)
    bin_str.unpack("H*")
  end
end


