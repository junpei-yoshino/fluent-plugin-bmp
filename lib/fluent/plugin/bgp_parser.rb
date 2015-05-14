require 'bindata'
require 'ipaddr'

class BgpParser
    
  class BgpOpenMessage < BinData::Record
    endian :big
    skip   :length =>  16
    uint16 :message_size
    uint8  :type
    uint8  :bgp_version
    uint16 :my_asn
    uint16 :hold_time
    ip4_addr :bgp_id
    uint8  :opt_length
    buffer :options, :length => :opt_length do
      array :read_until => :eof do
        bgp_option :option
      end
    end
  end

  class BgpOption < BinData::Record
    endian :big
    uint8 :type
    uint8 :param_length
    buffer :capabilities, :length => :param_length do
      array :read_until => :eof do
        bgp_capability :capability
      end
    end
  end

  class BgpCapability < BinData::Record
    uint8 :code
    uint8 :capability_length
    string :capability_value, :read_length => :capability_length
  end

  class BgpUpdateMessage < BinData::Record
    endian :big
    skip   :length =>  16
    uint16 :message_size
    uint8  :type
    uint16 :withdrawn_route_length
    buffer :withdrawn_routes, :length => :withdrawn_route_length, :onlyif => :has_withdrawn? do
      array :withdrawn_cidr, :type => :bgp_cidr, :read_until => :eof
    end
    uint16 :total_path_attribute_length
    buffer :path_attributes_buffer, :length => :total_path_attribute_length do
      array :path_attributes, :read_until => :eof do
        bgp_path_attribute :attr
      end
    end
    buffer :nlris_buffer, :length => :nlri_length do
      array :nlris, :type => :bgp_cidr, :read_until => :eof
    end

    def has_withdrawn?
      withdrawn_route_length.nonzero?
    end

    def nlri_length
      message_size - (16 + 2 + 1 + 2 + withdrawn_route_length + 2 + total_path_attribute_length)
    end

    def read_length_from_prefix(size)
      return int((size+7)/8)
    end
  end

  class BgpCidr < BinData::Record
    endian :big
    uint8  :bit_length
    array  :prefix, :type => uint8, :initial_length => :bytes_from_bit_length
    
    def bytes_from_bit_length
      (bit_length / 8.0).ceil
    end
  end

  class BgpPathAttribute < BinData::Record
    endian :big
    uint8 :attribute_flag
    uint8 :attribute_type
    choice :attribute_length, :selection => :extended? do
      uint8 0
      uint16 1
    end
    string :attribute_value, :read_length => :attribute_length
    
    def extended?
      (attribute_flag >> 5) & 1
    end
  end
    
  class IP4Addr < BinData::Primitive
    endian :big
    uint32 :storage

    def set(val)
      ip = IPAddr.new(val)
      if ! ip.ipv4?
        raise ArgumentError, "invalid IPv4 address '#{val}'"
      end
      self.storage = ip.to_i
    end

    def get
      IPAddr.new_ntoh([self.storage].pack('N')).to_s
    end
  end
    
  class IP6Addr < BinData::Primitive
    endian  :big
    uint128 :storage

    def set(val)
      ip = IPAddr.new(val)
      if ! ip.ipv6?
        raise ArgumentError, "invalid IPv6 address `#{val}'"
      end
      self.storage = ip.to_i
    end

    def get
      IPAddr.new_ntoh((0..7).map { |i|
      (self.storage >> (112 - 16 * i)) & 0xffff}.pack('n8')).to_s
    end
  end
end
