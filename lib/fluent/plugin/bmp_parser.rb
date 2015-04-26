require 'bindata'
require 'ipaddr'
require 'yaml'

require 'fluent/parser'

module Fluent
  class TextParser
    class IP4Addr16 < BinData::Primitive
      endian :big
      skip   :length => 12
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
    
    class BmpPerPeerHeader < BinData::Record
      endian :big
      uint8  :peer_type
      bit1   :protocol
      bit1   :installed
      bit6   :reserve
      uint64 :rd
      choice :peer_address, :selection => :protocol do
        ip4_addr16 0
        ip6_addr 1
      end
      uint32 :peer_as
      ip4_addr :bgp_id
      uint32 :timestamp_sec
      uint32 :timestamp_microsec
    end
    
    class BgpCapability < BinData::Record
      uint8 :code
      uint8 :capability_length
      string :capability_value, :read_length => :capability_length
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
    
    class BgpUpdateMessage < BinData::Record
      endian :big
      skip   :length =>  16
      uint16 :message_size
      uint8  :type
      uint16 :withdrawn_route_length
      buffer :withdrawn_routes, :length => :withdrawn_route_length, :onlyif => :has_withdrawn? do
        array :withdrawn_cidr, :read_until => :eof do
          uint8 :cidr_bit_length
          ip4_addr :withdrawn_prefix
        end
      end
      uint16 :total_path_attribute_length
      buffer :path_attributes_buffer, :length => :total_path_attribute_length do
        array :path_attributes, :read_until => :eof do
          bgp_path_attribute :attr
        end
      end
      buffer :nlris_buffer, :length => :nlri_length do
        array :nlris, :read_until => :eof do
          uint8 :nlri_bit_length
          ip4_addr :address
        end
      end
    
      def has_withdrawn?
        withdrawn_route_length.nonzero?
      end
    
      def nlri_length
        message_size - (16 + 2 + 1 + 2 + withdrawn_route_length + 2 + total_path_attribute_length)
      end
    
    end
    
    
    class RouteMonitor < BinData::Record
      endian :big
      bmp_per_peer_header :header
      bgp_update_message :bgp_updates
    end
    
    class StatisticsReport < BinData::Record
      endian :big
      bmp_per_peer_header :header
      uint32 :stats_count
      array :stats, :initial_length => :stats_count do 
        uint16 :stats_type
        uint16 :stats_data_size
        choice :stats_data, :selection => :stats_data_size do
          uint32 4
          uint64 8
        end
      end 
    end
    
    
    class PeerDownNotify < BinData::Record
      endian :big
      bmp_per_peer_header :header
      uint8  :reason
      string :data, :read_until => :eof, :onlyif => lambda { reason <= 3 }
    end
    class PeerUpNotify < BinData::Record
      endian :big
      bmp_per_peer_header :header
      choice :local_ip, :selection => :peer_address_family do
        ip4_addr16 0
        ip6_addr 1
      end
      uint16 :local_port
      uint16 :remote_port
      bgp_open_message :sent
      bgp_open_message :receive
      
      def peer_address_family
        header.protocol
      end
    end
    class InitiationMessage < BinData::Record
      endian :big
      array :records, :read_until => :eof do 
        uint16 :infotype
        uint16 :info_size
        string :info, :read_length => :info_size
      end
    end
    
    class TerminationMessage < BinData::Record
      endian :big
      uint16 :infotype
      uint16 :info_size
      string :info, :read_length => :info_size
    end
    
    class BmpRecord < BinData::Record
      endian :big
      uint8  :version
      uint32 :record_length
      uint8  :bmp_record_type
      choice :bmp_record, :selection => :bmp_record_type do
        route_monitor       0
        statistics_report   1
        peer_down_notify    2
        peer_up_notify      3
        initiation_message  4
        termination_message 5
      end
    end
  end
end
