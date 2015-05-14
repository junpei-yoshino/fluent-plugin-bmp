require 'bindata'
require 'ipaddr'
require 'yaml'

require 'fluent/parser'
require 'fluent/plugin/bgp_parser'

module Fluent
  class TextParser
    class BmpRecord < BinData::Record
      endian :big
      uint8  :version
      uint32 :record_length
      uint8  :bmp_record_type
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
    
  end
end
