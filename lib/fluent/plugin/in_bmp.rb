module Fluent
  class BmpInput < Input
    Plugin.register_input('bmp', self)

    def initialize
      super
      require 'cool.io'
      require 'fluent/plugin/socket_util'
      require 'fluent/plugin/parser_bmp'
    end

    config_param :port, :integer, :default => 1179
    config_param :bind, :string, :default => '0.0.0.0'
    config_param :tag, :string

    def configure(conf)
      super
      @parser = TextParser::BmpParser.new
      @parser.configure(conf)
    end

    def start

    end

    def shutdown

    end

    def run

    end

  end
end
