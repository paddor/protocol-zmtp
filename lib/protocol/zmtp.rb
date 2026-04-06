# frozen_string_literal: true

require_relative "zmtp/version"
require_relative "zmtp/error"
require_relative "zmtp/valid_peers"
require_relative "zmtp/codec"
require_relative "zmtp/connection"
require_relative "zmtp/peer_info"
require_relative "zmtp/mechanism/null"
require_relative "zmtp/mechanism/plain"
require_relative "zmtp/z85"

module Protocol
  module ZMTP
    # Autoload CURVE mechanism — requires a crypto backend (rbnacl or nuckle).
    autoload :Curve, File.expand_path("zmtp/mechanism/curve", __dir__)
  end
end
