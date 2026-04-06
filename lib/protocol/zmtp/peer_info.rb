# frozen_string_literal: true

module Protocol
  module ZMTP
    # Context passed to an authenticator during authentication.
    # +public_key+ is a +crypto::PublicKey+ instance.
    PeerInfo = Data.define(:public_key)
  end
end
