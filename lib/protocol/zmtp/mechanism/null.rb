# frozen_string_literal: true

module Protocol
  module ZMTP
    # Security mechanisms for the ZMTP handshake (NULL, PLAIN, CURVE).
    module Mechanism
      # NULL security mechanism — no encryption, no authentication.
      #
      # Performs the ZMTP 3.1 greeting exchange and READY command handshake.
      #
      class Null
        MECHANISM_NAME = "NULL"

        # Extra READY properties an upper layer (e.g. an OMQ extension)
        # wants this side to advertise. Mutated before #handshake!.
        # @return [Hash{String => String}]
        attr_accessor :metadata


        def initialize
          @metadata = nil
        end


        # Performs the full NULL handshake over +io+.
        #
        # 1. Exchange 64-byte greetings
        # 2. Validate peer greeting (version, mechanism)
        # 3. Exchange READY commands (socket type + identity + any extras)
        #
        # @param io [#read_exactly, #write, #flush] transport IO
        # @param as_server [Boolean]
        # @param socket_type [String]
        # @param identity [String]
        # @return [Hash] { peer_socket_type:, peer_identity:, peer_qos:, peer_qos_hash:, peer_properties: }
        # @raise [Error]
        def handshake!(io, as_server:, socket_type:, identity:, qos: 0, qos_hash: "")
          io.write(Codec::Greeting.encode(mechanism: MECHANISM_NAME, as_server: as_server))
          io.flush

          greeting_data = io.read_exactly(Codec::Greeting::SIZE)
          peer_greeting = Codec::Greeting.decode(greeting_data)

          unless peer_greeting[:mechanism] == MECHANISM_NAME
            raise Error, "unsupported mechanism: #{peer_greeting[:mechanism]}"
          end

          ready_cmd = Codec::Command.ready(
            socket_type:      socket_type,
            identity:         identity,
            qos:              qos,
            qos_hash:         qos_hash,
            metadata: @metadata,
          )
          io.write(ready_cmd.to_frame.to_wire)
          io.flush

          frame = Codec::Frame.read_from(io)
          unless frame.command?
            raise Error, "expected command frame, got data frame"
          end

          peer_cmd = Codec::Command.from_body(frame.body)
          unless peer_cmd.name == "READY"
            raise Error, "expected READY command, got #{peer_cmd.name}"
          end

          props            = peer_cmd.properties
          peer_socket_type = props["Socket-Type"]
          peer_identity    = props["Identity"] || ""
          peer_qos         = (props["X-QoS"] || "0").to_i
          peer_qos_hash    = props["X-QoS-Hash"] || ""

          unless peer_socket_type
            raise Error, "peer READY missing Socket-Type"
          end

          {
            peer_socket_type: peer_socket_type,
            peer_identity:    peer_identity,
            peer_qos:         peer_qos,
            peer_qos_hash:    peer_qos_hash,
            peer_properties:  props,
          }
        end


        # @return [Boolean] false — NULL does not encrypt frames
        def encrypted? = false
      end
    end
  end
end
