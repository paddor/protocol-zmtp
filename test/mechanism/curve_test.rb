# frozen_string_literal: true

require_relative "../test_helper"
require "protocol/zmtp/mechanism/curve"
require "nuckle"

HAVE_RBNACL = begin
  require "rbnacl"
  true
rescue LoadError
  false
end

describe Protocol::ZMTP::Mechanism::Curve do
  Curve = Protocol::ZMTP::Mechanism::Curve

  def generate_keypair(crypto)
    sk = crypto::PrivateKey.generate
    [sk.public_key.to_s, sk.to_s]
  end

  def make_curve_pair(server_crypto:, client_crypto:)
    server_pub, server_sec = generate_keypair(server_crypto)
    client_pub, client_sec = generate_keypair(client_crypto)

    s1, s2 = UNIXSocket.pair
    server_io = IO::Stream::Buffered.wrap(s1)
    client_io = IO::Stream::Buffered.wrap(s2)

    server_mech = Curve.server(server_pub, server_sec, crypto: server_crypto)
    client_mech = Curve.client(client_pub, client_sec, server_key: server_pub, crypto: client_crypto)

    server = Protocol::ZMTP::Connection.new(
      server_io, socket_type: "PAIR", as_server: true, mechanism: server_mech,
    )
    client = Protocol::ZMTP::Connection.new(
      client_io, socket_type: "PAIR", as_server: false, mechanism: client_mech,
    )

    [server, client, server_io, client_io]
  end

  backends = [Nuckle]
  backends << RbNaCl if HAVE_RBNACL

  backends.each do |crypto|
    describe "with #{crypto}" do
      it "completes handshake and exchanges messages" do
        Async do
          server, client, sio, cio = make_curve_pair(server_crypto: crypto, client_crypto: crypto)

          [Async { server.handshake! }, Async { client.handshake! }].each(&:wait)

          assert_equal "PAIR", client.peer_socket_type
          assert_equal "PAIR", server.peer_socket_type

          Async { client.send_message(["encrypted hello"]) }
          msg = nil
          Async { msg = server.receive_message }.wait
          assert_equal ["encrypted hello"], msg

          Async { server.send_message(["encrypted reply"]) }
          msg2 = nil
          Async { msg2 = client.receive_message }.wait
          assert_equal ["encrypted reply"], msg2
        ensure
          sio&.close; cio&.close
        end
      end

      it "is encrypted" do
        pub, sec = generate_keypair(crypto)
        mech = Curve.server(pub, sec, crypto: crypto)
        assert mech.encrypted?
      end

      it "rejects wrong server key" do
        Async do
          server_pub, server_sec = generate_keypair(crypto)
          client_pub, client_sec = generate_keypair(crypto)
          wrong_pub, _           = generate_keypair(crypto)

          s1, s2 = UNIXSocket.pair
          server_io = IO::Stream::Buffered.wrap(s1)
          client_io = IO::Stream::Buffered.wrap(s2)

          server_mech = Curve.server(server_pub, server_sec, crypto: crypto)
          client_mech = Curve.client(client_pub, client_sec, server_key: wrong_pub, crypto: crypto)

          server = Protocol::ZMTP::Connection.new(
            server_io, socket_type: "PAIR", as_server: true, mechanism: server_mech,
          )
          client = Protocol::ZMTP::Connection.new(
            client_io, socket_type: "PAIR", as_server: false, mechanism: client_mech,
          )

          errors = []
          [
            Async do
              server.handshake!
            rescue Protocol::ZMTP::Error, EOFError => e
              errors << e
              server_io.close rescue nil
            end,
            Async do
              client.handshake!
            rescue Protocol::ZMTP::Error, EOFError => e
              errors << e
              client_io.close rescue nil
            end,
          ].each(&:wait)

          refute_empty errors
        ensure
          server_io&.close rescue nil
          client_io&.close rescue nil
        end
      end

      it "raises on invalid key length" do
        assert_raises(ArgumentError) do
          Curve.server("short", "short", crypto: crypto)
        end
      end

      it "raises on nil keys" do
        assert_raises(ArgumentError) do
          Curve.server(nil, nil, crypto: crypto)
        end
      end
    end
  end

  if HAVE_RBNACL
    describe "interop: RbNaCl server, Nuckle client" do
      it "completes handshake and exchanges messages" do
        Async do
          server, client, sio, cio = make_curve_pair(server_crypto: RbNaCl, client_crypto: Nuckle)

          [Async { server.handshake! }, Async { client.handshake! }].each(&:wait)

          Async { client.send_message(["nuckle->rbnacl"]) }
          msg = nil
          Async { msg = server.receive_message }.wait
          assert_equal ["nuckle->rbnacl"], msg
        ensure
          sio&.close; cio&.close
        end
      end
    end

    describe "interop: Nuckle server, RbNaCl client" do
      it "completes handshake and exchanges messages" do
        Async do
          server, client, sio, cio = make_curve_pair(server_crypto: Nuckle, client_crypto: RbNaCl)

          [Async { server.handshake! }, Async { client.handshake! }].each(&:wait)

          Async { client.send_message(["rbnacl->nuckle"]) }
          msg = nil
          Async { msg = server.receive_message }.wait
          assert_equal ["rbnacl->nuckle"], msg
        ensure
          sio&.close; cio&.close
        end
      end
    end
  end
end
