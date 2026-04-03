# frozen_string_literal: true

require_relative "test_helper"

describe Protocol::ZMTP::Connection do
  def make_pair(server_mech: nil, client_mech: nil,
                server_type: "REP", client_type: "REQ")
    s1, s2 = UNIXSocket.pair
    server_io = IO::Stream::Buffered.wrap(s1)
    client_io = IO::Stream::Buffered.wrap(s2)

    server = Protocol::ZMTP::Connection.new(
      server_io, socket_type: server_type, as_server: true,
      mechanism: server_mech,
    )
    client = Protocol::ZMTP::Connection.new(
      client_io, socket_type: client_type, as_server: false,
      mechanism: client_mech,
    )

    [server, client, server_io, client_io]
  end

  it "completes NULL handshake" do
    Async do
      server, client, sio, cio = make_pair

      [Async { server.handshake! }, Async { client.handshake! }].each(&:wait)

      assert_equal "REP", client.peer_socket_type
      assert_equal "REQ", server.peer_socket_type
    ensure
      sio&.close; cio&.close
    end
  end

  it "sends and receives messages" do
    Async do
      server, client, sio, cio = make_pair(server_type: "PAIR", client_type: "PAIR")

      [Async { server.handshake! }, Async { client.handshake! }].each(&:wait)

      Async { client.send_message(["hello", "world"]) }
      msg = nil
      Async { msg = server.receive_message }.wait

      assert_equal ["hello", "world"], msg
    ensure
      sio&.close; cio&.close
    end
  end

  it "rejects incompatible socket types" do
    Async do |task|
      server, client, sio, cio = make_pair(server_type: "PUB", client_type: "REQ")

      errors = []
      [
        Async do
          server.handshake!
        rescue Protocol::ZMTP::Error, EOFError => e
          errors << e
          sio.close rescue nil
        end,
        Async do
          client.handshake!
        rescue Protocol::ZMTP::Error, EOFError => e
          errors << e
          cio.close rescue nil
        end,
      ].each(&:wait)

      refute_empty errors
    ensure
      sio&.close rescue nil
      cio&.close rescue nil
    end
  end

  it "tracks heartbeat timestamps" do
    conn = Protocol::ZMTP::Connection.new(
      StringIO.new, socket_type: "PAIR",
    )
    assert_nil conn.last_received_at
    conn.touch_heartbeat
    refute_nil conn.last_received_at
    refute conn.heartbeat_expired?(1.0)
  end

  it "#curve? returns false for NULL mechanism" do
    Async do
      server, client, sio, cio = make_pair(server_type: "PAIR", client_type: "PAIR")
      [Async { server.handshake! }, Async { client.handshake! }].each(&:wait)

      refute server.curve?
      refute client.curve?
    ensure
      sio&.close; cio&.close
    end
  end

  it "#write_wire writes pre-encoded bytes readable as frames" do
    Async do
      server, client, sio, cio = make_pair(server_type: "PAIR", client_type: "PAIR")
      [Async { server.handshake! }, Async { client.handshake! }].each(&:wait)

      wire = Protocol::ZMTP::Codec::Frame.encode_message(["hello", "world"])
      Async { client.write_wire(wire); client.flush }
      msg = nil
      Async { msg = server.receive_message }.wait

      assert_equal ["hello", "world"], msg
    ensure
      sio&.close; cio&.close
    end
  end
end
