# frozen_string_literal: true

require_relative "../test_helper"

describe Protocol::ZMTP::Codec::Command do
  Command = Protocol::ZMTP::Codec::Command

  it "roundtrips a READY command" do
    cmd = Command.ready(socket_type: "REQ", identity: "test")
    body = cmd.to_body
    decoded = Command.from_body(body)
    assert_equal "READY", decoded.name
    props = decoded.properties
    assert_equal "REQ", props["Socket-Type"]
    assert_equal "test", props["Identity"]
  end

  it "roundtrips a SUBSCRIBE command" do
    cmd = Command.subscribe("topic.")
    decoded = Command.from_body(cmd.to_body)
    assert_equal "SUBSCRIBE", decoded.name
    assert_equal "topic.", decoded.data
  end

  it "roundtrips a PING command with TTL" do
    cmd = Command.ping(ttl: 3.0, context: "ctx")
    decoded = Command.from_body(cmd.to_body)
    assert_equal "PING", decoded.name
    ttl, context = decoded.ping_ttl_and_context
    assert_equal 3.0, ttl
    assert_equal "ctx", context
  end

  it "encodes and decodes properties" do
    props = { "Socket-Type" => "PAIR", "Identity" => "" }
    encoded = Command.encode_properties(props)
    decoded = Command.decode_properties(encoded)
    assert_equal props, decoded
  end

  it "creates a command frame" do
    cmd = Command.ready(socket_type: "REP")
    frame = cmd.to_frame
    assert frame.command?
  end

  it "raises on malformed command" do
    assert_raises(Protocol::ZMTP::Error) { Command.from_body("") }
  end
end
