# frozen_string_literal: true

require_relative "../test_helper"

describe Protocol::ZMTP::Codec::Greeting do
  Greeting = Protocol::ZMTP::Codec::Greeting

  it "encodes a 64-byte greeting" do
    data = Greeting.encode(mechanism: "NULL", as_server: false)
    assert_equal 64, data.bytesize
    assert_equal 0xFF, data.getbyte(0)
    assert_equal 0x7F, data.getbyte(9)
  end

  it "roundtrips NULL mechanism" do
    data = Greeting.encode(mechanism: "NULL", as_server: false)
    decoded = Greeting.decode(data)
    assert_equal 3, decoded[:major]
    assert_equal 1, decoded[:minor]
    assert_equal "NULL", decoded[:mechanism]
    refute decoded[:as_server]
  end

  it "roundtrips CURVE mechanism as server" do
    data = Greeting.encode(mechanism: "CURVE", as_server: true)
    decoded = Greeting.decode(data)
    assert_equal "CURVE", decoded[:mechanism]
    assert decoded[:as_server]
  end

  it "rejects invalid signature" do
    data = "\x00" * 64
    assert_raises(Protocol::ZMTP::Error) { Greeting.decode(data) }
  end

  it "rejects old version" do
    data = Greeting.encode
    data = data.dup
    data.setbyte(10, 2) # major = 2
    assert_raises(Protocol::ZMTP::Error) { Greeting.decode(data) }
  end
end
