# frozen_string_literal: true

require_relative "../test_helper"

describe Protocol::ZMTP::Codec::Frame do
  Frame = Protocol::ZMTP::Codec::Frame

  def roundtrip(frame)
    wire = frame.to_wire
    io = IO::Stream::Buffered.wrap(StringIO.new(wire))
    Frame.read_from(io)
  end

  it "encodes and decodes a short data frame" do
    frame = Frame.new("hello")
    decoded = roundtrip(frame)
    assert_equal "hello", decoded.body
    refute decoded.more?
    refute decoded.command?
  end

  it "encodes and decodes a short frame with MORE" do
    frame = Frame.new("part1", more: true)
    decoded = roundtrip(frame)
    assert_equal "part1", decoded.body
    assert decoded.more?
    refute decoded.command?
  end

  it "encodes and decodes a command frame" do
    frame = Frame.new("\x05READY", command: true)
    decoded = roundtrip(frame)
    assert_equal "\x05READY", decoded.body
    assert decoded.command?
    refute decoded.more?
  end

  it "encodes and decodes a long frame (> 255 bytes)" do
    big = "x" * 300
    frame = Frame.new(big)
    decoded = roundtrip(frame)
    assert_equal big, decoded.body
  end

  it "encodes an empty frame" do
    frame = Frame.new("")
    decoded = roundtrip(frame)
    assert_equal "", decoded.body
  end
end
