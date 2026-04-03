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

  describe ".encode_message" do
    it "encodes a single-part message" do
      wire = Frame.encode_message(["hello"])
      io   = IO::Stream::Buffered.wrap(StringIO.new(wire))

      f = Frame.read_from(io)
      assert_equal "hello", f.body
      refute f.more?
    end

    it "encodes a multi-part message with correct MORE flags" do
      wire = Frame.encode_message(["part1", "part2", "part3"])
      io   = IO::Stream::Buffered.wrap(StringIO.new(wire))

      f1 = Frame.read_from(io)
      assert_equal "part1", f1.body
      assert f1.more?

      f2 = Frame.read_from(io)
      assert_equal "part2", f2.body
      assert f2.more?

      f3 = Frame.read_from(io)
      assert_equal "part3", f3.body
      refute f3.more?
    end

    it "returns a frozen string" do
      wire = Frame.encode_message(["data"])
      assert wire.frozen?
    end

    it "produces identical bytes to write_message" do
      parts = ["topic.foo", "payload here"]
      encoded = Frame.encode_message(parts)

      manual = +""
      parts.each_with_index do |part, i|
        manual << Frame.new(part, more: i < parts.size - 1).to_wire
      end

      assert_equal manual, encoded
    end
  end
end
