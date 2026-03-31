# frozen_string_literal: true

require_relative "../test_helper"

describe Protocol::ZMTP::Mechanism::Null do
  it "is not encrypted" do
    mech = Protocol::ZMTP::Mechanism::Null.new
    refute mech.encrypted?
  end
end
