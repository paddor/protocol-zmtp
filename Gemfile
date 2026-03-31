# frozen_string_literal: true

source "https://rubygems.org"

gemspec

gem "minitest"
gem "rake"
gem "async"
gem "io-stream"

if ENV["OMQ_DEV"]
  gem "nuckle", path: "../nuckle"
  gem "rbnacl", "~> 7.0"
else
  gem "nuckle"
end
