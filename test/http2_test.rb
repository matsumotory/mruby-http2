test_site = 'https://nghttp2.org/'

assert("HTTP2::Client#request_headers") do
  r = HTTP2::Client.get test_site
  assert_equal("GET", r.request_headers[":method"])
  assert_equal("/", r.request_headers[":path"])
  assert_equal("https", r.request_headers[":scheme"])
  assert_equal("nghttp2.org", r.request_headers[":authority"])
  assert_equal("*/*", r.request_headers["accept"])
end

assert("HTTP2::Client#status") do
  r = HTTP2::Client.get test_site
  assert_equal(200, r.status)
end

assert("HTTP2::Client#uri,get") do
  s = HTTP2::Client.new
  s.uri = test_site
  r = s.get
  assert_equal(200, r.status)
end
