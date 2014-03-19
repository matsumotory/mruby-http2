#assert("SPDY::Response#request_headers") do
#  r = HTTP2::Client.get "https://106.186.112.116/"
#  assert_equal("GET", r.request_headers[":method"])
#  assert_equal("/", r.request_headers[":path"])
#  assert_equal("https", r.request_headers[":scheme"])
#  assert_equal("106.186.112.116", r.request_headers[":authority"])
#  assert_equal("*/*", r.request_headers["accept"])
#end
#
#assert("SPDY::Response#status") do
#  r = HTTP2::Client.get "https://106.186.112.116/"
#  assert_equal(200, r.status)
#end
