test_site = 'https://127.0.0.1:8081/index.html'

assert("HTTP2::Client#request_headers") do
  r = HTTP2::Client.get test_site
  assert_equal("GET", r.method)
  assert_equal("/index.html", r.path)
  assert_equal("https", r.scheme)
  assert_equal("127.0.0.1:8081", r.authority)
  assert_equal("*/*", r.accept)
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
