r = HTTP2::Client.http2_get "https://http2.matsumoto-r.jp:58080/index.html"
p r.to_s

