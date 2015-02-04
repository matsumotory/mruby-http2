# HTTP2 Module for mruby 

[![Build Status](https://travis-ci.org/trusterd/mruby-http2.svg?branch=master)](https://travis-ci.org/trusterd/mruby-http2)
[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/trusterd/mruby-http2?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

HTTP2 module for mruby using [nghttp2](https://github.com/tatsuhiro-t/nghttp2). You can access Web site using HTTP/2 protocol from mruby applications or devices with mruby, and run HTTP/2 Web server easily.

- [HTTP/2 Web Server by mruby-http2](https://github.com/trusterdmruby-http2/blob/master/README.md#http2server)
- [HTTP/2 Client by mruby-http2](https://github.com/trusterd/mruby-http2/blob/master/README.md#http2client)

#### [HTTP/2](http://http2.github.io/) 

HTTP/2 is a replacement for how HTTP is expressed "on the wire". It is not a ground-up rewrite of the protocol; HTTP methods, status codes and semantics will be the same, and it should be possible to use the same APIs as HTTP/1.x (possibly with some small additions) to represent the protocol.

## [Trusterd HTTP/2 Web Server](https://github.com/trusterd/trusterd)
[Trusterd](https://github.com/trusterd/trusterd) is a HTTP/2 Web Server implementation using mruby-http2.

## Benchmark
Please see [link](https://gist.github.com/matsumoto-r/9702123).

## Install by mrbgems
#### Download mruby
```
git clone https://github.com/mruby/mruby.git
```
#### Add conf.gem line to `mruby/build_config.rb`
```ruby
MRuby::Build.new do |conf|

  # ... (snip) ...

  conf.gem :github => 'trusterd/mruby-http2'
end
```

#### build
```
cd mruby
rake
```

## Example
### mruby-http2 Test Site
```
https://http2.matsumoto-r.jp:58080/index.html
```
### HTTP2::Client
##### HTTP2 get
Access to nghttpd HTTP/2 Server
```ruby
r = HTTP2::Client.get 'https://127.0.0.1:8080/index.html'

r.response
r.body
r.request_headers
r.response_headers
r.status
r.body
r.body_length
r.stream_id
```
##### HTTP2 get reuslt
```ruby
{:body=>"hello mruby-http2!!\n", :body_length=>20, :recieve_bytes=>20.0, :response_headers=>{"last-modified"=>"Wed, 19 Mar 2014 08:41:00 GMT", "server"=>"nghttpd nghttp2/0.4.0-DEV", ":status"=>"200", "date"=>"Thu, 20 Mar 2014 11:38:17 GMT", "cache-control"=>"max-age=3600", "content-length"=>"20"}, :frame_send_header_goway=>true, :request_headers=>{"user-agent"=>"mruby-http2/0.0.1", "accept"=>"*/*", ":authority"=>"127.0.0.1:8080", ":scheme"=>"https", "accept-encoding"=>"gzip", ":method"=>"GET", ":path"=>"/index.html"}, :stream_id=>1}
"hello mruby-http2!!\n"
{"user-agent"=>"mruby-http2/0.0.1", "accept"=>"*/*", ":authority"=>"127.0.0.1:8080", ":scheme"=>"https", "accept-encoding"=>"gzip", ":method"=>"GET", ":path"=>"/index.html"}
{"last-modified"=>"Wed, 19 Mar 2014 08:41:00 GMT", "server"=>"nghttpd nghttp2/0.4.0-DEV", ":status"=>"200", "date"=>"Thu, 20 Mar 2014 11:38:17 GMT", "cache-control"=>"max-age=3600", "content-length"=>"20"}
200
"hello mruby-http2!!\n"
20
1
```
##### Set callback block from Ruby
Access to nghttpd HTTP/2 Server
```ruby
r = HTTP2::Client.get 'https://127.0.0.1:8080/index.html'

p r.response
p r.body
p r.request_headers
p r.response_headers
p r.status
p r.body
p r.body_length
p r.stream_id

p "---- set callback version ----"

s = HTTP2::Client.new
s.uri = 'https://127.0.0.1:8080/index.html'
s.on_header_callback {
  p "header callback"
}
s.send_callback {
  p "send_callback"
}
s.recv_callback {
  p "recv_callback"
}
s.before_frame_send_callback {
  p "before_frame_send_callback"
}
s.on_frame_send_callback {
  p "on_frame_send_callback"
}
s.on_frame_recv_callback {
  p "on_frame_recv_callback"
}
s.on_stream_close_callback {
  p "on_stream_close_callback"
}
s.on_data_chunk_recv_callback {
  p "on_data_chunk_recv_callback"
}
r = s.get
p r.response

```
##### Result
```ruby
"---- set callback version ----"
"recv_callback"
"on_frame_recv_callback"
"recv_callback"
"before_frame_send_callback"
"send_callback"
"on_frame_send_callback"
"before_frame_send_callback"
"send_callback"
"on_frame_send_callback"
"recv_callback"
"header callback"
"header callback"
"header callback"
"header callback"
"header callback"
"header callback"
"on_frame_recv_callback"
"on_data_chunk_recv_callback"
"on_frame_recv_callback"
"on_frame_recv_callback"
"on_stream_close_callback"
"recv_callback"
"before_frame_send_callback"
"send_callback"
"on_frame_send_callback"
{:body=>"hello mruby-http2!!\n", :body_length=>20, :recieve_bytes=>20.0, :response_headers=>{"last-modified"=>"Wed, 19 Mar 2014 08:41:00 GMT", "server"=>"nghttpd nghttp2/0.4.0-DEV", ":status"=>"200", "date"=>"Thu, 20 Mar 2014 11:39:34 GMT", "cache-control"=>"max-age=3600", "content-length"=>"20"}, :frame_send_header_goway=>true, :request_headers=>{"user-agent"=>"mruby-http2/0.0.1", "accept"=>"*/*", ":authority"=>"127.0.0.1:8080", ":scheme"=>"https", "accept-encoding"=>"gzip", ":method"=>"GET", ":path"=>"/index.html"}, :stream_id=>1}
```
### HTTP2::Server
##### run HTTP/2 server
###### If you want to get more information, Please see [Trusterd HTTP/2 Web Server](https://github.com/trusterd/trusterd) using mruby-http2.
```ruby
root_dir = "/usr/local/trusterd"

s = HTTP2::Server.new({

  :port           => 8080,
  :document_root  => "#{root_dir}/htdocs",
  :server_name    => "mruby-http2 server",

  :key            => "#{root_dir}/ssl/server.key",
  :crt            => "#{root_dir}/ssl/server.crt",

})

s.run
```
##### request from HTTP2::Client 
```ruby
r = HTTP2::Client.get 'https://127.0.0.1:8080/index.html'

p r.response
p r.body
p r.request_headers
p r.response_headers
p r.status
p r.body
p r.body_length
p r.stream_id

p "---- set callback version ----"

s = HTTP2::Client.new
s.uri = 'https://127.0.0.1:8080/index.html'
s.on_header_callback {
  p "header callback"
}
s.send_callback {
  p "send_callback"
}
s.recv_callback {
  p "recv_callback"
}
s.before_frame_send_callback {
  p "before_frame_send_callback"
}
s.on_frame_send_callback {
  p "on_frame_send_callback"
}
s.on_frame_recv_callback {
  p "on_frame_recv_callback"
}
s.on_stream_close_callback {
  p "on_stream_close_callback"
}
s.on_data_chunk_recv_callback {
  p "on_data_chunk_recv_callback"
}
r = s.get
p r.response
```
##### response
```ruby
{:body=>"hello mruby-http2!!\n", :body_length=>20, :recieve_bytes=>20.0, :response_headers=>{":status"=>"200"}, :frame_send_header_goway=>true, :request_headers=>{"user-agent"=>"mruby-http2/0.0.1", "accept"=>"*/*", ":authority"=>"127.0.0.1:8080", ":scheme"=>"https", "accept-encoding"=>"gzip", ":method"=>"GET", ":path"=>"/index.html"}, :stream_id=>1}
"hello mruby-http2!!\n"
{"user-agent"=>"mruby-http2/0.0.1", "accept"=>"*/*", ":authority"=>"127.0.0.1:8080", ":scheme"=>"https", "accept-encoding"=>"gzip", ":method"=>"GET", ":path"=>"/index.html"}
{":status"=>"200"}
200
"hello mruby-http2!!\n"
20
1
"---- set callback version ----"
"recv_callback"
"before_frame_send_callback"
"send_callback"
"on_frame_send_callback"
"recv_callback"
"on_frame_recv_callback"
"recv_callback"
"before_frame_send_callback"
"send_callback"
"on_frame_send_callback"
"recv_callback"
"header callback"
"on_frame_recv_callback"
"recv_callback"
"recv_callback"
"on_data_chunk_recv_callback"
"on_frame_recv_callback"
"recv_callback"
"recv_callback"
"on_frame_recv_callback"
"on_stream_close_callback"
"recv_callback"
"before_frame_send_callback"
"send_callback"
"on_frame_send_callback"
{:body=>"hello mruby-http2!!\n", :body_length=>20, :recieve_bytes=>20.0, :response_headers=>{":status"=>"200"}, :frame_send_header_goway=>true, :request_headers=>{"user-agent"=>"mruby-http2/0.0.1", "accept"=>"*/*", ":authority"=>"127.0.0.1:8080", ":scheme"=>"https", "accept-encoding"=>"gzip", ":method"=>"GET", ":path"=>"/index.html"}, :stream_id=>1}
```

# License
under the MIT License:

* http://www.opensource.org/licenses/mit-license.php

