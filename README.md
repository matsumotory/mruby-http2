# HTTP2 Module for mruby  [![Build Status](https://travis-ci.org/matsumoto-r/mruby-http2.png?branch=master)](https://travis-ci.org/matsumoto-r/mruby-http2)
HTTP2 module for mruby. You can access Web site using HTTP/2.0 protocol from mruby applications or devices with mruby.

- [HTTP/2.0](http://http2.github.io/) 

    HTTP/2.0 is a replacement for how HTTP is expressed "on the wire". It is not a ground-up rewrite of the protocol; HTTP methods, status codes and semantics will be the same, and it should be possible to use the same APIs as HTTP/1.x (possibly with some small additions) to represent the protocol.

## TODO
This mrbgem is very early version.
- replace uri parser to mruby-http
- implement some method (post...)
- implement some class (Server, Proxy...)
- write HTTP2 callback function by Ruby block

## example
- HTTP2 by mruby

```ruby
r = HTTP2::Client.get 'https://106.186.112.116/'

r
r.body
r.request_headers
r.response_headers
r.status
r.body
r.body_length
r.stream_id
```

- response

```ruby
#r

{
  :body=>"---- snip ----", 
  :body_length=>1400, 
  :stream_id=>1, 
  :frame_send_header_goway=>true, 
  :recieve_bytes=>1400.0, 
  :request_headers=>{
    ":path"=>"/", 
    ":scheme"=>"https", 
    "user-agent"=>"mruby-http2/0.0.1", 
    ":authority"=>"106.186.112.116", 
    ":method"=>"GET", 
    "accept"=>"*/*"
  }, 
  :response_headers=>{
    "last-modified"=>"Wed, 18 Dec 2013 15:12:23 GMT", 
    "etag"=>"\"52b1bb57-2450\"", 
    "x-varnish"=>"340171131", 
    "content-length"=>"9296", 
    "date"=>"Tue, 31 Dec 2013 11:04:13 GMT", 
    "age"=>"0", 
    "accept-ranges"=>"bytes", 
    "content-type"=>"text/html", 
    ":status"=>"200", 
    "server"=>"nginx/1.4.1 (Ubuntu)", 
    "via"=>"1.1 varnish, 1.1 nghttpx"
  }
}

#r,status
200

#r.request_headers
{
  ":path"=>"/",
  ":scheme"=>"https",
  "user-agent"=>"mruby-http2/0.0.1",
  ":authority"=>"106.186.112.116",
  ":method"=>"GET",
  "accept"=>"*/*"
}

#r.response_headers
{
  "last-modified"=>"Wed, 18 Dec 2013 15:12:23 GMT",
  "etag"=>"\"52b1bb57-2450\"",
  "x-varnish"=>"340171131",
  "content-length"=>"9296",
  "date"=>"Tue, 31 Dec 2013 11:04:13 GMT",
  "age"=>"0",
  "accept-ranges"=>"bytes",
  "content-type"=>"text/html",
  ":status"=>"200",
  "server"=>"nginx/1.4.1 (Ubuntu)",
  "via"=>"1.1 varnish, 1.1 nghttpx"
}

#r.body

```

## install by mrbgems
 - Download

```
git clone https://github.com/mruby/mruby.git
git clone https://github.com/matsumoto-r/mruby-http2.git
```

 - nghttp2 build

```
cd mruby-http2
git submodule init
git submodule update
cd src/nghttp2
autoreconf -i
automake
autoconf
./configure
make
cd ../../../
```

 - add conf.gem line to `build_config.rb`

```
cd mruby
```
```ruby
MRuby::Build.new do |conf|

  # ... (snip) ...

  conf.gem '../mruby-http2'
end
```

 - build

```
rake
```

# License
under the MIT License:

* http://www.opensource.org/licenses/mit-license.php


