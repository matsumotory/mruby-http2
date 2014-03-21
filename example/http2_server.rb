s = HTTP2::Server.new({
  :port   =>  8080, 
  :key    =>  "/path/to/server.key", 
  :crt    =>  "/path/to/server.crt",
  :document_root => "/path/to/docment_root",
  :server_name => "mruby-http2 server",
  :debug  =>  true,
})

s.run
