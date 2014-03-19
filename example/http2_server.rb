s = HTTP2::Server.new({
  :port   =>  8080, 
  :key    =>  "/path/to/server.key", 
  :crt    =>  "/path/to/server.crt",
  :debug  =>  true,
})

s.run
