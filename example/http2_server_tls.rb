root_dir = "/usr/local/trusterd"

s = HTTP2::Server.new({

  :port           => 8081,
  :server_name    => "mruby-http2 server",
  :document_root  => "#{root_dir}/htdocs",
  :key            => "#{root_dir}/ssl/server.key",
  :crt            => "#{root_dir}/ssl/server.crt",

  :daemon => true,
})

s.run
