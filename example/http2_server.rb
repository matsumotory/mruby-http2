root_dir = "/usr/local/trusterd"

s = HTTP2::Server.new({

  :port           => 8080,
  :document_root  => "#{root_dir}/htdocs",
  :server_name    => "mruby-http2 server",

  :tls => false,
  :daemon => true,
})

s.run
