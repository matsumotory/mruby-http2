MRuby::Build.new do |conf|
  toolchain :gcc
  conf.gembox 'default'

  # link other mrbgem for now; catch segfault bug when rake all test; 2014/05/06
  conf.gem :github => "iij/mruby-io"
  conf.gem :github => "iij/mruby-socket"
  conf.gem :github => "iij/mruby-pack"
  conf.gem :github => "matsumoto-r/mruby-simplehttp"
  conf.gem '../mruby-http2'
end
