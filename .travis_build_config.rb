MRuby::Build.new do |conf|
  toolchain :gcc
  conf.gembox 'default'

  # link other mrbgem for now; catch segfault bug when rake all test; 2014/05/06
  conf.gem :github => "iij/mruby-io"
  conf.gem :github => "iij/mruby-socket"
  conf.gem :github => "iij/mruby-pack"
  conf.gem :github => "matsumotory/mruby-simplehttp"
  conf.gem '../mruby-http2'
end

MRuby::Build.new('test') do |conf|
  # Gets set by the VS command prompts.
  if ENV['VisualStudioVersion'] || ENV['VSINSTALLDIR']
    toolchain :visualcpp
  else
    toolchain :gcc
  end

  enable_debug
  conf.enable_bintest
  conf.enable_test

  conf.gembox 'default'
end

