MRuby::Gem::Specification.new('mruby-http2') do |spec|
  spec.license = 'MIT'
  spec.authors = 'MATSUMOTO Ryosuke'
  spec.version = '0.0.1'
  spec.summary = 'HTTP/2 Client and Server Module'
  spec.linker.libraries << ['ssl', 'crypto', 'z', 'event', 'event_openssl', 'curl', "nghttp2"]
  spec.add_dependency('mruby-simplehttp')

  require 'open3'

  nghttp2_dir = "#{build_dir}/nghttp2"
  nghttp2_lib = "#{build_dir}/nghttp2/lib/.libs"
  libnghttp2a = "#{nghttp2_lib}/libnghttp2.a"
  if ENV['NGHTTP2_CURRENT'] != "true"
    nghttp2_ver = "f93a2b71a17d7032a312022486f45a336c926d95"
  end

  def run_command env, command
    STDOUT.sync = true
    puts "mruby-http2 build: [exec] #{command}"
    Open3.popen2e(env, command) do |stdin, stdout, thread|
      print stdout.read
      fail "#{command} failed" if thread.value != 0
    end
  end

  FileUtils.mkdir_p build_dir

  if ! File.exists? nghttp2_dir
    Dir.chdir(build_dir) do
    e = {}
      run_command e, 'git clone https://github.com/tatsuhiro-t/nghttp2.git'
    end
  end

  if ! File.exists? libnghttp2a
    Dir.chdir nghttp2_dir do
      e = {}
    if ENV['NGHTTP2_CURRENT'] != "true"
      run_command e, "git checkout #{nghttp2_ver} ."
    end
      run_command e, 'git submodule init'
      run_command e, 'git submodule update'
      run_command e, 'autoreconf -i'
      run_command e, 'automake'
      run_command e, 'autoconf'
      if RUBY_PLATFORM =~ /darwin/i
        run_command e, './configure --disable-threads'
      else
        run_command e, './configure'
      end
      run_command e, 'make'
    end
  end

  spec.cc.include_paths << nghttp2_lib
  spec.linker.library_paths << "#{nghttp2_dir}/lib/includes"

end

