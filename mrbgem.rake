MRuby::Gem::Specification.new('mruby-http2') do |spec|
  spec.license = 'MIT'
  spec.authors = 'MATSUMOTO Ryosuke'
  spec.version = '0.0.1'
  spec.summary = 'HTTP/2 Client and Server Module'
  spec.linker.libraries << ['ssl', 'crypto', 'z', 'event', 'event_openssl']

  require 'open3'

  nghttp2_dir = "#{build_dir}/nghttp2"
  nghttp2_lib = "#{build_dir}/nghttp2/lib/.libs"
  libnghttp2a = "#{nghttp2_lib}/libnghttp2.a"
  nghttp2_ver = "8ccb6e463d52928f6704b5a749107065f9468dc2"

  def run_command env, command
    STDOUT.sync = true
    p "exec #{command}"
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
      run_command e, "git checkout #{nghttp2_ver}"
      run_command e, 'git submodule init'
      run_command e, 'git submodule update'
      run_command e, 'autoreconf -i'
      run_command e, 'automake'
      run_command e, 'autoconf'
      run_command e, './configure'
      run_command e, 'make'
    end
  end

  spec.linker.flags_before_libraries << libnghttp2a
  spec.cc.flags << "-I#{nghttp2_dir}/lib/includes"
end
