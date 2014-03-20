MRuby::Gem::Specification.new('mruby-http2') do |spec|
  spec.license = 'MIT'
  spec.authors = 'MATSUMOTO Ryosuke'
  spec.linker.libraries << ['ssl', 'crypto', 'z', 'event', 'event_openssl']
  spec.linker.flags_before_libraries << "../mruby-http2/src/nghttp2/lib/.libs/libnghttp2.a"
  spec.cc.flags << '-I../mruby-http2/src/nghttp2/lib/includes'

  require 'open3'

  nghttp2_dir = "#{build_dir}/src/nghttp2"

  def run_command(env, command)
    STDOUT.sync = true
    Open3.popen2e(env, command) do |stdin, stdout, thread|
      print stdout.read
      fail "#{command} failed" if thread.value != 0
    end
  end

  Dir.chdir nghttp2_dir do
    e = {}
    run_command e, 'git submodule init'
    run_command e, 'git submodule update'
    run_command e, 'autoreconf -i'
    run_command e, 'automake'
    run_command e, 'autoconf'
    run_command e, './configure'
    run_command e, 'make'
  end

end
