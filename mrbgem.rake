MRuby::Gem::Specification.new('mruby-http2') do |spec|
  spec.license = 'MIT'
  spec.authors = 'MATSUMOTO Ryosuke'
  spec.linker.libraries << ['ssl', 'crypto', 'z', 'event', 'event_openssl']
  spec.linker.flags_before_libraries << "../mruby-http2/src/nghttp2/lib/.libs/libnghttp2.a"
  spec.cc.flags << '-I../mruby-http2/src/nghttp2/lib/includes'
end
