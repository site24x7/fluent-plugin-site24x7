lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name    = "fluent-plugin-site24x7"
  spec.version = "0.1.4"
  spec.authors = ["Magesh Rajan"]
  spec.email   = ["magesh.rajan@zohocorp.com"]

  spec.summary       = %q{Site24x7 output plugin for Fluent event collector.}
  spec.homepage      = "https://github.com/site24x7/fluent-plugin-site24x7"
  spec.license       = ""

  test_files, files  = `git ls-files -z`.split("\x0").partition do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.files         = files
  spec.executables   = files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = test_files
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 2.2.24"
  spec.add_development_dependency "rake", "~> 13.0.3"
  spec.add_development_dependency "test-unit", "~> 3.3.7"
  spec.add_development_dependency "yajl-ruby", "~> 1.2"
  spec.add_development_dependency 'webmock', '~> 3.5', '>= 3.5.0'

  spec.add_runtime_dependency "fluentd", [">= 0.14.10", "< 2"]
  spec.add_runtime_dependency "net-http-persistent", '~> 3.1'


end
