# Created by yuxilong on 2026/11/24.
Pod::Spec.new do |s|
  s.name = 'BTCrypto'
  s.version = '1.0.0'
  s.summary = 'Objective-C authenticated encryption and RSA utilities for iOS.'
  s.homepage = 'https://github.com/BaiTu-iOS/BTCrypto'
  s.author = 'BaiTu-iOS'
  s.license = { :type => 'MIT', :file => 'LICENSE' }
  s.source = { :git => 'https://github.com/BaiTu-iOS/BTCrypto.git', :tag => s.version.to_s }
  s.ios.deployment_target = '15.0'
  s.requires_arc = true
  # The bundled sodium archive is static; use one copy per application.
  s.static_framework = true
  s.default_subspec = 'Core'
  s.preserve_paths = 'THIRD_PARTY_NOTICES.md', 'BTCrypto/**/LICENSE', 'BTCrypto/Sodium/libsodium.LICENSE'

  s.subspec 'Core' do |ss|
    ss.source_files = 'BTCrypto/BTCrypto.h'
    ss.dependency 'BTCrypto/Sodium'
    ss.dependency 'BTCrypto/RSATool'
  end

  s.subspec 'Sodium' do |ss|
    ss.source_files = 'BTCrypto/Sodium/SodiumCrypto.{h,m}'
    ss.dependency 'BTCrypto/Runtime'
  end

  s.subspec 'Runtime' do |ss|
    ss.source_files = 'BTCrypto/Sodium/NAChloride/*.{h,m}', 'BTCrypto/Sodium/SodiumObjc/*.{h,m}'
    ss.dependency 'BTCrypto/Headers'
    ss.vendored_frameworks = 'BTCrypto/Sodium/libsodium.xcframework'
    ss.frameworks = 'Security'
  end

  s.subspec 'Headers' do |ss|
    ss.source_files = 'BTCrypto/Sodium/include/**/*.h'
  end

  s.subspec 'RSATool' do |ss|
    ss.source_files = 'BTCrypto/RSATool/*.{h,m}'
    ss.frameworks = 'Security'
  end
end
