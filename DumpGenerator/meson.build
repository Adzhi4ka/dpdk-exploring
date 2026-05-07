project('dump_generator', 'cpp', version: '1', default_options: ['cpp_std=c++17'])

dpdk = dependency('libdpdk', method: 'pkg-config')
cpp = meson.get_compiler('cpp') 
pcap_dep = cpp.find_library('pcap', required: true)

src_files = [
  'bin/main.cpp',
  'lib/Generators/ManualGenerator.hpp',
  'lib/Generators/RealGenerator.hpp',
  'lib/Generators/TrashGenerator.hpp',
  'lib/GeneratorContainer.hpp'
]

executable('dump_generator', src_files, dependencies: [dpdk, pcap_dep])