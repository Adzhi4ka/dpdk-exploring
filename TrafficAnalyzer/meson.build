project('traffic_analyzer', 'cpp', version: '0.5', default_options: ['cpp_std=c++17'])

dpdk = dependency('libdpdk', method: 'pkg-config')

src_files = [
  'bin/main.cpp',
  'lib/PacketCheckers/IPv4Filter.hpp',
  'lib/PacketCheckers/IPv4Filter.hpp',
  'lib/PacketCheckers/FilterDecorator.hpp',
  'lib/FilterContainer.hpp',
  'lib/TrafficAnalyzer.hpp',
  'lib/TrafficReader.hpp'
]

executable('traffic_analyzer', src_files, dependencies: dpdk)
