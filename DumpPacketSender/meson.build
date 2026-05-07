project('dump_packet_sender', 'cpp', version: '1', default_options: ['cpp_std=c++17'])

dpdk = dependency('libdpdk', method: 'pkg-config')
cpp = meson.get_compiler('cpp') 
pcap_dep = cpp.find_library('pcap', required: true)

src_files = [
  'main.cpp'
]

executable('dump_packet_sender', src_files, dependencies: [dpdk, pcap_dep])
