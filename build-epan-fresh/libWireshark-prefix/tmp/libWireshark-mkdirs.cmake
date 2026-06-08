# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/tmp/workspace/utoni/nDPId/libWireshark")
  file(MAKE_DIRECTORY "/tmp/workspace/utoni/nDPId/libWireshark")
endif()
file(MAKE_DIRECTORY
  "/tmp/workspace/utoni/nDPId/build-epan-fresh/libWireshark-prefix/src/libWireshark-build"
  "/tmp/workspace/utoni/nDPId/build-epan-fresh/libWireshark-prefix"
  "/tmp/workspace/utoni/nDPId/build-epan-fresh/libWireshark-prefix/tmp"
  "/tmp/workspace/utoni/nDPId/build-epan-fresh/libWireshark-prefix/src/libWireshark-stamp"
  "/tmp/workspace/utoni/nDPId/build-epan-fresh/libWireshark-prefix/src"
  "/tmp/workspace/utoni/nDPId/build-epan-fresh/libWireshark-prefix/src/libWireshark-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/tmp/workspace/utoni/nDPId/build-epan-fresh/libWireshark-prefix/src/libWireshark-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/tmp/workspace/utoni/nDPId/build-epan-fresh/libWireshark-prefix/src/libWireshark-stamp${cfgdir}") # cfgdir has leading slash
endif()
