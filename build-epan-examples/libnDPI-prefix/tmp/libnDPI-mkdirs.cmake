# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/home/runner/work/nDPId/nDPId/libnDPI")
  file(MAKE_DIRECTORY "/home/runner/work/nDPId/nDPId/libnDPI")
endif()
file(MAKE_DIRECTORY
  "/home/runner/work/nDPId/nDPId/build-epan-examples/libnDPI-prefix/src/libnDPI-build"
  "/home/runner/work/nDPId/nDPId/build-epan-examples/libnDPI-prefix"
  "/home/runner/work/nDPId/nDPId/build-epan-examples/libnDPI-prefix/tmp"
  "/home/runner/work/nDPId/nDPId/build-epan-examples/libnDPI-prefix/src/libnDPI-stamp"
  "/home/runner/work/nDPId/nDPId/build-epan-examples/libnDPI-prefix/src"
  "/home/runner/work/nDPId/nDPId/build-epan-examples/libnDPI-prefix/src/libnDPI-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/runner/work/nDPId/nDPId/build-epan-examples/libnDPI-prefix/src/libnDPI-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/runner/work/nDPId/nDPId/build-epan-examples/libnDPI-prefix/src/libnDPI-stamp${cfgdir}") # cfgdir has leading slash
endif()
