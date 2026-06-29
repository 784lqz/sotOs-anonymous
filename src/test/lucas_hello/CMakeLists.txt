# Marker target for the L1 hello fixture · the binary is pre-built and
# committed; CMake doesn't compile it. We expose its path as a variable
# for the rootserver's CPIO bundling step (see src/root/CMakeLists.txt).

set(LUCAS_HELLO_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/hello-linux.bin"
    CACHE FILEPATH "Path to the pre-built static Linux hello ELF"
    FORCE)

if(NOT EXISTS "${LUCAS_HELLO_BIN}")
    message(WARNING "lucas_hello: ${LUCAS_HELLO_BIN} not found · rebuild per README.md")
endif()
