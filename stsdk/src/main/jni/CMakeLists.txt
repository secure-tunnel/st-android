cmake_minimum_required(VERSION 3.10.0)

set(CMAKE_VERBOSE_MAKEFILE ON)

set(INC_DIR openssl/include/ security/)
set(CFLAGS -fexceptions -frtti -DANDROID_LOG -pthread  -Wall -O2 -g)
set(LINK_DIR openssl/${ANDROID_ABI}/lib)
set(LINKED_LIBRARIES ssl crypto)

SET(LOCAL_SRC_FILES security/security.c)

include_directories(${INC_DIR})
add_definitions(${CFLAGS})
link_directories(${LINK_DIR})

add_library(bmf_security SHARED ${LOCAL_SRC_FILES})
find_library(log-lib log)
target_link_libraries(bmf_security ${log-lib} ${LINKED_LIBRARIES})
