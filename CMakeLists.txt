cmake_minimum_required(VERSION 3.22)
cmake_policy(SET CMP0074 NEW)
cmake_policy(SET CMP0091 NEW)

set(CMAKE_SYSTEM_NAME Windows)
set(POLYHOOK_BUILD_SHARED_LIB OFF)

set(POLYHOOK_LIB PolyHook_2)
if(POLYHOOK_VENDORED)
    add_subdirectory(PolyHook_2_0)
elseif()
    find_package(PolyHook_2 CONFIG REQUIRED)
    set(POLYHOOK_LIB PolyHook_2::PolyHook_2)
endif()

file(GLOB HOOKUTILS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
add_library(hookutils STATIC ${HOOKUTILS_SOURCES})
target_include_directories(hookutils
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(hookutils ${POLYHOOK_LIB})