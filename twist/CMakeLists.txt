cmake_minimum_required(VERSION 4.0.3)

project(VolvulusTwist)

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LDAP REQUIRED ldap)

file(GLOB SOURCES "src/*.cpp")

add_executable(VolvulusTwist ${SOURCES})
target_link_libraries(VolvulusTwist 
    ${LDAP_LIBRARIES} 
    include
)
target_include_directories(VolvulusTwist PRIVATE ${LDAP_INCLUDE_DIRS})