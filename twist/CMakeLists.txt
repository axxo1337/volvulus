cmake_minimum_required(VERSION 4.0.3)

project(VolvulusTwist)

set(CMAKE_CXX_STANDARD 17)

find_path(OPENLDAP_INCLUDE_DIR ldap.h)
find_library(OPENLDAP_LIBRARIES NAMES ldap)
find_library(LBER_LIBRARIES NAMES lber)

file(GLOB SOURCES "src/*.cpp")

add_executable(VolvulusTwist ${SOURCES})
target_link_libraries(VolvulusTwist ${OPENLDAP_LIBRARIES})
target_include_directories(VolvulusTwist PRIVATE ${LDAP_INCLUDE_DIRS} include)