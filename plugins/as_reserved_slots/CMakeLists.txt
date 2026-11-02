# as_reserved_slots — Plugify port of the Pisex admin_system module "[AS] Reserved slots"
# (keeps public_slots server slots free for players without the reserve flag).
#
#   plugify-as_reserved_slots  the plugin shared library (entry "bin/as_reserved_slots")
#   as_reserved_slots_tests    engine-free tests (build/tests/as_reserved_slots_tests)
#
# Pure s2sdk, no pisexcompat and no s2guard (docs/PLUGIN_STANDARD.md §7). The guards of
# handoff/weaponskins/PITFALLS.md live in src/plugin.cpp itself — the B1/B2 map gate, the C2
# client checks, the B6 reconcile, the C13 player_disconnect event and the A7/C12 unload rules.
# Like every admin_system module the .so compiles the binding globals the plugify module fills at
# load time:
#   * s2sdk (__s2sdk_*),
#   * the generated admin_system consumer bindings (__admin_system_*) plus the hand-written
#     consumer wrapper include/admin_api.hpp.
# The config is read by the self-contained KV1 reader in src/kv1.hpp / src/config.hpp.

set(AS_RESERVED_SLOTS_VERSION "1.1.0")

# The generated admin_system binding globals (__admin_system_*) have to be compiled into every
# consumer plugin. plugins/admin_system is configured before plugins/as_reserved_slots and
# defines `admin_system_bindings_obj`. An exported standalone repository carries only the checked
# in include/ tree and no sibling CMakeLists.txt, so this is the private fallback over the same
# generated .cpp. Its target name is plugin-specific on purpose: it can never collide with the
# admin_system plugin's target or with another consumer's fallback.
if(TARGET admin_system_bindings_obj)
    set(AS_RESERVED_SLOTS_ADMIN_BINDING_OBJECTS "$<TARGET_OBJECTS:admin_system_bindings_obj>")
elseif(EXISTS
        "${CMAKE_SOURCE_DIR}/plugins/admin_system/include/external/plugify/include/admin_system/admin_system.cpp")
    add_library(admin_system_bindings_as_reserved_slots OBJECT
            "${CMAKE_SOURCE_DIR}/plugins/admin_system/include/external/plugify/include/admin_system/admin_system.cpp")
    target_include_directories(admin_system_bindings_as_reserved_slots SYSTEM PUBLIC
            "${CMAKE_SOURCE_DIR}/plugins/admin_system/include/external/plugify/include"
            "${CMAKE_SOURCE_DIR}/sdk/include")
    target_compile_definitions(admin_system_bindings_as_reserved_slots PUBLIC _GLIBCXX_USE_CXX11_ABI=1)
    set(AS_RESERVED_SLOTS_ADMIN_BINDING_OBJECTS
            "$<TARGET_OBJECTS:admin_system_bindings_as_reserved_slots>")
else()
    message(FATAL_ERROR "as_reserved_slots needs the generated admin_system consumer bindings (plugins/admin_system/include/external/plugify/include/admin_system/admin_system.cpp)")
endif()

add_library(plugify-as_reserved_slots SHARED
        src/plugin.cpp
        $<TARGET_OBJECTS:s2sdk_bindings>
        ${AS_RESERVED_SLOTS_ADMIN_BINDING_OBJECTS}
)
target_include_directories(plugify-as_reserved_slots PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
# SYSTEM: the generated plg/s2sdk/admin_system headers and admin_api.hpp are not ours to fix;
# their warnings must not fail -Werror on our sources.
target_include_directories(plugify-as_reserved_slots SYSTEM PRIVATE
        "${CMAKE_SOURCE_DIR}/sdk/include"
        "${CMAKE_SOURCE_DIR}/plugins/admin_system/include"
        "${CMAKE_SOURCE_DIR}/plugins/admin_system/include/external/plugify/include"
)
target_link_libraries(plugify-as_reserved_slots PRIVATE
        plugify_sdk
        -static-libstdc++ -static-libgcc
)
target_compile_options(plugify-as_reserved_slots PRIVATE -Wall -Wextra -Werror)
target_compile_definitions(plugify-as_reserved_slots PRIVATE
        _GLIBCXX_USE_CXX11_ABI=1
        PLUGIFY_MODULE="as_reserved_slots"
        PLUGIFY_IS_DEBUG=0
        PLUGIFY_IS_RELEASE=1
)
set_target_properties(plugify-as_reserved_slots PROPERTIES OUTPUT_NAME as_reserved_slots)

if(UNIX AND NOT APPLE)
    target_link_options(plugify-as_reserved_slots PRIVATE
            "-Wl,--version-script,${CMAKE_CURRENT_SOURCE_DIR}/sym/version_script.lds")
endif()

configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/as_reserved_slots.pplugin.in"
        "${CMAKE_CURRENT_BINARY_DIR}/as_reserved_slots.pplugin"
)

# --- tests ---------------------------------------------------------------------
# as_reserved_slots_tests: engine-free. The plugin TU is compiled into the test (its handlers live
# in an anonymous namespace) and every __s2sdk_* / __admin_system_* binding slot is a recording
# fake. Covered: the KV1 reader/config paths and defaults, the B1/B2 map gate, slot reuse and the
# auth/connect ordering, reserved/full behaviour, the missing-core/binding fail-soft rule (a full
# server produces zero kicks), bots and the A7/C12 teardown. Written into build/tests so
# ../test.sh runs it with the rest (*_tests convention).
#
# The top-level CMakeLists declares the PLUGIFY_PORT_TESTS option *after* the plugin directories,
# so on a first configure it is not defined here yet: default it to the same ON. An explicit
# -DPLUGIFY_PORT_TESTS=OFF (the exported standalone build) is already in the cache and still wins.
if(NOT DEFINED PLUGIFY_PORT_TESTS)
    set(PLUGIFY_PORT_TESTS ON)
endif()
if(PLUGIFY_PORT_TESTS)
    add_executable(as_reserved_slots_tests
            tests/as_reserved_slots_tests.cpp
            $<TARGET_OBJECTS:s2sdk_bindings>
            ${AS_RESERVED_SLOTS_ADMIN_BINDING_OBJECTS}
    )
    target_include_directories(as_reserved_slots_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_include_directories(as_reserved_slots_tests SYSTEM PRIVATE
            "${CMAKE_SOURCE_DIR}/sdk/include"
            "${CMAKE_SOURCE_DIR}/plugins/admin_system/include"
            "${CMAKE_SOURCE_DIR}/plugins/admin_system/include/external/plugify/include"
    )
    target_link_libraries(as_reserved_slots_tests PRIVATE plugify_sdk -static-libstdc++ -static-libgcc)
    target_compile_options(as_reserved_slots_tests PRIVATE -Wall -Wextra -Werror)
    target_compile_definitions(as_reserved_slots_tests PRIVATE
            _GLIBCXX_USE_CXX11_ABI=1
            PLUGIFY_MODULE="as_reserved_slots"
            PLUGIFY_IS_DEBUG=0
            PLUGIFY_IS_RELEASE=1
    )
    set_target_properties(as_reserved_slots_tests PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
endif()
