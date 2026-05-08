# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set(SOURCES msh3_app.cpp)
add_executable(msh3app ${SOURCES})
target_link_libraries(msh3app PRIVATE msh3 )
install(TARGETS msh3app EXPORT msh3 RUNTIME DESTINATION bin)

set(SERVER_SOURCES msh3_server.cpp)
add_executable(msh3server ${SERVER_SOURCES})
target_link_libraries(msh3server PRIVATE msh3)
install(TARGETS msh3server EXPORT msh3 RUNTIME DESTINATION bin)

set(CLIENT_SOURCES msh3_client.cpp)
add_executable(msh3client ${CLIENT_SOURCES})
target_link_libraries(msh3client PRIVATE msh3)
install(TARGETS msh3client EXPORT msh3 RUNTIME DESTINATION bin)

find_package(pybind11 REQUIRED)

pybind11_add_module(pymsh3
    pymsh3_bindings.cpp
)

target_link_libraries(pymsh3 PRIVATE msh3)

install(TARGETS pymsh3
    LIBRARY DESTINATION .
)