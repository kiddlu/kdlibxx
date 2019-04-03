cmake_minimum_required(VERSION 3.5)
project(c-call-lua)

aux_source_directory(. SOURCE_FILES)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

target_link_libraries(${PROJECT_NAME} -lluajit-5.1)
