#!/bin/bash

# Location of CMakeLists.txt file
CMAKE_LOC=..

# Location of cmake build
CMAKE_BUILD=build

help() {
  echo "No or invalid arguments supplied!";
  echo "Help";
  echo "====";
  echo "Setup cmake build by calling:";
  echo "$0 build         # (re)run cmake build ${BUILD_TYPE}";
  echo "$0 build Debug   # (re)run cmake build Debug version";
  echo "$0 build Release # (re)run cmake build Release version";
  echo "$0 clean         # clean cmake build";
}

if [ $# -eq 0 ]; then
  help;
  exit 1;
fi

if [ "$1" = "build" ]; then
  mkdir -p ${CMAKE_BUILD};
  cd ${CMAKE_BUILD};
  if [ $# -eq 2 ]; then
    cmake -DCMAKE_BUILD_TYPE=$2 ${CMAKE_LOC};
  else
    cmake ${CMAKE_LOC};
  fi
  exit 0;
fi

if [ "$1" = "clean" ]; then
  rm --force -r ${CMAKE_BUILD};
  exit 0;
fi

help
exit 1;
