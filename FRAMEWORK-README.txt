/*! \mainpage README
    \verbatim
===============================================================================
                           IT Security Framework
===============================================================================

-------------------------------------------------------------------------------
                              Dependencies
-------------------------------------------------------------------------------

* cmake >= 3.0
* check
* g++ >= 4.9

-------------------------------------------------------------------------------
                             Directory structure
-------------------------------------------------------------------------------
ROOT
|-build...........................Files for building (Makefile).
|-cmake...........................Modules for the CMake build system.
|-doc.............................Contains a doxygen template.
|-tls.............................Sources for the TLS tasks
|-blockhain.......................Sources for the blockchain task

-------------------------------------------------------------------------------
                           Building the Framework
-------------------------------------------------------------------------------
The framework uses a CMake powered build system. The building process using
this system consist of two steps. In the first one the build is configured
using CMake. The actual building is done in the second step using the
generated build tool. On Linux systems this build tool is usually make.

Configuring the project using CMake:
------------------------------------
Call "./run_cmake.sh clean" to clean the cmake build.
Call "./run_cmake.sh build Debug" to build the framework with debug constants.
Call "./run_cmake.sh build Release" to build the framework.

Note: Each changes to the source tree or the CMakeLists.txt file needs a new
      invocation of ./run_cmake.sh build. Some changes also require a full clean!

Per default

To modify the configuration you can either specify the needed parameters on the
command line while calling cmake (-D), or use a graphical configuration tool
like ccmake and cmake-gui.

An usage hint of the most useful make targets are displayed at the end of the
cmake execution.

Most important build targets:
-----------------------------
   all...............Builds all programs and libraries.
   suite.............Builds the test program.
   check.............Runs the test program.
   doxygen...........Builds doxygen documentation.

Building the project:
---------------------
After the configuration step you simply start the build in the generated build
system specific way. ("make" when using Makefiles, opening the project file
when using Visual Studio, ...)

###############################################################################
Example for Linux: (building the test suite using Makefiles)
 $ make suite
###############################################################################

-------------------------------------------------------------------------------
                       Running the Tests and Assignments
-------------------------------------------------------------------------------
As soon as the build step is finished the binaries can be found in
subdirectories of "<buildDir>".

Running the test suite:
-----------------------
To run the test suite simply run "make check" in the build directory. By
default, only a summary of the results is displayed. The full output of the test
programs can be found in the "LastTest.log" files, which are usually located in 
"<buildDir>/Testing/Temporary/".

Running attack programs:
-------------------------------------------------------------------------------
Executing these attack programs is quite similar to the executing of a test
program. Simply run the desired attack and provide the challenge data file
and/or the desired attack method as command line parameter.
Executing the test programs without a parameter will print out usage help.
When the attack is successful, the result is automatically written to disk
next to the challenge file or in a provided result folder (.res or
.sol suffix).

###############################################################################
Example for Linux: (Run attack on random number generators)
 $ cd <buildDir>
 $ make
 $ make tls_local_tsc # run the attack
###############################################################################

  \endverbatim
*/
