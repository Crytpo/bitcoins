/******************************************************************************
**
** Copyright (C) 2016 Graz University of Technology
**
** Contact: itsec-team@iaik.tugraz.at
**
** IT-SECURITY LICENSE
** Version 1.2, 1st of October 2016
**
** This framework may only be used within the IT-Security exercises 2016. Only
** students that are formally registered within TUGRAZ-online may use it until
** 30th of June 2016. After that date, licensees have the duty to safely
** delete the software framework.
**
** This license does not grant you any rights to re-distribute the software,
** to change the license, to grant access to other individuals, and to
** commercially use the software.
**
** This software is distributed WITHOUT ANY WARRANTY; without even the implied
** warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
**
** If you are interested in a more reasonable license, please use the contact
** information above.
**
******************************************************************************/

#include <fstream>
#include <iostream>
#include <vector>

#include <errno.h>
#include <error.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "attack.h"
#include "clocks.h"
#include "oracle.h"

namespace
{
  constexpr char socket_name[] = "itsec-tls-socket";

  void sigusr1_handler(int)
  {
  }

  int run_attack(const std::string& sol_filename)
  {
    remote_oracle oracle(socket_name);
    if (!oracle)
    {
      std::cout << "Failed to connect." << std::endl;
      return 1;
    }

    const auto original_record = oracle.request_ciphertext();
    if (original_record.header.type != TLS_APPLICATION_DATA)
    {
      std::cout << "Failed to request ciphertext." << std::endl;
      return 1;
    }

    // Encrypt the original plain text.
    const auto recovered_plaintext = lucky13_tsc(original_record, oracle);

    std::cout << "Stopping oracle." << std::endl;

    std::ofstream ofs(sol_filename.c_str());
    if (!ofs)
    {
      std::cout << "Failed to open " << sol_filename << "." << std::endl;
      return 1;
    }

    ofs.write(reinterpret_cast<const char*>(recovered_plaintext.data()),
              recovered_plaintext.size());

    return 0;
  }
}

int main(int argc, char** argv)
{
  if (argc != 3)
    return 1;

  unlink(socket_name);

  // register signal handler for SIGUSR1
  struct sigaction act
  {
  };
  sigemptyset(&act.sa_mask);
  act.sa_handler = sigusr1_handler;
  if (sigaction(SIGUSR1, &act, nullptr) == -1)
  {
    std::cout << "Failed to set up signal handler." << std::endl;
    return 1;
  }

  const pid_t pid = fork();
  if (pid == 0)
  {
    // Start decryption oracle
    char argv0[] = "mqoracle.x86_64";
    char argv1[] = "itsec-tls-socket";

    char* newargv[] = {argv0, argv1, argv[1], nullptr};
    if (execve(argv0, newargv, nullptr) == -1)
    {
      std::cout << "Failed to exec mqoracle." << std::endl;
      return 1;
    }
  }
  else if (pid < 0)
  {
    std::cout << "Failed to fork." << std::endl;
    return 1;
  }

  sigset_t sigset;
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGUSR1);
  sigaddset(&sigset, SIGCHLD);

  siginfo_t siginfo{};
  if (sigwaitinfo(&sigset, &siginfo) == -1)
  {
    std::cout << "Ouch, something went horribly wrong." << std::endl;
    return 1;
  }

  if (siginfo.si_signo == SIGCHLD)
  {
    std::cout << "Child process quit." << std::endl;
    return 1;
  }

  const int ret = run_attack(argv[2]);
  int status    = 0;
  do
  {
    if (waitpid(pid, &status, 0) == -1)
      if (errno == EINTR)
        continue;
  } while (!WIFEXITED(status) && !WIFSIGNALED(status));

  return ret;
}
