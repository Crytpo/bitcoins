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

#include "mqprot.h"
#include "oracle.h"

#include <cstdlib>
#include <cstring>

#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// remote oracle

remote_oracle::remote_oracle(const char* socket_name) : fd_(-1)
{
  fd_ = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd_ != -1)
  {
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socket_name, sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

    if (connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1)
    {
      close(fd_);
      fd_ = -1;
    }
  }
}

remote_oracle::~remote_oracle()
{
  stop();
}

remote_oracle::operator bool() const
{
  return fd_ != -1;
}

remote_oracle::record remote_oracle::request_ciphertext()
{
  control_message cm{};
  cm.cmd = REQUEST_CIPHERTEXT;
  if (send(fd_, &cm, sizeof(cm), 0) == -1)
  {
    stop();
    return record();
  }

  result_message rm{};
  const auto received = recv(fd_, &rm, sizeof(rm), 0);
  if (received == -1 || rm.status != OK)
  {
    stop();
    return record();
  }

  record record;
  record.header = rm.ciphertext.header;
  record.iv     = rm.ciphertext.iv;
  record.ciphertext.resize(rm.ciphertext.data_size);
  std::memcpy(record.ciphertext.data(), rm.ciphertext.data.data(), record.ciphertext.size());

  return record;
};

remote_oracle::record remote_oracle::request_challenge(uint16_t size)
{
  control_message cm{};
  cm.cmd                              = REQUEST_CHALLENGE;
  cm.request_challenge.challenge_size = size;
  if (write(fd_, &cm, sizeof(cm)) == -1)
    return record();

  result_message rm{};
  const auto received = recv(fd_, &rm, sizeof(rm), 0);
  if (received == -1 || rm.status != OK)
  {
    stop();
    return record();
  }

  record record;
  record.header = rm.ciphertext.header;
  record.iv     = rm.ciphertext.iv;
  record.ciphertext.resize(rm.ciphertext.data_size);
  std::memcpy(record.ciphertext.data(), rm.ciphertext.data.data(), record.ciphertext.size());

  return record;
};

void remote_oracle::stop()
{
  if (fd_ != -1)
  {
    control_message cm{};
    cm.cmd = QUIT;
    send(fd_, &cm, sizeof(cm), 0);
    close(fd_);
    fd_ = -1;
  }
}

std::pair<bool, uint64_t> remote_oracle::decrypt(const record& record)
{
  uint64_t timing = 0;
  {
    control_message cm{};
    cm.cmd                            = SEND_CHALLENGE;
    cm.send_challenge.header          = record.header;
    cm.send_challenge.iv              = record.iv;
    cm.send_challenge.ciphertext_size = record.ciphertext.size();

    if (cm.send_challenge.ciphertext_size > cm.send_challenge.ciphertext.size())
    {
      timing = -1;
      return std::make_pair(false, timing);
    }

    std::memcpy(cm.send_challenge.ciphertext.data(), record.ciphertext.data(),
                cm.send_challenge.ciphertext_size);
    if (send(fd_, &cm, sizeof(cm), 0) == -1)
    {
      stop();
      return std::make_pair(false, timing);
    }
  }

  result_message rm{};
  const auto received = recv(fd_, &rm, sizeof(rm), 0);
  if (received == -1)
  {
    stop();
    return std::make_pair(false, timing);
  }

  timing = rm.plaintext.timing;
  if (rm.status != OK)
    return std::make_pair(false, timing);

  return std::make_pair(true, timing);
}
