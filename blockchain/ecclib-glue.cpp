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

#include "ecclib-glue.h"

#include "../ecclib/utils/param.h"
#include "../ecclib/utils/rand.h"
#include "../tls/random.h"

extern "C" {

static uint_t rand_impl(void)
{
  uint_t v = 0;
  get_random_data(reinterpret_cast<uint8_t*>(&v), sizeof(v));
  return v;
}

}

eccp_parameters_t secp256_params;

void __attribute__((constructor)) init_ecclib_glue()
{
  rand_f = &rand_impl;

  param_load(&secp256_params, SECP256R1);
}
