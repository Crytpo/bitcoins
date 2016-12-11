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

#ifndef ECCP_AFFINE_H_
#define ECCP_AFFINE_H_

#include "../types.h"

#ifdef __cplusplus
extern "C" {
#endif

void eccp_affine_point_clear(eccp_point_affine_t* A);

int eccp_affine_point_is_valid(const eccp_point_affine_t* A, const eccp_parameters_t* param);

int eccp_affine_point_compare(const eccp_point_affine_t* A, const eccp_point_affine_t* B,
                              const eccp_parameters_t* param);

void eccp_affine_point_copy(eccp_point_affine_t* dest, const eccp_point_affine_t* src,
                            const eccp_parameters_t* param);

void eccp_affine_point_add(eccp_point_affine_t* res, const eccp_point_affine_t* A,
                           const eccp_point_affine_t* B, const eccp_parameters_t* param);
void eccp_affine_point_double(eccp_point_affine_t* res, const eccp_point_affine_t* A,
                              const eccp_parameters_t* param);
void eccp_affine_point_negate(eccp_point_affine_t* res, const eccp_point_affine_t* P,
                              const eccp_parameters_t* param);

#ifdef __cplusplus
}
#endif

#endif /* ECCP_AFFINE_H_ */
