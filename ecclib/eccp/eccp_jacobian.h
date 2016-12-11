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

#ifndef ECCP_JACOBIAN_H_
#define ECCP_JACOBIAN_H_

#include "../types.h"

#ifdef __cplusplus
extern "C" {
#endif

int eccp_jacobian_point_is_valid(const eccp_point_projective_t* a, const eccp_parameters_t* param);

int eccp_jacobian_point_equals(const eccp_point_projective_t* a, const eccp_point_projective_t* b,
                               const eccp_parameters_t* param);
void eccp_jacobian_point_copy(eccp_point_projective_t* dest, const eccp_point_projective_t* src,
                              const eccp_parameters_t* param);

void eccp_jacobian_to_affine(eccp_point_affine_t* res, const eccp_point_projective_t* a,
                             const eccp_parameters_t* param);

void eccp_affine_to_jacobian(eccp_point_projective_t* res, const eccp_point_affine_t* a,
                             const eccp_parameters_t* param);

void eccp_jacobian_point_double(eccp_point_projective_t* res, const eccp_point_projective_t* a,
                                const eccp_parameters_t* param);

void eccp_jacobian_point_add(eccp_point_projective_t* res, const eccp_point_projective_t* a,
                             const eccp_point_projective_t* b, const eccp_parameters_t* param);

void eccp_jacobian_point_add_affine(eccp_point_projective_t* res, const eccp_point_projective_t* a,
                                    const eccp_point_affine_t* b, const eccp_parameters_t* param);

void eccp_jacobian_point_negate(eccp_point_projective_t* res, const eccp_point_projective_t* P,
                                const eccp_parameters_t* param);

void eccp_jacobian_point_multiply_L2R_DA(eccp_point_affine_t* result, const eccp_point_affine_t* P,
                                         const gfp_t scalar, const eccp_parameters_t* param);

void eccp_jacobian_point_multiply_R2L_DA(eccp_point_affine_t* result, const eccp_point_affine_t* P,
                                         const gfp_t scalar, const eccp_parameters_t* param);

void eccp_jacobian_point_multiply_L2R_NAF(eccp_point_affine_t* result, const eccp_point_affine_t* P,
                                          const gfp_t scalar, const eccp_parameters_t* param);

void eccp_jacobian_point_multiply_COMB(eccp_point_affine_t* result,
                                       const eccp_point_affine_t* P_table, const unsigned int width,
                                       const gfp_t scalar, const eccp_parameters_t* param);

void eccp_jacobian_point_multiply_COMB_precompute(eccp_point_affine_t* P_table,
                                                  const eccp_point_affine_t* P, const int width,
                                                  const eccp_parameters_t* param);

#ifdef __cplusplus
}
#endif

#endif /* ECCP_JACOBIAN_H_ */
