/*
 * t_cose_parameters.h
 *
 * Copyright 2019-2020, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_parameters_h
#define t_cose_parameters_h

#include <stdint.h>
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_common.h"
#include "qcbor/qcbor.h"




/**
 * \file t_cose_parameters.h
 *
 * \brief A list of COSE parameter labels, both integer and string.
 *
 * It is fixed size to avoid the complexity of memory management and
 * because the number of parameters is assumed to be small.
 *
 * On a 64-bit machine it is 24 * PARAMETER_LIST_MAX which is 244
 * bytes. That accommodates 10 string parameters and 10 integer parameters
 * and is small enough to go on the stack.
 *
 * On a 32-bit machine: 16 * PARAMETER_LIST_MAX = 176
 *
 * This is a big consumer of stack in this implementation.  Some
 * cleverness with a union could save almost 200 bytes of stack, as
 * this is on the stack twice.
 */
struct t_cose_label_list {
    /* Terminated by value LABEL_LIST_TERMINATOR */
    int64_t int_labels[T_COSE_PARAMETER_LIST_MAX+1];
    /*  Terminated by a NULL_Q_USEFUL_BUF_C */
    struct q_useful_buf_c tstr_labels[T_COSE_PARAMETER_LIST_MAX+1];
};


/*
 * The IANA COSE Header Parameters registry lists label 0 as
 * "reserved". This means it can be used, but only by a revision of
 * the COSE standard if it is deemed necessary for some large and good
 * reason. It cannot just be allocated by IANA as any normal
 * assignment. See [IANA COSE Registry]
 * (https://www.iana.org/assignments/cose/cose.xhtml).  It is thus
 * considered safe to use as the list terminator.
 */
#define LABEL_LIST_TERMINATOR 0


/**
 * \brief Clear a label list to empty.
 *
 * \param[in,out] list The list to clear.
 */
inline static void clear_label_list(struct t_cose_label_list *list)
{
    memset(list, 0, sizeof(struct t_cose_label_list));
}




enum t_cose_err_t
check_critical_labels(const struct t_cose_label_list *critical_labels,
                      const struct t_cose_label_list *unknown_labels);



enum t_cose_err_t
parse_cose_header_parameters(QCBORDecodeContext        *decode_context,
                             struct t_cose_parameters  *returned_parameters,
                             struct t_cose_label_list  *critical_labels,
                             struct t_cose_label_list  *unknown_labels);


/**
 * \brief Clear a struct t_cose_parameters to empty
 *
 * \param[in,out] parameters   Parameter list to clear.
 */
static inline void clear_cose_parameters(struct t_cose_parameters *parameters)
{
#if COSE_ALGORITHM_RESERVED != 0
#error Invalid algorithm designator not 0. Parameter list initialization fails.
#endif

#if T_COSE_UNSET_ALGORITHM_ID != COSE_ALGORITHM_RESERVED
#error Constant for unset algorithm ID not aligned with COSE_ALGORITHM_RESERVED
#endif

    /* This clears all the useful_bufs to NULL_Q_USEFUL_BUF_C
     * and the cose_algorithm_id to COSE_ALGORITHM_RESERVED
     */
    memset(parameters, 0, sizeof(struct t_cose_parameters));

#ifndef T_COSE_DISABLE_CONTENT_TYPE
    /* The only non-zero clear-state value. (0 is plain text in CoAP
     * content format) */
    parameters->content_type_uint =  T_COSE_EMPTY_UINT_CONTENT_TYPE;
#endif
}

#endif /* t_cose_parameters_h */
