/*
 * Author: Bryan Berns <berns@uwalumni.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

 /*
  * This file provides the GSSAPI interface to support Kerberos SSPI within
  * OpenSSH.  This is only a partial definition of the full GSSAPI specification
  * since OpenSSH only requires a subset of the overall functionality.
  *
  * The definitions are derived from information provided in RFC2744.  In
  * addition, RFC2743 provides additional information on the GSSAPI
  * specification and intended operation.
  */

#include <windows.h>
#include <stdint.h>

#define SECURITY_WIN32
#include <security.h>

/*
 * Common Structures & Type Definitions
 */

typedef uint32_t OM_uint32;

typedef char *gss_name_struct, *gss_name_t;

typedef struct cred_st *gss_cred_id_t;
typedef CtxtHandle *gss_ctx_id_t;

typedef OM_uint32 gss_qop_t;
typedef OM_uint32 gss_cred_usage_t;

typedef struct gss_buffer_desc_struct
{
	size_t length;
	void *value;
}
gss_buffer_desc, *gss_buffer_t;

typedef struct gss_OID_desc_struct
{
	OM_uint32 length;
	void *elements;
}
gss_OID_desc, *gss_OID;

typedef struct gss_OID_set_desc_struct
{
	size_t  count;
	gss_OID elements;
}
gss_OID_set_desc, *gss_OID_set;

typedef struct gss_channel_bindings_struct 
{
	OM_uint32 initiator_addrtype;
	gss_buffer_desc initiator_address;
	OM_uint32 acceptor_addrtype;
	gss_buffer_desc acceptor_address;
	gss_buffer_desc application_data;
} 
gss_channel_bindings_desc, *gss_channel_bindings_t;

/*
 * Input & Return Flags 
 */

/* Credential Usage Indication Options */
#define GSS_C_BOTH      0
#define GSS_C_INITIATE  1
#define GSS_C_ACCEPT    2

/* Context Flag Options */
#define GSS_C_DELEG_FLAG        1
#define GSS_C_MUTUAL_FLAG       2
#define GSS_C_REPLAY_FLAG       4
#define GSS_C_SEQUENCE_FLAG     8
#define GSS_C_CONF_FLAG         16
#define GSS_C_INTEG_FLAG        32
#define GSS_C_ANON_FLAG         64
#define GSS_C_PROT_READY_FLAG   128
#define GSS_C_TRANS_FLAG        256
#define GSS_C_DELEG_POLICY_FLAG 32768

/* Display Status Code Types */
#define GSS_C_GSS_CODE  1
#define GSS_C_MECH_CODE 2

/* Convenience Null Castless Comparison Options */
#define GSS_C_NO_NAME             ((gss_name_t) 0)
#define GSS_C_NO_BUFFER           ((gss_buffer_t) 0)
#define GSS_C_NO_OID              ((gss_OID) 0)
#define GSS_C_NO_OID_SET          ((gss_OID_set) 0)
#define GSS_C_NO_CONTEXT          ((gss_ctx_id_t) 0)
#define GSS_C_NO_CREDENTIAL       ((gss_cred_id_t) 0)
#define GSS_C_NO_CHANNEL_BINDINGS ((gss_channel_bindings_t) 0)

/* Convenience Initializer For Empty Buffer */
#define GSS_C_EMPTY_BUFFER {0, NULL}

/* Default Quality of Protection Code */
#define GSS_C_QOP_DEFAULT 0

 /* Infinite Context / Credential Value */
#define GSS_C_INDEFINITE ((OM_uint32) 0xfffffffful)

/*
 * Status & Return Code Processing
 */

#define GSS_S_COMPLETE 0

#define GSS_C_CALLING_ERROR_OFFSET 24
#define GSS_C_ROUTINE_ERROR_OFFSET 16
#define GSS_C_SUPPLEMENTARY_OFFSET 0
#define GSS_C_CALLING_ERROR_MASK ((OM_uint32) 0377ul)
#define GSS_C_ROUTINE_ERROR_MASK ((OM_uint32) 0377ul)

#define GSS_CALLING_ERROR(x)      ((x) & (GSS_C_CALLING_ERROR_MASK << GSS_C_CALLING_ERROR_OFFSET))
#define GSS_ROUTINE_ERROR(x)      ((x) & (GSS_C_ROUTINE_ERROR_MASK << GSS_C_ROUTINE_ERROR_OFFSET))
#define GSS_ERROR(x)              ((x) & ((GSS_C_CALLING_ERROR_MASK << GSS_C_CALLING_ERROR_OFFSET) | (GSS_C_ROUTINE_ERROR_MASK << GSS_C_ROUTINE_ERROR_OFFSET)))

#define GSS_S_BAD_MECH             (((OM_uint32)  1ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_BAD_NAME             (((OM_uint32)  2ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_BAD_NAMETYPE         (((OM_uint32)  3ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_BAD_BINDINGS         (((OM_uint32)  4ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_BAD_STATUS           (((OM_uint32)  5ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_BAD_SIG              (((OM_uint32)  6ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_NO_CRED              (((OM_uint32)  7ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_NO_CONTEXT           (((OM_uint32)  8ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_DEFECTIVE_TOKEN      (((OM_uint32)  9ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_DEFECTIVE_CREDENTIAL (((OM_uint32) 10ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_CREDENTIALS_EXPIRED  (((OM_uint32) 11ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_CONTEXT_EXPIRED      (((OM_uint32) 12ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_FAILURE              (((OM_uint32) 13ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_BAD_QOP              (((OM_uint32) 14ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_UNAUTHORIZED         (((OM_uint32) 15ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_UNAVAILABLE          (((OM_uint32) 16ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_DUPLICATE_ELEMENT    (((OM_uint32) 17ul) << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_NAME_NOT_MN          (((OM_uint32) 18ul) << GSS_C_ROUTINE_ERROR_OFFSET)

#define GSS_S_CONTINUE_NEEDED      (1ul << (GSS_C_SUPPLEMENTARY_OFFSET + 0))
#define GSS_S_DUPLICATE_TOKEN      (1ul << (GSS_C_SUPPLEMENTARY_OFFSET + 1))
#define GSS_S_OLD_TOKEN            (1ul << (GSS_C_SUPPLEMENTARY_OFFSET + 2))
#define GSS_S_UNSEQ_TOKEN          (1ul << (GSS_C_SUPPLEMENTARY_OFFSET + 3))
#define GSS_S_GAP_TOKEN            (1ul << (GSS_C_SUPPLEMENTARY_OFFSET + 4))

/* 
 * Function Prototypes 
 */

OM_uint32 
gss_accept_sec_context(_Out_ OM_uint32 * minor_status, _Inout_opt_ gss_ctx_id_t * context_handle,
	_In_opt_ gss_cred_id_t acceptor_cred_handle, _In_ gss_buffer_t input_token_buffer, 
	_In_opt_ gss_channel_bindings_t input_chan_bindings, _Out_opt_ gss_name_t * src_name, 
	_Out_opt_ gss_OID * mech_type, _Outptr_ gss_buffer_t output_token, _Out_ OM_uint32 * ret_flags, 
	_Out_opt_ OM_uint32 * time_rec, _Outptr_opt_ gss_cred_id_t * delegated_cred_handle);

OM_uint32
gss_acquire_cred(_Out_ OM_uint32 *minor_status, _In_opt_ gss_name_t desired_name, 
	_In_opt_ OM_uint32 time_req, _In_opt_ gss_OID_set desired_mechs, _In_ gss_cred_usage_t cred_usage,
	_Outptr_opt_ gss_cred_id_t * output_cred_handle, _Outptr_opt_ gss_OID_set *actual_mechs, 
	_Out_opt_ OM_uint32 *time_rec);

OM_uint32 
gss_add_oid_set_member(_Out_ OM_uint32 * minor_status, _In_ gss_OID member_oid, 
	_In_ gss_OID_set * oid_set);

OM_uint32
gss_create_empty_oid_set(_Out_ OM_uint32 * minor_status, _Outptr_ gss_OID_set * oid_set);

OM_uint32 
gss_delete_sec_context(_Out_ OM_uint32 * minor_status, _Inout_ gss_ctx_id_t * context_handle,
	_Inout_opt_ gss_buffer_t output_token);

OM_uint32 
gss_display_name(_Out_ OM_uint32 * minor_status, _In_ gss_name_t input_name, 
	_Out_ gss_buffer_t output_name_buffer, _Out_ gss_OID * output_name_type);

OM_uint32 
gss_display_status(_In_ OM_uint32 * minor_status, _In_ OM_uint32 status_value,
	_In_ int status_type, _In_opt_ gss_OID mech_type, _Out_ OM_uint32 * message_context, 
	_Inout_ gss_buffer_t status_string);

OM_uint32 
gss_export_name(_Out_ OM_uint32 * minor_status, _In_ const gss_name_t input_name, 
	_Inout_ gss_buffer_t exported_name);

OM_uint32 
gss_get_mic(_Out_ OM_uint32 * minor_status, _In_ gss_ctx_id_t context_handle, 
	_In_opt_ gss_qop_t qop_req, _In_ gss_buffer_t message_buffer, 
	_Out_ gss_buffer_t message_token);

OM_uint32 
gss_import_name(_Out_ OM_uint32 * minor_status, _In_ gss_buffer_t input_name_buffer,
	_In_ gss_OID input_name_type, _Out_ gss_name_t * output_name);

OM_uint32 
gss_indicate_mechs(_Out_ OM_uint32 * minor_status, _Outptr_ gss_OID_set * mech_set);

OM_uint32 
gss_release_buffer(_Out_ OM_uint32 * minor_status, _Inout_ gss_buffer_t buffer);

OM_uint32 
gss_release_cred(_Out_ OM_uint32 * minor_status, _Inout_opt_ gss_cred_id_t * cred_handle);

OM_uint32 
gss_release_name(_Out_ OM_uint32 * minor_status, _Inout_ gss_name_t * input_name);

OM_uint32 
gss_release_oid_set(_Out_ OM_uint32 * minor_status, _In_ gss_OID_set * set);

OM_uint32 
gss_test_oid_set_member(_Out_ OM_uint32 * minor_status, _In_ gss_OID member, 
	_In_ gss_OID_set set, _Out_ int * present);

OM_uint32 
gss_verify_mic(_Out_ OM_uint32 * minor_status, _In_ gss_ctx_id_t context_handle, 
	_In_ gss_buffer_t message_buffer, _Out_opt_ gss_buffer_t message_token, 
	_Inout_ gss_qop_t * qop_state);

extern gss_OID GSS_C_NT_HOSTBASED_SERVICE;