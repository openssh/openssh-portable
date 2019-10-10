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

#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "inc\utf.h"
#include "inc\pwd.h"
#include "debug.h"
#include "inc\gssapi.h"

 /*
  * This file provides the GSSAPI interface to support Kerberos SSPI within
  * OpenSSH.  This is only a partial definition of the full GSSAPI specification
  * since OpenSSH only requires a subset of the overall functionality.
  *
  * The function definitions as well as the accompanying comments are derived
  * from information provided in RFC2744.  In addition, RFC2743 provides
  * additional information on the GSSAPI specification and intended operation.
  */

/* 
 * Include the definitions necessary to implement some of the interface
 * structure that are required for gss-serv.c to perform Kerberos operations.
 */
#include "..\..\..\config.h"
#undef HAVE_GSSAPI_H
#include "..\..\..\ssh-gss.h"

/*
 * This will be initialized to a function table that contains pointers to 
 * all standard security functions.  The reason for using this instead of
 * relying on the standard imports is because the OneCore libraries do
 * not expose all the functions we need.
 */
PSecurityFunctionTableW SecFunctions = NULL;

/*
 * GSS_C_NT_HOSTBASED_SERVICE is a oid value that is used to negotiate a 
 * a Kerberos transaction using an SPN in the format host@user@realm format. 
 */
#define GSS_C_NT_HOSTBASED_SERVICE_STR "\x2A\x86\x48\x86\xF7\x12\x01\x02\x02"
gss_OID GSS_C_NT_HOSTBASED_SERVICE = &(gss_OID_desc)
{ 
	sizeof(GSS_C_NT_HOSTBASED_SERVICE_STR) - 1,
	(void *) GSS_C_NT_HOSTBASED_SERVICE_STR 
};

/* 
 * This handle is used to relay the handle for the user to functions that 
 * ultimately call CreateProcessAsUser to spawn the user shell.
 */
HANDLE sspi_auth_user = 0;

struct cred_st {
	int isToken;
	union { 
		HANDLE token;
		CredHandle credHandle;
	};
};

/*
 * This is called before each gssapi implementation function to ensure the
 * environment is initialized properly.  Any additional implementation setup
 * should be added to this function.
 */
static int 
ssh_gss_sspi_init(_Out_ OM_uint32 * minor_status)
{	
	/* minor status never used - reset to zero*/
	*minor_status = 0;

	/* already initialized; return */
	if (SecFunctions != NULL) 
		return 1;

	/* get a pointer to a function table containing all the function pointers */
	if ((SecFunctions = InitSecurityInterfaceW()) == NULL) {
		/* failure */
		debug("failed to acquire function table for sspi support.");
		return 0;
	}

	/* success */
	return 1;
}

/*
 * Allows an application to determine which underlying security mechanisms are
 * available.
 */
OM_uint32 
gss_indicate_mechs(_Out_ OM_uint32 * minor_status, _Outptr_ gss_OID_set *mech_set)
{
	if (ssh_gss_sspi_init(minor_status) == 0) 
		return GSS_S_FAILURE;

	/* create an list that contains the one oid that we support */
	if (gss_create_empty_oid_set(minor_status, mech_set) != GSS_S_COMPLETE)
		return GSS_S_FAILURE;
	
	if (gss_add_oid_set_member(minor_status, GSS_C_NT_HOSTBASED_SERVICE, mech_set) != GSS_S_COMPLETE) {
		gss_release_oid_set(minor_status, mech_set);
		return GSS_S_FAILURE;
	}

	return GSS_S_COMPLETE;
}

/*
 * Create an object-identifier set containing no object identifiers, to which
 * members may be subsequently added using the gss_add_oid_set_member() routine.
 * These routines are intended to be used to construct sets of mechanism object
 * identifiers, for input to gss_acquire_cred.
 */
OM_uint32 
gss_create_empty_oid_set(_Out_ OM_uint32 * minor_status, _Outptr_ gss_OID_set * oid_set)
{
	if (ssh_gss_sspi_init(minor_status) == 0) 
		return GSS_S_FAILURE;

	/* allocate / initialize space for this new oid set */
	if (((*oid_set) = calloc(1, sizeof(gss_OID_set_desc))) == NULL)
		return GSS_S_FAILURE;

	return GSS_S_COMPLETE;
}

/*
 * Free storage associated with a GSSAPI-generated gss_OID_set object. The set
 * parameter must refer to an OID-set that was returned from a GSS-API routine.
 * gss_release_oid_set() will free the storage associated with each individual
 * member OID, the OID set's elements array, and the gss_OID_set_desc.
 */
OM_uint32 
gss_release_oid_set(_Out_ OM_uint32 * minor_status, _In_ gss_OID_set * set)
{
	if (ssh_gss_sspi_init(minor_status) == 0) 
		return GSS_S_FAILURE;

	/* free all individual oid strings */
	for (size_t oid_num = 0; oid_num < (*set)->count; oid_num++)
		free((*set)->elements[oid_num].elements);

	/* free overall oid set */
	free((*set)->elements);
	free(*set);

	return GSS_S_COMPLETE;
}

/*
 * Add an Object Identifier to an Object Identifier set.  This routine is
 * intended for use in conjunction with gss_create_empty_oid_set when
 * constructing a set of mechanism OIDs for input to gss_acquire_cred. The
 * oid_set parameter must refer to an OID-set that was created by GSS-API (e.g.
 * a set returned by gss_create_empty_oid_set()). GSS-API creates a copy of the
 * member_oid and inserts this copy into the set, expanding the storage
 * allocated to the OID-set's elements array if necessary.  The routine may add
 * the new member OID anywhere within the elements array, and implementations
 * should verify that the new member_oid is not already contained within the
 * elements array; if the member_oid is already present, the oid_set should
 * remain unchanged.
 */
OM_uint32 
gss_add_oid_set_member(_Out_ OM_uint32 * minor_status, _In_ gss_OID member_oid, _In_ gss_OID_set * oid_set)
{
	OM_uint32 ret = GSS_S_FAILURE;
	void * member_oid_elements = NULL;

	if (ssh_gss_sspi_init(minor_status) == 0) 
		return GSS_S_FAILURE;

	/* create our own copy of the oid entry itself to add to the set */
	if ((member_oid_elements = malloc(member_oid->length)) == NULL)
		goto cleanup;
	memcpy(member_oid_elements, member_oid->elements, member_oid->length);

	/* reallocate the new elements structure based on the increased size */
	const size_t current_count = (*oid_set)->count;
	(*oid_set)->elements = realloc((*oid_set)->elements, (current_count + 1) * sizeof(gss_OID_desc));
	if ((*oid_set)->elements == NULL)
		goto cleanup;
	
	/* append the new oid to the end of the recently increased list */
	(*oid_set)->elements[current_count].elements = member_oid_elements;
	(*oid_set)->elements[current_count].length = member_oid->length;
	(*oid_set)->count++;

	member_oid_elements = NULL;
	ret = GSS_S_COMPLETE;
cleanup:
	if (member_oid_elements)
		free(member_oid_elements);

	return ret;
}

/*
 * Interrogate an Object Identifier set to determine whether a specified Object
 * Identifier is a member.  This routine is intended to be used with OID sets
 * returned by gss_indicate_mechs(), gss_acquire_cred(), and gss_inquire_cred(),
 * but will also work with user-generated sets.
 */
OM_uint32 
gss_test_oid_set_member(_Out_ OM_uint32 * minor_status, _In_ gss_OID member,
	_In_ gss_OID_set set, _Out_ int * present)
{
	if (ssh_gss_sspi_init(minor_status) == 0) 
		return GSS_S_FAILURE;

	/* loop through each oid in the passed set */
	for (size_t oid_num = 0; oid_num < set->count; oid_num++) {
		/* do not bother doing memory comparison if sizes do not match */
		if (set->elements[oid_num].length != member->length) 
			continue;

		/* compare the binary storage of the test oid to the one in our list */
		if (memcmp(set->elements[oid_num].elements, member->elements, member->length) == 0) {
			/* match found */
			*present = TRUE;
			return GSS_S_COMPLETE;
		}
	}

	/* no match found in the list */
	*present = FALSE;
	return GSS_S_COMPLETE;
}

/* 
 * Convert a contiguous string name to internal form.  In general, the internal
 * name returned (via the <output_name> parameter) will not be an MN; the
 * exception to this is if the <input_name_type> indicates that the contiguous
 * string provided via the <input_name_buffer> parameter is of type
 * GSS_C_NT_EXPORT_NAME, in which case the returned internal name will be an MN
 * for the mechanism that exported the name.
 */
OM_uint32 
gss_import_name(_Out_ OM_uint32 * minor_status, _In_ gss_buffer_t input_name_buffer,
	_In_ gss_OID input_name_type, _Outptr_ gss_name_t * output_name)
{
	if (ssh_gss_sspi_init(minor_status) == 0) 
		return GSS_S_FAILURE;

	/* make sure we support the passed type */
	if (input_name_type->length != GSS_C_NT_HOSTBASED_SERVICE->length ||
	    memcmp(input_name_type->elements, GSS_C_NT_HOSTBASED_SERVICE->elements, input_name_type->length) != 0)
		return GSS_S_BAD_NAMETYPE;
	
	/* there is nothing special we have to do for this type so just duplicate
	the  */
	(*output_name) = _strdup(input_name_buffer->value);

	if (output_name == NULL)
		return GSS_S_FAILURE;

	return GSS_S_COMPLETE;
}

/*
 * Free GSSAPI-allocated storage associated with an internal-form name.
 * Implementations are encouraged to set the name to GSS_C_NO_NAME on successful
 * completion of this call.
 */
OM_uint32 
gss_release_name(_Out_ OM_uint32 * minor_status, _Inout_ gss_name_t * input_name)
{
	if (ssh_gss_sspi_init(minor_status) == 0) 
		return GSS_S_FAILURE;

	/* validate input */
	if (input_name == NULL || *input_name == NULL)
		return GSS_S_BAD_NAME;
	
	/* deallocate memory associated with the name */
	free(*input_name);
	*input_name = GSS_C_NO_NAME;
	
	return GSS_S_COMPLETE;
}

/*
 * To produce a canonical contiguous string representation of a mechanism name
 * (MN), suitable for direct comparison (e.g. with memcmp) for use in
 * authorization functions (e.g. matching entries in an access-control list).
 * The <input_name> parameter must specify a or by gss_canonicalize_name).
 */
OM_uint32 
gss_export_name(_Out_ OM_uint32 * minor_status, _In_ const gss_name_t input_name,
	_Inout_ gss_buffer_t exported_name)
{
	if (ssh_gss_sspi_init(minor_status) == 0) 
		return GSS_S_FAILURE;

	/* convenience pointer to shorten the void */
	const gss_OID_desc* const ntoid = GSS_C_NT_HOSTBASED_SERVICE;

	/* make sure we support the passed type */
	if (strstr(input_name, "host@") == input_name)
		return GSS_S_BAD_NAMETYPE;

	/* get the lengths of all the parts of the string */
	/* note: assumes short format for encoding oid length (i.e. less than 128)
	*/
	const uint16_t token_id = 0x0401;
	const uint8_t oid_tag = 0x06;
	const uint8_t oid_len = (uint8_t) ntoid->length;
	const uint16_t oid_outer_len = sizeof(oid_tag) + sizeof(oid_len) + oid_len;
	const uint32_t name_len = (uint16_t) strlen(input_name);

	/* allocate space for the exported name */
	exported_name->length = sizeof(token_id) + sizeof(oid_outer_len) + oid_outer_len + sizeof(name_len) + name_len;
	exported_name->value = malloc(exported_name->length);
	if (exported_name->value == NULL)
		return GSS_S_FAILURE;

	/* get big-endian values so we can just do a direct memcpy from the values
	*/
	const uint16_t token_id_be = htons(token_id);
	const uint16_t oid_outer_len_be = htons(oid_outer_len);
	const uint32_t name_len_be = htonl(name_len);

	/* construct the encoded value */
	uint8_t * output = exported_name->value;
	memcpy(output, &token_id_be, sizeof(token_id_be)); output += sizeof(token_id_be);
	memcpy(output, &oid_outer_len_be, sizeof(oid_outer_len_be)); output += sizeof(oid_outer_len_be);
	memcpy(output, &oid_tag, sizeof(oid_tag)); output += sizeof(oid_tag);
	memcpy(output, &oid_len, sizeof(oid_len)); output += sizeof(oid_len);
	memcpy(output, ntoid->elements, ntoid->length); output += ntoid->length;
	memcpy(output, &name_len_be, sizeof(name_len_be)); output += sizeof(name_len_be);
	memcpy(output, input_name, name_len);

	return GSS_S_COMPLETE;
}

/*
 * Free storage associated with a buffer.  The storage must have been allocated
 * by a GSS-API routine.  In addition to freeing the associated storage, the
 * routine will zero the length field in the descriptor to which the buffer
 * parameter refers, and implementations are encouraged to additionally set the
 * pointer field in the descriptor to NULL.  Any buffer object returned by a
 * GSS-API routine may be passed to gss_release_buffer (even if there is no
 * storage associated with the buffer).
 */
OM_uint32 
gss_release_buffer(_Out_ OM_uint32 * minor_status, _Inout_ gss_buffer_t buffer)
{
	if (ssh_gss_sspi_init(minor_status) == 0) 
		return GSS_S_FAILURE;

	/* deallocate the buffer associated with the buffer */
	free(buffer->value);	
	buffer->length = 0;
	buffer->value = NULL;

	return GSS_S_COMPLETE;
}

/* 
 * Allows an application to acquire a handle for a pre-existing credential by
 * name.  GSS-API implementations must impose a local access-control policy on
 * callers of this routine to prevent unauthorized callers from acquiring
 * credentials to which they are not entitled.  This routine is not intended to
 * provide a "login to the network" function, as such a function would involve
 * the creation of new credentials rather than merely acquiring a handle to
 * existing credentials.  Such functions, if required, should be defined in
 * implementation-specific extensions to the API.
 */
OM_uint32 
gss_acquire_cred(_Out_ OM_uint32 *minor_status, _In_opt_ gss_name_t desired_name,
	_In_opt_ OM_uint32 time_req, _In_opt_ gss_OID_set desired_mechs, _In_ gss_cred_usage_t cred_usage,
	_Outptr_opt_ gss_cred_id_t * output_cred_handle, _Outptr_opt_ gss_OID_set *actual_mechs, _Out_opt_ OM_uint32 *time_rec)
{
	OM_uint32 ret = GSS_S_FAILURE;
	SYSTEMTIME current_time_system;
	wchar_t * desired_name_utf16 = NULL;
	CredHandle cred_handle, *p_cred_handle = NULL;
	

	if (output_cred_handle != NULL)
		*output_cred_handle = NULL;

	if (ssh_gss_sspi_init(minor_status) == 0)
		goto done;

	/* get the current time so we can determine expiration if requested */
	GetSystemTime(&current_time_system);

	/* translate credential usage parameters */
	ULONG cred_usage_local = 0;
	if (cred_usage == GSS_C_ACCEPT) cred_usage_local = SECPKG_CRED_INBOUND;
	else if (cred_usage == GSS_C_INITIATE) cred_usage_local = SECPKG_CRED_OUTBOUND;
	else if (cred_usage == GSS_C_BOTH) cred_usage_local = SECPKG_CRED_BOTH;

	/* convert input name to unicode so we can process usernames with special characters */
	if ((desired_name_utf16 = utf8_to_utf16(desired_name)) == NULL)
		goto done;

	/* acquire a handle to existing credentials -- in many cases the name will
	 * be null in which case the credentials of the current user are used */
	TimeStamp expiry;
	SECURITY_STATUS status = SecFunctions->AcquireCredentialsHandleW(desired_name_utf16, MICROSOFT_KERBEROS_NAME_W, cred_usage_local,
		NULL, NULL, NULL, NULL, &cred_handle, &expiry);

	/* fail immediately if errors occurred */
	if (status != SEC_E_OK)
		goto done;
	
	p_cred_handle = &cred_handle;
	/* copy credential data out of local buffer */
	if (output_cred_handle != NULL) {
		if ((*output_cred_handle = malloc(sizeof(struct cred_st))) == NULL)
			goto done;
		(*output_cred_handle)->isToken = 0;
		(*output_cred_handle)->credHandle = cred_handle;
	}
	
	/* determine expiration if requested */
	if (time_rec != NULL) {
		FILETIME current_time;
		SystemTimeToFileTime(&current_time_system, &current_time);
		*time_rec = (OM_uint32) (expiry.QuadPart - ((PLARGE_INTEGER)&current_time)->QuadPart) / 10000;
	}

	/* set actual supported mechs if requested */
	if (actual_mechs != NULL && gss_indicate_mechs(minor_status, actual_mechs) != GSS_S_COMPLETE)
		goto done;

	ret = GSS_S_COMPLETE;
done:
	if (desired_name_utf16)
		free(desired_name_utf16);
	if (ret != GSS_S_COMPLETE) {
		if (p_cred_handle)
			SecFunctions->FreeCredentialsHandle(p_cred_handle);
		if (output_cred_handle && *output_cred_handle) {
			free(*output_cred_handle);
			*output_cred_handle = NULL;
		}
	}

	return ret;
}

/*
 * Initiates the establishment of a security context between the application and
 * a remote peer.  Initially, the input_token parameter should be specified
 * either as GSS_C_NO_BUFFER, or as a pointer to a gss_buffer_desc object whose
 * length field contains the value zero. The routine may return a output_token
 * which should be transferred to the peer application, where the peer
 * application will present it to gss_accept_sec_context.
 */
OM_uint32 
gss_init_sec_context(
	_Out_ OM_uint32 * minor_status, _In_ gss_cred_id_t claimant_cred_handle, _In_ gss_ctx_id_t * context_handle,
	_In_ gss_name_t target_name, _In_ gss_OID mech_type, _In_ OM_uint32 req_flags, _In_ OM_uint32 time_req, _In_ gss_channel_bindings_t input_chan_bindings,
	_In_ gss_buffer_t input_token, _Inout_ gss_OID * actual_mech_type, _Inout_ gss_buffer_t output_token, _Out_ OM_uint32 * ret_flags,
	_Out_ OM_uint32 * time_rec)
{
	OM_uint32 ret = GSS_S_FAILURE;
	wchar_t * target_name_utf16 = NULL;
	gss_ctx_id_t p_ctx_h = NULL;

	output_token->value = NULL;

	if (ssh_gss_sspi_init(minor_status) == 0) 
		goto done;

	/* make sure we support the passed type */
	if (mech_type->length != GSS_C_NT_HOSTBASED_SERVICE->length ||
	    memcmp(mech_type->elements, GSS_C_NT_HOSTBASED_SERVICE->elements, mech_type->length) != 0) {
		ret = GSS_S_BAD_NAMETYPE;
		goto done;
	}
	
	unsigned long sspi_req_flags = ISC_REQ_ALLOCATE_MEMORY;
	if (req_flags & GSS_C_MUTUAL_FLAG) 
		sspi_req_flags |= ISC_REQ_MUTUAL_AUTH;
	if (req_flags & GSS_C_CONF_FLAG) 
		sspi_req_flags |= ISC_REQ_CONFIDENTIALITY;
	if (req_flags & GSS_C_REPLAY_FLAG) 
		sspi_req_flags |= ISC_REQ_REPLAY_DETECT;
	if (req_flags & GSS_C_DELEG_FLAG) 
		sspi_req_flags |= ISC_REQ_DELEGATE;
	if (req_flags & GSS_C_INTEG_FLAG) 
		sspi_req_flags |= ISC_REQ_INTEGRITY;
	if (req_flags & GSS_C_SEQUENCE_FLAG) 
		sspi_req_flags |= ISC_REQ_SEQUENCE_DETECT;

	/* determine if this is the first call (no input buffer available) */
	gss_buffer_desc empty_buffer = GSS_C_EMPTY_BUFFER;
	const int no_input_buffer = (input_token == GSS_C_NO_BUFFER) || memcmp(input_token, &empty_buffer, sizeof(gss_buffer_desc)) == 0;

	/* setup input buffer */
	SecBuffer input_buffer_token = { (no_input_buffer) ? 0 : (unsigned long) input_token->length, SECBUFFER_TOKEN, (no_input_buffer) ? NULL : input_token->value };
	SecBufferDesc input_buffer = { SECBUFFER_VERSION, 1, &input_buffer_token };

	/* setup output buffer - will be dynamically allocated by function */
	SecBuffer output_buffer_token = { 0, SECBUFFER_TOKEN, NULL };
	SecBufferDesc output_buffer = { SECBUFFER_VERSION, 1, &output_buffer_token };

	/* get the current time so we can determine expiration if requested */
	SYSTEMTIME current_time_system;
	GetSystemTime(&current_time_system);

	/* acquire default cred handler if none specified */
	CredHandle *pCredHandle = NULL;
	if (claimant_cred_handle != NULL)
		pCredHandle = &(claimant_cred_handle->credHandle);
	
	if (pCredHandle == NULL) {
		static CredHandle cred_handle = { 0, 0 };
		pCredHandle = &cred_handle;
		if (cred_handle.dwLower == 0 && cred_handle.dwUpper == 0) {
			TimeStamp expiry_cred;
			if (SecFunctions->AcquireCredentialsHandleW(NULL, MICROSOFT_KERBEROS_NAME_W, SECPKG_CRED_OUTBOUND,
			    NULL, NULL, NULL, NULL, &cred_handle, &expiry_cred) != SEC_E_OK)
				goto done;
		}
	}

	/* condition the string for windows */
	if ((target_name_utf16 = utf8_to_utf16(target_name)) == NULL)
		goto done;

	if (wcsncmp(target_name_utf16, L"host@", wcslen(L"host@")) == 0) 
		*wcschr(target_name_utf16, L'@') = L'/';

	TimeStamp expiry;
	LONG sspi_ret_flags = 0;
	CtxtHandle out_context;

	const SECURITY_STATUS status = SecFunctions->InitializeSecurityContextW(pCredHandle,
		(*context_handle == GSS_C_NO_CONTEXT) ? NULL : *context_handle,
		target_name_utf16, sspi_req_flags, 0, SECURITY_NATIVE_DREP, (no_input_buffer) ? NULL : &input_buffer,
		0, (*context_handle != NULL) ? NULL : &out_context, &output_buffer, &sspi_ret_flags, (time_rec == NULL) ? NULL : &expiry);

	/* check if error occurred */
	if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED)
		goto done;
	
	/* copy output token to output buffer */
	output_token->length = output_buffer_token.cbBuffer;
	if ((output_token->value = malloc(output_token->length)) == NULL)
		goto done;

	memcpy(output_token->value, output_buffer_token.pvBuffer, output_token->length);
	SecFunctions->FreeContextBuffer(output_buffer_token.pvBuffer);

	/* if requested, translate returned flags that are actually available */
	if (ret_flags != NULL) {
		*ret_flags = 0;
		if (sspi_ret_flags & ISC_RET_MUTUAL_AUTH) 
			*ret_flags |= GSS_C_MUTUAL_FLAG;
		if (sspi_ret_flags & ISC_RET_CONFIDENTIALITY) 
			*ret_flags |= GSS_C_CONF_FLAG;
		if (sspi_ret_flags & ISC_RET_REPLAY_DETECT) 
			*ret_flags |= GSS_C_REPLAY_FLAG;
		if (sspi_ret_flags & ISC_RET_DELEGATE) 
			*ret_flags |= GSS_C_DELEG_FLAG;
		if (sspi_ret_flags & ISC_RET_INTEGRITY) 
			*ret_flags |= GSS_C_INTEG_FLAG;
		if (sspi_ret_flags & ISC_RET_SEQUENCE_DETECT) 
			*ret_flags |= GSS_C_SEQUENCE_FLAG;
	}

	/* report if delegation was requested by not fulfilled */
	if ((sspi_req_flags & ISC_REQ_DELEGATE) != 0 && (sspi_ret_flags & ISC_RET_DELEGATE) == 0)
		debug("sspi delegation was requested but not fulfilled");

	/* if requested, translate the expiration time to number of second */
	if (time_rec != NULL) {
		FILETIME current_time;
		SystemTimeToFileTime(&current_time_system, &current_time);
		*time_rec = (OM_uint32)(expiry.QuadPart - ((PLARGE_INTEGER)&current_time)->QuadPart) / 10000;
	}

	/* if requested, return the supported mechanism oid */
	if (actual_mech_type != NULL)
		*actual_mech_type = GSS_C_NT_HOSTBASED_SERVICE;
	
	/* copy the credential context structure to the caller */
	if (*context_handle == GSS_C_NO_CONTEXT) {
		if ((p_ctx_h = malloc(sizeof(out_context))) == NULL)
			goto done;
		*context_handle = p_ctx_h;
		memcpy(*context_handle, &out_context, sizeof(out_context));
	}

	ret = (status == SEC_I_CONTINUE_NEEDED) ? GSS_S_CONTINUE_NEEDED : GSS_S_COMPLETE;
done:
	if (target_name_utf16)
		free(target_name_utf16);

	if (ret != GSS_S_COMPLETE && ret != GSS_S_CONTINUE_NEEDED) {
		if (output_token->value) {
			free(output_token->value);
			output_token->value = NULL;
		}
		if (p_ctx_h)
			free(p_ctx_h);
		
	}

	return ret;
}

/*
 * Informs GSS-API that the specified credential handle is no longer required by
 * the application, and frees associated resources. Implementations are
 * encouraged to set the cred_handle to GSS_C_NO_CREDENTIAL on successful
 * completion of this call.
 */
OM_uint32 
gss_release_cred(_Out_ OM_uint32 * minor_status, _Inout_opt_ gss_cred_id_t * cred_handle)
{
	if (ssh_gss_sspi_init(minor_status) == 0) 
		return GSS_S_FAILURE;

	if (*cred_handle != GSS_C_NO_CREDENTIAL) {
		if ((*cred_handle)->isToken) {
			CloseHandle((*cred_handle)->token);
			if ((*cred_handle)->token == sspi_auth_user)
				sspi_auth_user = 0;
		}
		else
			SecFunctions->FreeCredentialsHandle(&(*cred_handle)->credHandle);
		free(*cred_handle);
		*cred_handle = GSS_C_NO_CREDENTIAL;
	}

	return GSS_S_COMPLETE;
}

/*
 * Delete a security context.  gss_delete_sec_context will delete the local data
 * structures associated with the specified security context, and may generate
 * an output_token, which when passed to the peer gss_process_context_token will
 * instruct it to do likewise.  If no token is required by the mechanism, the
 * GSS-API should set the length field of the output_token (if provided) to
 * zero.  No further security services may be obtained using the context
 * specified by context_handle.
 */
OM_uint32 
gss_delete_sec_context(_Out_ OM_uint32 * minor_status, _Inout_ gss_ctx_id_t * context_handle, 
	_Inout_opt_ gss_buffer_t output_token)
{
	if (ssh_gss_sspi_init(minor_status) == 0) 
		return GSS_S_FAILURE;

	/* input sanity checks */
	if (context_handle == NULL)
		return GSS_S_NO_CONTEXT;

	if (output_token != GSS_C_NO_BUFFER) {
		free(output_token->value);
		output_token->value = NULL;
		output_token->length = 0;
	}

	/* cleanup security context */
	SecFunctions->DeleteSecurityContext(*context_handle);
	free(*context_handle);
	*context_handle = GSS_C_NO_CONTEXT;

	return GSS_S_COMPLETE;
}

/*
 * Verifies that a cryptographic MIC, contained in the token parameter, fits the
 * supplied message.  The qop_state parameter allows a message recipient to
 * determine the strength of protection that was applied to the message.
 */
OM_uint32 
gss_verify_mic(_Out_ OM_uint32 * minor_status, _In_ gss_ctx_id_t context_handle,
	_In_ gss_buffer_t message_buffer, _In_ gss_buffer_t message_token, _Out_opt_ gss_qop_t * qop_state)
{
	if (ssh_gss_sspi_init(minor_status) == 0) 
		return GSS_S_FAILURE;

	/* translate the message and token to a security buffer so we can verify it */
	SecBuffer verify_buffer_set[] = { 
		{ (unsigned long) message_buffer->length, SECBUFFER_DATA, message_buffer->value },
		{ (unsigned long) message_token->length, SECBUFFER_TOKEN, message_token->value } };
	SecBufferDesc verify_buffer = { SECBUFFER_VERSION, _countof(verify_buffer_set), verify_buffer_set };

	/* verify message and signature */
	ULONG qop;
	const SECURITY_STATUS status = SecFunctions->VerifySignature(context_handle, &verify_buffer, 0, &qop);

	/* translate error codes */
	OM_uint32 return_code = GSS_S_COMPLETE;
	if (status != SEC_E_OK) {
		/* translate specific error */
		if (status == SEC_E_MESSAGE_ALTERED) return_code = GSS_S_BAD_SIG;
		else if (status == SEC_E_OUT_OF_SEQUENCE) return_code = GSS_S_UNSEQ_TOKEN;
		else if (status == SEC_E_INVALID_TOKEN) return_code = GSS_S_DEFECTIVE_TOKEN;
		else if (status == SEC_E_CONTEXT_EXPIRED) return_code = GSS_S_CONTEXT_EXPIRED;
		else if (status == SEC_E_QOP_NOT_SUPPORTED) return_code = GSS_S_BAD_QOP;
		else return_code = GSS_S_FAILURE;
	}

	if (qop_state != NULL)
		*qop_state = (OM_uint32) GSS_C_QOP_DEFAULT;
	
	return return_code;
}

/* 
 * Generates a cryptographic MIC for the supplied message, and places the MIC in
 * a token for transfer to the peer application. The qop_req parameter allows a
 * choice between several cryptographic algorithms, if supported by the chosen
 * mechanism.
 */
OM_uint32 
gss_get_mic(_Out_ OM_uint32 * minor_status, _In_ gss_ctx_id_t context_handle,
	_In_opt_ gss_qop_t qop_req, _In_ gss_buffer_t message_buffer, _Out_ gss_buffer_t message_token)
{
	OM_uint32 ret = GSS_S_FAILURE;

	message_token->value = NULL;	
	if (ssh_gss_sspi_init(minor_status) == 0)
		goto done;

	/* determine the max possible signature and allocate memory to support it */
	SecPkgContext_Sizes sizes;
	if (SecFunctions->QueryContextAttributesW(context_handle, SECPKG_ATTR_SIZES, &sizes) != SEC_E_OK)
		goto done;
	if ((message_token->value = malloc(sizes.cbMaxSignature)) == NULL)
		goto done;

	message_token->length = sizes.cbMaxSignature;

	/* translate the message and token to a security buffer so we can sign it */
	SecBuffer sign_buffer_set[] = {
		{ (unsigned long) message_buffer->length, SECBUFFER_DATA, message_buffer->value },
		{ (unsigned long) message_token->length, SECBUFFER_TOKEN, message_token->value } };
	SecBufferDesc sign_buffer = { SECBUFFER_VERSION, _countof(sign_buffer_set), sign_buffer_set };

	/* attempt to sign the data */
	ULONG qop = 0;
	const SECURITY_STATUS status = SecFunctions->MakeSignature(context_handle, qop, &sign_buffer, 0);

	/* translate error codes */
	if (status != SEC_E_OK)  {
		if (status == SEC_E_CONTEXT_EXPIRED) 
			ret = GSS_S_CONTEXT_EXPIRED;
		else if (status == SEC_E_QOP_NOT_SUPPORTED) 
			ret = GSS_S_BAD_QOP;
		goto done;
	}

	ret = GSS_S_COMPLETE;

done:
	if (ret != GSS_S_COMPLETE) {
		if (message_token->value) {
			free(message_token->value);
			message_token->value = NULL;
		}
	}
	return ret;
}

/*
 * Allows a remotely initiated security context between the application and a
 * remote peer to be established.  The routine may return a output_token which
 * should be transferred to the peer application, where the peer application
 * will present it to gss_init_sec_context. If no token need be sent,
 * gss_accept_sec_context will indicate this by setting the length field of the
 * output_token argument to zero.  To complete the context establishment, one or
 * more reply tokens may be required from the peer application; if so,
 * gss_accept_sec_context will return a status flag of GSS_S_CONTINUE_NEEDED, in
 * which case it should be called again when the reply token is received from
 * the peer application, passing the token to gss_accept_sec_context via the
 * input_token parameters.
 */
OM_uint32 
gss_accept_sec_context(_Out_ OM_uint32 * minor_status, _Inout_opt_ gss_ctx_id_t * context_handle,
	_In_opt_ gss_cred_id_t acceptor_cred_handle, _In_ gss_buffer_t input_token_buffer, _In_opt_ gss_channel_bindings_t input_chan_bindings,
	_Out_opt_ gss_name_t * src_name, _Out_opt_ gss_OID * mech_type, _Outptr_ gss_buffer_t output_token,
	_Out_ OM_uint32 * ret_flags, _Out_opt_ OM_uint32 * time_rec, _Outptr_opt_ gss_cred_id_t * delegated_cred_handle)
{
	OM_uint32 ret = GSS_S_FAILURE;
	gss_ctx_id_t p_ctx_h = NULL;

	*src_name = NULL;

	if (delegated_cred_handle != NULL)
		*delegated_cred_handle = NULL;

	if (ssh_gss_sspi_init(minor_status) == 0) 
		goto done;

	/* setup input buffer */
	SecBuffer input_buffer_token = { (unsigned long) input_token_buffer->length, 
		SECBUFFER_TOKEN | SECBUFFER_READONLY, input_token_buffer->value };
	SecBufferDesc input_buffer = { SECBUFFER_VERSION, 1, &input_buffer_token };

	/* setup output buffer - will be dynamically allocated by function */
	SecBuffer output_buffer_token = { 0, SECBUFFER_TOKEN, NULL };
	SecBufferDesc output_buffer = { SECBUFFER_VERSION, 1, &output_buffer_token };

	/* get the current time so we can determine expiration if requested */
	SYSTEMTIME current_time_system;
	GetSystemTime(&current_time_system);

	TimeStamp expiry;
	CtxtHandle sspi_context_handle;
	ULONG sspi_ret_flags = 0;
	ULONG sspi_req_flags = ASC_REQ_CONFIDENTIALITY | ASC_REQ_MUTUAL_AUTH | ASC_REQ_INTEGRITY | 
		ASC_REQ_DELEGATE | ASC_REQ_SEQUENCE_DETECT | ASC_REQ_ALLOCATE_MEMORY;

	/* call sspi accept security context function */
	const SECURITY_STATUS status = SecFunctions->AcceptSecurityContext(&acceptor_cred_handle->credHandle, 
		(*context_handle == GSS_C_NO_CONTEXT) ? NULL : *context_handle, &input_buffer,
		sspi_req_flags, SECURITY_NATIVE_DREP, 
		(*context_handle == GSS_C_NO_CONTEXT) ? &sspi_context_handle : *context_handle, 
		&output_buffer, &sspi_ret_flags, &expiry);

	/* translate error codes */
	if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
		if (status == SEC_E_INVALID_TOKEN) 
			ret = GSS_S_DEFECTIVE_TOKEN;
		else if (status == SEC_E_INVALID_HANDLE) 
			ret = GSS_S_NO_CONTEXT;
		goto done;
	}

	/* only do checks on the finalized context (no continue needed) */
	if (status == SEC_E_OK) {
		/* validate accepted context is actually a host service ticket */
		SecPkgContext_NativeNamesW target;
		if (SecFunctions->QueryContextAttributesW((*context_handle == GSS_C_NO_CONTEXT) ? &sspi_context_handle : *context_handle,
		    SECPKG_ATTR_NATIVE_NAMES, &target) != SEC_E_OK)
			goto done;
		
		const int valid_spn = _wcsnicmp(target.sServerName, L"host/", wcslen(L"host/")) == 0;
		FreeContextBuffer(target.sServerName);
		FreeContextBuffer(target.sClientName);
		if (valid_spn == 0) {
			debug("client passed an invalid principal name");
			ret = GSS_S_FAILURE;
			goto done;
		}
	}

	/* copy the context handler to the caller */
	if (*context_handle == GSS_C_NO_CONTEXT) {
		if ((p_ctx_h = malloc(sizeof(CtxtHandle))) == NULL)
			goto done;
		*context_handle = p_ctx_h;
		memcpy(*context_handle, &sspi_context_handle, sizeof(CtxtHandle));
	}

	/* if requested, translate returned flags that are actually available */
	if (ret_flags != NULL) {
		*ret_flags = 0;
		if (sspi_ret_flags & ASC_RET_MUTUAL_AUTH) 
			*ret_flags |= GSS_C_MUTUAL_FLAG;
		if (sspi_ret_flags & ASC_RET_CONFIDENTIALITY) 
			*ret_flags |= GSS_C_CONF_FLAG;
		if (sspi_ret_flags & ASC_RET_REPLAY_DETECT) 
			*ret_flags |= GSS_C_REPLAY_FLAG;
		if (sspi_ret_flags & ASC_RET_DELEGATE) 
			*ret_flags |= GSS_C_DELEG_FLAG;
		if (sspi_ret_flags & ASC_RET_INTEGRITY) 
			*ret_flags |= GSS_C_INTEG_FLAG;
		if (sspi_ret_flags & ASC_RET_SEQUENCE_DETECT) 
			*ret_flags |= GSS_C_SEQUENCE_FLAG;
	}

	/* report if delegation was requested by not fulfilled */
	if ((sspi_req_flags & ASC_REQ_DELEGATE) != 0 && (sspi_ret_flags & ASC_RET_DELEGATE) == 0)
		debug("%s: delegation was requested but not fulfilled", __FUNCTION__);
	
	/* if provided, specify the mechanism */
	if (mech_type != NULL)
		*mech_type = GSS_C_NT_HOSTBASED_SERVICE;
	
	/* if requested, translate the expiration time to number of second */
	if (time_rec != NULL) {
		FILETIME current_time;
		SystemTimeToFileTime(&current_time_system, &current_time);
		*time_rec = (OM_uint32)(expiry.QuadPart - ((PLARGE_INTEGER)&current_time)->QuadPart) / 10000;
	}

	/* only do checks on the finalized context (no continue needed) */
	if (status == SEC_E_OK) {
		/* extract the username from the context handle will be domain\samaccountname format */
		SecPkgContext_NamesW NamesBuffer;
		if (SecFunctions->QueryContextAttributesW(*context_handle, SECPKG_ATTR_NAMES, &NamesBuffer) != SEC_E_OK)
			goto done;
		
		/* copy to internal utf8 string and free the sspi string */
		if ((*src_name = utf16_to_utf8(NamesBuffer.sUserName)) == NULL)
			goto done;

		FreeContextBuffer(NamesBuffer.sUserName);
	}

	/* copy output token to output buffer */
	output_token->length = output_buffer_token.cbBuffer;
	output_token->value = malloc(output_token->length);
	memcpy(output_token->value, output_buffer_token.pvBuffer, output_token->length);
	SecFunctions->FreeContextBuffer(output_buffer_token.pvBuffer);

	/* get the user token for impersonation */
	if (delegated_cred_handle != NULL) {
		if ((*delegated_cred_handle = malloc(sizeof(struct cred_st))) == NULL)
			goto done;
		if (SecFunctions->QuerySecurityContextToken(*context_handle, &sspi_auth_user) != SEC_E_OK)
			goto done;
		(*delegated_cred_handle)->isToken = 1;
		(*delegated_cred_handle)->token = sspi_auth_user;
	}

	ret = (status == SEC_I_CONTINUE_NEEDED) ? GSS_S_CONTINUE_NEEDED : GSS_S_COMPLETE;

done:
	if (ret != GSS_S_COMPLETE && ret != GSS_S_CONTINUE_NEEDED) {
		if (p_ctx_h)
			free(p_ctx_h);
		if (*src_name)
			free(*src_name);
		if (delegated_cred_handle && *delegated_cred_handle)
			free(*delegated_cred_handle);
	}
	return ret;
}

/*
 * Allows an application to obtain a textual representation of an opaque
 * internal-form name for display purposes.  The syntax of a printable name is
 * defined by the GSS-API implementation.
 */
OM_uint32 
gss_display_name(_Out_ OM_uint32 * minor_status, _In_ gss_name_t input_name, 
	_Out_ gss_buffer_t output_name_buffer, _Out_ gss_OID * output_name_type)
{
	if (ssh_gss_sspi_init(minor_status) == 0) 
		return GSS_S_FAILURE;

	output_name_buffer->length = strlen(input_name) + 1;
	if ((output_name_buffer->value = _strdup(input_name)) == NULL)
		return GSS_S_FAILURE;

	/* set the output oid type if requested */
	if (output_name_type != NULL)
		*output_name_type = GSS_C_NT_HOSTBASED_SERVICE;
	
	return GSS_S_COMPLETE;
}

/*
 * Allows an application to obtain a textual representation of a GSS-API status
 * code, for display to the user or for logging purposes.  Since some status
 * values may indicate multiple conditions, applications may need to call
 * gss_display_status multiple times, each call generating a single text string.
 * The message_context parameter is used by gss_display_status to store state
 * information about which error messages have already been extracted from a
 * given status_value; message_context must be initialized to 0 by the
 * application prior to the first call, and gss_display_status will return a
 * non-zero value in this parameter if there are further messages to extract.
 */
OM_uint32 
gss_display_status(_In_ OM_uint32 * minor_status, _In_ OM_uint32 status_value, _In_ int status_type,
	_In_opt_ gss_OID mech_type, _Out_ OM_uint32 * message_context, _Inout_ gss_buffer_t status_string)
{
	if (ssh_gss_sspi_init(minor_status) == 0) 
		return GSS_S_FAILURE;

	/* lookup textual representation of the numeric status code */
	char * message_string = NULL;
	if (status_value == GSS_S_COMPLETE) 
		message_string = "GSS_S_COMPLETE";
	else if (status_value == GSS_S_BAD_BINDINGS) 
		message_string = "GSS_S_BAD_BINDINGS";
	else if (status_value == GSS_S_BAD_MECH) 
		message_string = "GSS_S_BAD_MECH";
	else if (status_value == GSS_S_BAD_NAME) 
		message_string = "GSS_S_BAD_NAME";
	else if (status_value == GSS_S_BAD_NAMETYPE) 
		message_string = "GSS_S_BAD_NAMETYPE";
	else if (status_value == GSS_S_BAD_QOP) 
		message_string = "GSS_S_BAD_QOP";
	else if (status_value == GSS_S_BAD_SIG) 
		message_string = "GSS_S_BAD_SIG";
	else if (status_value == GSS_S_BAD_STATUS) 
		message_string = "GSS_S_BAD_STATUS";
	else if (status_value == GSS_S_CONTEXT_EXPIRED) 
		message_string = "GSS_S_CONTEXT_EXPIRED";
	else if (status_value == GSS_S_CONTINUE_NEEDED) 
		message_string = "GSS_S_CONTINUE_NEEDED";
	else if (status_value == GSS_S_CREDENTIALS_EXPIRED) 
		message_string = "GSS_S_CREDENTIALS_EXPIRED";
	else if (status_value == GSS_S_DEFECTIVE_CREDENTIAL) 
		message_string = "GSS_S_DEFECTIVE_CREDENTIAL";
	else if (status_value == GSS_S_DEFECTIVE_TOKEN) 
		message_string = "GSS_S_DEFECTIVE_TOKEN";
	else if (status_value == GSS_S_DUPLICATE_ELEMENT) 
		message_string = "GSS_S_DUPLICATE_ELEMENT";
	else if (status_value == GSS_S_DUPLICATE_TOKEN) 
		message_string = "GSS_S_DUPLICATE_TOKEN";
	else if (status_value == GSS_S_FAILURE) 
		message_string = "GSS_S_FAILURE";
	else if (status_value == GSS_S_NAME_NOT_MN) 
		message_string = "GSS_S_NAME_NOT_MN";
	else if (status_value == GSS_S_NO_CONTEXT) 
		message_string = "GSS_S_NO_CONTEXT";
	else if (status_value == GSS_S_NO_CRED) 
		message_string = "GSS_S_NO_CRED";
	else if (status_value == GSS_S_OLD_TOKEN) 
		message_string = "GSS_S_OLD_TOKEN";
	else if (status_value == GSS_S_UNAUTHORIZED) 
		message_string = "GSS_S_UNAUTHORIZED";
	else if (status_value == GSS_S_UNAVAILABLE) 
		message_string = "GSS_S_UNAVAILABLE";
	else if (status_value == GSS_S_UNSEQ_TOKEN) 
		message_string = "GSS_S_UNSEQ_TOKEN";

	/* copy local status string to the output buffer */
	status_string->length = strlen(message_string) + 1;
	if ((status_string->value = _strdup(message_string)) == NULL)
		return GSS_S_FAILURE;

	/* no supplementary messages available */
	*message_context = 0;

	return GSS_S_COMPLETE;
}

/*
 * The function ssh_gssapi_krb5_userok and gssapi_kerberos_mech structure
 * are referenced in gss-serv.c and are required in order for the calling
 * code to accept negotiate a kerberos token.
 */

static int 
ssh_gssapi_krb5_userok(ssh_gssapi_client *client, char *name)
{
	/*
	 * This check is important since it makes sure that the username string
	 * that the user passed (e.g. user@host) matches the user authenticated
	 * via SSPI.  If this check fails, the authentication process will move
	 * onto the next available method.
	 */
	struct passwd * user = getpwnam(name);
	if (_stricmp(client->displayname.value, user->pw_name) != 0) {
		/* check failed */
		debug("sspi user '%s' did not match user-provided, resolved user '%s'", 
			(char *) client->displayname.value, name);
		return 0;
	}

	return 1;
}

ssh_gssapi_mech gssapi_kerberos_mech = {
	"toWM5Slw5Ew8Mqkay+al2g==",
	"Kerberos",
	{sizeof(GSS_C_NT_HOSTBASED_SERVICE_STR) - 1, GSS_C_NT_HOSTBASED_SERVICE_STR},
	NULL,
	&ssh_gssapi_krb5_userok,
	NULL,
	NULL
};