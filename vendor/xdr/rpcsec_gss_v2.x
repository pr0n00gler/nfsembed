/*
 * Copyright (c) 2009 IETF Trust and the persons identified
 * as the document authors. All rights reserved.
 *
 * The document authors are identified in [RFC2203] and
 * [RFC5403].
 *
 * Redistribution and use in source and binary forms, with
 * or without modification, are permitted provided that the
 * following conditions are met:
 *
 * o Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer in the documentation and/or other
 *   materials provided with the distribution.
 *
 * o Neither the name of Internet Society, IETF or IETF
 *   Trust, nor the names of specific contributors, may be
 *   used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS
 *   AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 *   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *   FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 *   EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *   NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 *   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * This code was derived from [RFC2203]. Please
 * reproduce this note if possible.
 */

 enum rpc_gss_service_t {
   /* Note: the enumerated value for 0 is reserved. */
   rpc_gss_svc_none         = 1,
   rpc_gss_svc_integrity    = 2,
   rpc_gss_svc_privacy      = 3,
   rpc_gss_svc_channel_prot = 4 /* new */
 };

  enum rpc_gss_proc_t {
    RPCSEC_GSS_DATA          = 0,
    RPCSEC_GSS_INIT          = 1,
    RPCSEC_GSS_CONTINUE_INIT = 2,
    RPCSEC_GSS_DESTROY       = 3,
    RPCSEC_GSS_BIND_CHANNEL  = 4 /* new */
 };

 struct rpc_gss_cred_vers_1_t {
   rpc_gss_proc_t    gss_proc; /* control procedure */
   unsigned int      seq_num;  /* sequence number */
   rpc_gss_service_t service;  /* service used */
   opaque            handle<>; /* context handle */
 };

 const RPCSEC_GSS_VERS_1 = 1;
 const RPCSEC_GSS_VERS_2 = 2; /* new */

 union rpc_gss_cred_t switch (unsigned int rgc_version) {
   case RPCSEC_GSS_VERS_1:
   case RPCSEC_GSS_VERS_2: /* new */
     rpc_gss_cred_vers_1_t rgc_cred_v1;
 };

 struct rgss2_bind_chan_MIC_in_args {
   opaque          rbcmia_bind_chan_hash<>;
 };

 typedef opaque    rgss2_chan_pref<>;
 typedef opaque    rgss2_oid<>;

 struct rgss2_bind_chan_verf_args {
   rgss2_chan_pref rbcva_chan_bind_prefix;
   rgss2_oid       rbcva_chan_bind_oid_hash;
   opaque          rbcva_chan_mic<>;
 };

 enum rgss2_bind_chan_status {
   RGSS2_BIND_CHAN_OK           = 0,
   RGSS2_BIND_CHAN_PREF_NOTSUPP = 1,
   RGSS2_BIND_CHAN_HASH_NOTSUPP = 2
 };

 union rgss2_bind_chan_res switch
    (rgss2_bind_chan_status rbcr_stat) {

   case RGSS2_BIND_CHAN_OK:
     void;

   case RGSS2_BIND_CHAN_PREF_NOTSUPP:
     rgss2_chan_pref rbcr_pref_list<>;

   case RGSS2_BIND_CHAN_HASH_NOTSUPP:
     rgss2_oid       rbcr_oid_list<>;
 };

 struct rgss2_bind_chan_MIC_in_res {
   unsigned int        rbcmr_seq_num;
   opaque              rbcmr_bind_chan_hash<>;
   rgss2_bind_chan_res rbcmr_res;
 };

 struct rgss2_bind_chan_verf_res {
   rgss2_bind_chan_res rbcvr_res;
   opaque              rbcvr_mic<>;
 };
