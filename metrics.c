#include "includes.h"
#include "metrics.h"
#include "ssherr.h"
#include <stdlib.h>

#ifdef __linux__
#include <linux/version.h>
#endif

/* add the information from the tcp_info struct to the
 * serialized binary object
 */
void
metrics_write_binn_object(struct tcp_info *data, struct binn_struct *binnobj) {
/* the base set of tcpi_ measurements starting from kernel 3.7.0
 * these measurements existed in previous kernels but the oldest this
 * is going to support is 3.7.0. We do need to store the kernel version as well */
	binn_object_set_uint32(binnobj, "kernel_version", LINUX_VERSION_CODE);

	if (data->tcpi_rcv_ssthresh)
		binn_object_set_uint32(binnobj, "tcpi_rcv_ssthresh",
				       data->tcpi_rcv_ssthresh);
	if (data->tcpi_snd_ssthresh)
		binn_object_set_uint32(binnobj, "tcpi_snd_ssthresh",
				       data->tcpi_snd_ssthresh);
	if (data->tcpi_rtt)
		binn_object_set_uint32(binnobj, "tcpi_rtt",
				       data->tcpi_rtt);
	if (data->tcpi_backoff)
		binn_object_set_uint8(binnobj, "tcpi_backoff",
				      data->tcpi_backoff);
	if (data->tcpi_rcv_rtt)
		binn_object_set_uint32(binnobj, "tcpi_rcv_rtt",
				       data->tcpi_rcv_rtt);
	if (data->tcpi_total_retrans)
		binn_object_set_uint32(binnobj, "tcpi_total_retrans",
				       data->tcpi_total_retrans);
	if (data->tcpi_last_data_recv)
		binn_object_set_uint32(binnobj, "tcpi_last_data_recv",
				       data->tcpi_last_data_recv);
	if (data->tcpi_ca_state)
		binn_object_set_uint8(binnobj, "tcpi_ca_state",
				      data->tcpi_ca_state);
	if (data->tcpi_sacked)
		binn_object_set_uint32(binnobj, "tcpi_sacked",
				       data->tcpi_sacked);
	if (data->tcpi_pmtu)
		binn_object_set_uint32(binnobj, "tcpi_pmtu",
				       data->tcpi_pmtu);
	if (data->tcpi_ato)
		binn_object_set_uint32(binnobj, "tcpi_ato",
				       data->tcpi_ato);
	if (data->tcpi_snd_wscale)
		binn_object_set_uint8(binnobj, "tcpi_snd_wscale",
				      data->tcpi_snd_wscale);
	if (data->tcpi_probes)
		binn_object_set_uint8(binnobj, "tcpi_probes",
				      data->tcpi_probes);
	if (data->tcpi_fackets)
		binn_object_set_uint32(binnobj, "tcpi_fackets",
				       data->tcpi_fackets);
	if (data->tcpi_rcv_wscale)
		binn_object_set_uint8(binnobj, "tcpi_rcv_wscale",
				      data->tcpi_rcv_wscale);
	if (data->tcpi_lost)
		binn_object_set_uint32(binnobj, "tcpi_lost",
				       data->tcpi_lost);
	if (data->tcpi_last_ack_sent)
		binn_object_set_uint32(binnobj, "tcpi_last_ack_sent",
				       data->tcpi_last_ack_sent);
	if (data->tcpi_state)
		binn_object_set_uint8(binnobj, "tcpi_state",
				      data->tcpi_state);
	if (data->tcpi_rttvar)
		binn_object_set_uint32(binnobj, "tcpi_rttvar",
				       data->tcpi_rttvar);
	if (data->tcpi_retransmits)
		binn_object_set_uint8(binnobj, "tcpi_retransmits",
				      data->tcpi_retransmits);
	if (data->tcpi_unacked)
		binn_object_set_uint32(binnobj, "tcpi_unacked",
				       data->tcpi_unacked);
	if (data->tcpi_last_data_sent)
		binn_object_set_uint32(binnobj, "tcpi_last_data_sent",
				       data->tcpi_last_data_sent);
	if (data->tcpi_snd_cwnd)
		binn_object_set_uint32(binnobj, "tcpi_snd_cwnd",
				       data->tcpi_snd_cwnd);
	if (data->tcpi_rcv_mss)
		binn_object_set_uint32(binnobj, "tcpi_rcv_mss",
				       data->tcpi_rcv_mss);
	if (data->tcpi_last_ack_recv)
		binn_object_set_uint32(binnobj, "tcpi_last_ack_recv",
				       data->tcpi_last_ack_recv);
	if (data->tcpi_reordering)
		binn_object_set_uint32(binnobj, "tcpi_reordering",
				       data->tcpi_reordering);
	if (data->tcpi_advmss)
		binn_object_set_uint32(binnobj, "tcpi_advmss",
				       data->tcpi_advmss);
	if (data->tcpi_rto)
		binn_object_set_uint32(binnobj, "tcpi_rto",
				       data->tcpi_rto);
	if (data->tcpi_snd_mss)
		binn_object_set_uint32(binnobj, "tcpi_snd_mss",
				       data->tcpi_snd_mss);
	if (data->tcpi_rcv_space)
		binn_object_set_uint32(binnobj, "tcpi_rcv_space",
				       data->tcpi_rcv_space);
	if (data->tcpi_options)
		binn_object_set_uint8(binnobj, "tcpi_options",
				      data->tcpi_options);
	if (data->tcpi_retrans)
		binn_object_set_uint32(binnobj, "tcpi_retrans",
				       data->tcpi_retrans);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
	if (data->tcpi_max_pacing_rate)
		binn_object_set_uint64(binnobj, "tcpi_max_pacing_rate",
				       data->tcpi_max_pacing_rate);
	if (data->tcpi_pacing_rate)
		binn_object_set_uint64(binnobj, "tcpi_pacing_rate",
				       data->tcpi_pacing_rate);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
	if (data->tcpi_bytes_acked)
		binn_object_set_uint64(binnobj, "tcpi_bytes_acked",
				       data->tcpi_bytes_acked);
	if (data->tcpi_bytes_received)
		binn_object_set_uint64(binnobj, "tcpi_bytes_received",
				       data->tcpi_bytes_received);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	if (data->tcpi_segs_in)
		binn_object_set_uint32(binnobj, "tcpi_segs_in",
				       data->tcpi_segs_in);
	if (data->tcpi_segs_out)
		binn_object_set_uint32(binnobj, "tcpi_segs_out",
				       data->tcpi_segs_out);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
	if (data->tcpi_notsent_bytes)
		binn_object_set_uint32(binnobj, "tcpi_notsent_bytes",
				       data->tcpi_notsent_bytes);
	if (data->tcpi_min_rtt)
		binn_object_set_uint32(binnobj, "tcpi_min_rtt",
				       data->tcpi_min_rtt);
	if (data->tcpi_data_segs_in)
		binn_object_set_uint32(binnobj, "tcpi_data_segs_in",
				       data->tcpi_data_segs_in);
	if (data->tcpi_data_segs_out)
		binn_object_set_uint32(binnobj, "tcpi_data_segs_out",
				       data->tcpi_data_segs_out);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
	if (data->tcpi_delivery_rate_app_limited)
		binn_object_set_uint8(binnobj, "tcpi_delivery_rate_app_limited",
				      data->tcpi_delivery_rate_app_limited);
	if (data->tcpi_delivery_rate)
		binn_object_set_uint64(binnobj, "tcpi_delivery_rate",
				       data->tcpi_delivery_rate);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	if (data->tcpi_busy_time)
		binn_object_set_uint64(binnobj, "tcpi_busy_time",
				       data->tcpi_busy_time);
	if (data->tcpi_sndbuf_limited)
		binn_object_set_uint64(binnobj, "tcpi_sndbuf_limited",
				       data->tcpi_sndbuf_limited);
	if (data->tcpi_rwnd_limited)
		binn_object_set_uint64(binnobj, "tcpi_rwnd_limited",
				       data->tcpi_rwnd_limited);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
	if (data->tcpi_delivered)
		binn_object_set_uint32(binnobj, "tcpi_delivered",
				       data->tcpi_delivered);
	if (data->tcpi_delivered_ce)
		binn_object_set_uint32(binnobj, "tcpi_delivered_ce",
				       data->tcpi_delivered_ce);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)
	if (data->tcpi_bytes_sent)
		binn_object_set_uint64(binnobj, "tcpi_bytes_sent",
				       data->tcpi_bytes_sent);
	if (data->tcpi_bytes_retrans)
		binn_object_set_uint64(binnobj, "tcpi_bytes_retrans",
				       data->tcpi_bytes_retrans);
	if (data->tcpi_dsack_dups)
		binn_object_set_uint32(binnobj, "tcpi_dsack_dups",
				       data->tcpi_dsack_dups);
	if (data->tcpi_reord_seen)
		binn_object_set_uint32(binnobj, "tcpi_reord_seen",
				       data->tcpi_reord_seen);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
	if (data->tcpi_snd_wnd)
		binn_object_set_uint32(binnobj, "tcpi_snd_wnd",
				       data->tcpi_snd_wnd);
	if (data->tcpi_rcv_ooopack)
		binn_object_set_uint32(binnobj, "tcpi_rcv_ooopack",
				       data->tcpi_rcv_ooopack);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
	if (data->tcpi_fastopen_client_fail)
		binn_object_set_uint8(binnobj, "tcpi_fastopen_client_fail",
				      data->tcpi_fastopen_client_fail);
#endif
}

/* this reads out the tcp_info binn object and formats it into a single line
 * the object will not necessarily have all of the elements. If it's empty it
 * current just spits out 0. This isn't optimal as 0 can also be a valid value */
void
metrics_read_binn_object (void *binnobj, char **output) {
	int len = 0;
	int buflen = 1023;
	int kernel_version = 0;
	if (binnobj == NULL) {
		fprintf(stderr, "Metric polling returned bad data.\n");
		return;
	}
	kernel_version = binn_object_uint32(binnobj, "kernel_version");

	/* base set of metrics */
	len = snprintf(*output, buflen, "%d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d",
		       binn_object_uint8(binnobj, "tcpi_state"),
		       binn_object_uint8(binnobj, "tcpi_ca_state"),
		       binn_object_uint8(binnobj, "tcpi_retransmits"),
		       binn_object_uint8(binnobj, "tcpi_probes"),
		       binn_object_uint8(binnobj, "tcpi_backoff"),
		       binn_object_uint8(binnobj, "tcpi_options"),
		       binn_object_uint8(binnobj, "tcpi_snd_wscale"),
		       binn_object_uint8(binnobj, "tcpi_rcv_wscale"),
		       binn_object_uint32(binnobj, "tcpi_rto"),
		       binn_object_uint32(binnobj, "tcpi_ato"),
		       binn_object_uint32(binnobj, "tcpi_snd_mss"),
		       binn_object_uint32(binnobj, "tcpi_rcv_mss"),
		       binn_object_uint32(binnobj, "tcpi_unacked"),
		       binn_object_uint32(binnobj, "tcpi_sacked"),
		       binn_object_uint32(binnobj, "tcpi_lost"),
		       binn_object_uint32(binnobj, "tcpi_retrans"),
		       binn_object_uint32(binnobj, "tcpi_fackets"),
		       binn_object_uint32(binnobj, "tcpi_last_data_sent"),
		       binn_object_uint32(binnobj, "tcpi_last_ack_sent"),
		       binn_object_uint32(binnobj, "tcpi_last_data_recv"),
		       binn_object_uint32(binnobj, "tcpi_last_ack_recv"),
		       binn_object_uint32(binnobj, "tcpi_pmtu"),
		       binn_object_uint32(binnobj, "tcpi_rcv_ssthresh"),
		       binn_object_uint32(binnobj, "tcpi_rtt"),
		       binn_object_uint32(binnobj, "tcpi_rttvar"),
		       binn_object_uint32(binnobj, "tcpi_snd_ssthresh"),
		       binn_object_uint32(binnobj, "tcpi_snd_cwnd"),
		       binn_object_uint32(binnobj, "tcpi_advmss"),
		       binn_object_uint32(binnobj, "tcpi_reordering"),
		       binn_object_uint32(binnobj, "tcpi_rcv_rtt"),
		       binn_object_uint32(binnobj, "tcpi_rcv_space")
		);

	/* compare the received kernel version to the version that supports
	 * any given metric. This means that a remote host that has a different
	 * kernel that the local host will be able to process the data in terms of
	 * the remote kernel version.*/
	if (kernel_version >= KERNEL_VERSION(3,15,0)) {
		len += snprintf(*output+len, (buflen-len), ", %llu, %llu",
				binn_object_uint64(binnobj, "tcpi_max_pacing_rate"),
				binn_object_uint64(binnobj, "tcpi_pacing_rate")
			);
	}

	if (kernel_version >= KERNEL_VERSION(4,1,0)) {
		len += snprintf(*output+len, (buflen-len), ", %llu, %llu",
				binn_object_uint64(binnobj, "tcpi_bytes_acked"),
				binn_object_uint64(binnobj, "tcpi_bytes_received")
			);
	}

	if (kernel_version >= KERNEL_VERSION(4,2,0)) {
		len += snprintf(*output+len, (buflen-len), ", %d, %d",
				binn_object_uint32(binnobj, "tcpi_segs_in"),
				binn_object_uint32(binnobj, "tcpi_segs_out")
			);
	}

	if (kernel_version >= KERNEL_VERSION(4,6,0)) {
		len += snprintf(*output+len, (buflen-len), ", %d, %d, %d, %d",
				binn_object_uint32(binnobj, "tcpi_notsent_bytes"),
				binn_object_uint32(binnobj, "tcpi_min_rtt"),
				binn_object_uint32(binnobj, "tcpi_data_segs_in"),
				binn_object_uint32(binnobj, "tcpi_data_segs_out")
			);
	}

	if (kernel_version >= KERNEL_VERSION(4,9,0)) {
		len += snprintf(*output+len, (buflen-len), ", %d, %llu",
				binn_object_uint8(binnobj, "tcpi_delivery_rate_app_limited"),
				binn_object_uint64(binnobj, "tcpi_delivery_rate")
			);
	}

	if (kernel_version >= KERNEL_VERSION(4,10,0)) {
		len += snprintf(*output+len, (buflen-len), ", %llu, %llu, %llu",
				binn_object_uint64(binnobj, "tcpi_busy_time"),
				binn_object_uint64(binnobj, "tcpi_sndbuf_limited"),
				binn_object_uint64(binnobj, "tcpi_rwnd_limited")
			);
	}

	if (kernel_version >= KERNEL_VERSION(4,18,0)) {
		len += snprintf(*output+len, (buflen-len), ", %d, %d",
				binn_object_uint32(binnobj, "tcpi_delivered"),
				binn_object_uint32(binnobj, "tcpi_delivered_ce")
			);
	}

	if (kernel_version >= KERNEL_VERSION(4,19,0)) {
		len += snprintf(*output+len, (buflen-len), ", %llu, %llu, %d, %d",
				binn_object_uint64(binnobj, "tcpi_bytes_sent"),
				binn_object_uint64(binnobj, "tcpi_bytes_retrans"),
				binn_object_uint32(binnobj, "tcpi_dsack_dups"),
				binn_object_uint32(binnobj, "tcpi_reord_seen")
			);
	}

	if (kernel_version >= KERNEL_VERSION(5,4,0)) {
		len += snprintf(*output+len, (buflen-len), ", %d, %d",
				binn_object_uint32(binnobj, "tcpi_snd_wnd"),
				binn_object_uint32(binnobj, "tcpi_rcv_ooopack")
			);
	}

	if (kernel_version >= KERNEL_VERSION(5,5,0)) {
		len += snprintf(*output+len, (buflen-len), ", %d",
				binn_object_uint8(binnobj, "tcpi_fastopen_client_fail")
			);
	}


	/* len = snprintf(*output, 1023, "%d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %lld, %lld, %lld, %lld, %d, %d, %d, %d, %d, %d, %lld, %lld, %lld, %lld, %d, %d, %lld, %lld, %d, %d, %d, %d\n", */
	/* 	binn_object_int8(binnobj, "tcpi_state"), */
	/* 	binn_object_int8(binnobj, "tcpi_ca_state"), */
	/* 	binn_object_int8(binnobj, "tcpi_retransmits"), */
	/* 	binn_object_int8(binnobj, "tcpi_probes"), */
	/* 	binn_object_int8(binnobj, "tcpi_backoff"), */
	/* 	binn_object_int8(binnobj, "tcpi_options"), */
	/* 	binn_object_int8(binnobj, "tcpi_snd_wscale"), */
	/* 	binn_object_int8(binnobj, "tcpi_rcv_wscale"), */
	/* 	binn_object_int8(binnobj, "tcpi_delivery_rate_app_limited"), */
	/* 	binn_object_int8(binnobj, "tcpi_fastopen_client_fail"), */
	/* 	binn_object_int32(binnobj, "tcpi_rto"), */
	/* 	binn_object_int32(binnobj, "tcpi_ato"), */
	/* 	binn_object_int32(binnobj, "tcpi_snd_mss"), */
	/* 	binn_object_int32(binnobj, "tcpi_rcv_mss"), */
	/* 	binn_object_int32(binnobj, "tcpi_unacked"), */
	/* 	binn_object_int32(binnobj, "tcpi_sacked"), */
	/* 	binn_object_int32(binnobj, "tcpi_lost"), */
	/* 	binn_object_int32(binnobj, "tcpi_retrans"), */
	/* 	binn_object_int32(binnobj, "tcpi_fackets"), */
	/* 	binn_object_int32(binnobj, "tcpi_last_data_sent"), */
	/* 	binn_object_int32(binnobj, "tcpi_last_ack_sent"), */
	/* 	binn_object_int32(binnobj, "tcpi_last_data_recv"), */
	/* 	binn_object_int32(binnobj, "tcpi_last_ack_recv"), */
	/* 	binn_object_int32(binnobj, "tcpi_pmtu"), */
	/* 	binn_object_int32(binnobj, "tcpi_rcv_ssthresh"), */
	/* 	binn_object_int32(binnobj, "tcpi_rtt"), */
	/* 	binn_object_int32(binnobj, "tcpi_rttvar"), */
	/* 	binn_object_int32(binnobj, "tcpi_snd_ssthresh"), */
	/* 	binn_object_int32(binnobj, "tcpi_snd_cwnd"), */
	/* 	binn_object_int32(binnobj, "tcpi_advmss"), */
	/* 	binn_object_int32(binnobj, "tcpi_reordering"), */
	/* 	binn_object_int32(binnobj, "tcpi_rcv_rtt"), */
	/* 	binn_object_int32(binnobj, "tcpi_rcv_space"), */
	/* 	binn_object_int32(binnobj, "tcpi_total_retrans"), */
	/* 	binn_object_int64(binnobj, "tcpi_pacing_rate"), */
	/* 	binn_object_int64(binnobj, "tcpi_max_pacing_rate"), */
	/* 	binn_object_int64(binnobj, "tcpi_bytes_acked"), */
	/* 	binn_object_int64(binnobj, "tcpi_bytes_received"), */
	/* 	binn_object_int32(binnobj, "tcpi_segs_out"), */
	/* 	binn_object_int32(binnobj, "tcpi_segs_in"), */
	/* 	binn_object_int32(binnobj, "tcpi_notsent_bytes"), */
	/* 	binn_object_int32(binnobj, "tcpi_min_rtt"), */
	/* 	binn_object_int32(binnobj, "tcpi_data_segs_in"), */
	/* 	binn_object_int32(binnobj, "tcpi_data_segs_out"), */
	/* 	binn_object_int64(binnobj, "tcpi_delivery_rate"), */
	/* 	binn_object_int64(binnobj, "tcpi_busy_time"), */
	/* 	binn_object_int64(binnobj, "tcpi_rwnd_limited"), */
	/* 	binn_object_int64(binnobj, "tcpi_sndbuf_limited"), */
	/* 	binn_object_int32(binnobj, "tcpi_delivered"), */
	/* 	binn_object_int32(binnobj, "tcpi_delivered_ce"), */
	/* 	binn_object_int64(binnobj, "tcpi_bytes_sent"), */
	/* 	binn_object_int64(binnobj, "tcpi_bytes_retrans"), */
	/* 	binn_object_int32(binnobj, "tcpi_dsack_dups"), */
	/* 	binn_object_int32(binnobj, "tcpi_reord_seen"), */
	/* 	binn_object_int32(binnobj, "tcpi_rcv_ooopack"), */
	/* 	binn_object_int32(binnobj, "tcpi_snd_wnd")); */
}

/*this is just long and unseemly so we make it a function */
void
metrics_print_header(FILE *fptr, char *extra_text) {
	if (fptr == NULL) {
		//return -1;
	}
	if (extra_text != NULL) {
		fprintf(fptr, "%s\n", extra_text);
	}
	fprintf(fptr, "state, ca_state, retransmits, probes, backoff, options, ");
	fprintf(fptr, "snd_wscale, rcv_wscale, delivery_rate_app_limited, fastopen_client_fail, ");
	fprintf(fptr, "rto, ato, snd_mss, rcv_mss, unacked, sacked, lost, retrans, ");
	fprintf(fptr, "fackets, last_data_sent, last_ack_sent, last_data_recv, ");
	fprintf(fptr, "last_ack_recv, pmtu, rcv_ssthresh, rtt, rttvar, snd_ssthresh, ");
	fprintf(fptr, "snd_cwnd, advmss, reordering, rcv_rtt, rcv_space, total_retrans, ");
	fprintf(fptr, "pacing_rate, max_pacing_rate, bytes_acked, bytes_received, segs_out, ");
	fprintf(fptr, "segs_in, notsent_bytes, min_rtt, data_segs_in, data_segs_out, ");
	fprintf(fptr, "delivery_rate, busy_time, rwnd_limited, sndbuf_limited, delivered, ");
	fprintf(fptr, "delivered_ce, bytes_sent, bytes_retrans, dsack_dups, reord_seen, ");
	fprintf(fptr, "rcv_ooopack, snd_wnd\n\n");
}
