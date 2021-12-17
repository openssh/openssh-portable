#include "includes.h"
#include "metrics.h"
#include "ssherr.h"
#include <stdlib.h>
#ifdef __linux__
#include <linux/version.h>
#endif

#ifndef KERNEL_VERSION /* shouldn't be necessary to define this */
#define KERNEL_VERSION(a,b,c) (((a) <<16) + ((b) << 8) +(c))
#endif

/* add the information from the tcp_info struct to the
 * serialized binary object
 */
void
metrics_write_binn_object(struct tcp_info *data, struct binn_struct *binnobj) {
#if !defined TCP_INFO
	/*tcp info isn't supported on this system */
	return;
#else

/* the base set of tcpi_ measurements starting from kernel 3.7.0
 * these measurements existed in previous kernels but the oldest this
 * is going to support is 3.7.0. We do need to store the kernel version as well */

/* obvioulsy the version code macro only exists under linux so
 * on non linux systems we set the kernel version to 0
 * which will get us the base set of metrics from netinet/tcp.h
 */
#ifdef __linux__
	binn_object_set_uint32(binnobj, "kernel_version", LINUX_VERSION_CODE);
#else
	binn_object_set_uint32(binnobj, "kernel_version", 0);
#endif

	/* the following are common under both linux and BSD */
	binn_object_set_uint8(binnobj, "tcpi_snd_wscale",
			      data->tcpi_snd_wscale);
	binn_object_set_uint8(binnobj, "tcpi_rcv_wscale",
			      data->tcpi_rcv_wscale);
	binn_object_set_uint8(binnobj, "tcpi_state",
			      data->tcpi_state);
	binn_object_set_uint8(binnobj, "tcpi_options",
			      data->tcpi_options);
	binn_object_set_uint32(binnobj, "tcpi_snd_ssthresh",
			       data->tcpi_snd_ssthresh);
	binn_object_set_uint32(binnobj, "tcpi_rtt",
			       data->tcpi_rtt);
	binn_object_set_uint32(binnobj, "tcpi_last_data_recv",
			       data->tcpi_last_data_recv);
	binn_object_set_uint32(binnobj, "tcpi_rttvar",
			       data->tcpi_rttvar);
	binn_object_set_uint32(binnobj, "tcpi_snd_cwnd",
			       data->tcpi_snd_cwnd);
	binn_object_set_uint32(binnobj, "tcpi_rcv_mss",
			       data->tcpi_rcv_mss);
	binn_object_set_uint32(binnobj, "tcpi_rto",
			       data->tcpi_rto);
	binn_object_set_uint32(binnobj, "tcpi_snd_mss",
			       data->tcpi_snd_mss);
	binn_object_set_uint32(binnobj, "tcpi_rcv_space",
			       data->tcpi_rcv_space);

/* the following exist under both but with different names */
#ifdef __linux__
	binn_object_set_uint8(binnobj, "tcpi_ca_state",
			      data->tcpi_ca_state);
	binn_object_set_uint8(binnobj, "tcpi_probes",
			      data->tcpi_probes);
	binn_object_set_uint8(binnobj, "tcpi_backoff",
			      data->tcpi_backoff);
	binn_object_set_uint8(binnobj, "tcpi_retransmits",
			      data->tcpi_retransmits);
	binn_object_set_uint32(binnobj, "tcpi_rcv_ssthresh",
			       data->tcpi_rcv_ssthresh);
	binn_object_set_uint32(binnobj, "tcpi_sacked",
			       data->tcpi_sacked);
	binn_object_set_uint32(binnobj, "tcpi_pmtu",
			       data->tcpi_pmtu);
	binn_object_set_uint32(binnobj, "tcpi_fackets",
			       data->tcpi_fackets);
	binn_object_set_uint32(binnobj, "tcpi_lost",
			       data->tcpi_lost);
	binn_object_set_uint32(binnobj, "tcpi_last_ack_sent",
			       data->tcpi_last_ack_sent);
	binn_object_set_uint32(binnobj, "tcpi_unacked",
			       data->tcpi_unacked);
	binn_object_set_uint32(binnobj, "tcpi_last_data_sent",
			       data->tcpi_last_data_sent);
	binn_object_set_uint32(binnobj, "tcpi_last_ack_recv",
			       data->tcpi_last_ack_recv);
	binn_object_set_uint32(binnobj, "tcpi_reordering",
			       data->tcpi_reordering);
	binn_object_set_uint32(binnobj, "tcpi_advmss",
			       data->tcpi_advmss);
	binn_object_set_uint32(binnobj, "tcpi_retrans",
			       data->tcpi_retrans);
	binn_object_set_uint32(binnobj, "tcpi_ato",
			       data->tcpi_ato);
	binn_object_set_uint32(binnobj, "tcpi_rcv_rtt",
			       data->tcpi_rcv_rtt);
#else
	binn_object_set_uint8(binnobj, "tcpi_backoff",
			      data->__tcpi_backoff);
	binn_object_set_uint8(binnobj, "tcpi_ca_state",
			      data->__tcpi_ca_state);
	binn_object_set_uint8(binnobj, "tcpi_probes",
			      data->__tcpi_probes);
	binn_object_set_uint8(binnobj, "tcpi_retransmits",
			      data->__tcpi_retransmits);
	binn_object_set_uint32(binnobj, "tcpi_rcv_ssthresh",
			       data->__tcpi_rcv_ssthresh);
	binn_object_set_uint32(binnobj, "tcpi_sacked",
			       data->__tcpi_sacked);
	binn_object_set_uint32(binnobj, "tcpi_pmtu",
			       data->__tcpi_pmtu);
	binn_object_set_uint32(binnobj, "tcpi_fackets",
			       data->__tcpi_fackets);
	binn_object_set_uint32(binnobj, "tcpi_lost",
			       data->__tcpi_lost);
	binn_object_set_uint32(binnobj, "tcpi_last_ack_sent",
			       data->__tcpi_last_ack_sent);
	binn_object_set_uint32(binnobj, "tcpi_unacked",
			       data->__tcpi_unacked);
	binn_object_set_uint32(binnobj, "tcpi_last_data_sent",
			       data->__tcpi_last_data_sent);
	binn_object_set_uint32(binnobj, "tcpi_last_ack_recv",
			       data->__tcpi_last_ack_recv);
	binn_object_set_uint32(binnobj, "tcpi_reordering",
			       data->__tcpi_reordering);
	binn_object_set_uint32(binnobj, "tcpi_advmss",
			       data->__tcpi_advmss);
	binn_object_set_uint32(binnobj, "tcpi_retrans",
			       data->__tcpi_retrans);
	binn_object_set_uint32(binnobj, "tcpi_ato",
			       data->__tcpi_ato);
	binn_object_set_uint32(binnobj, "tcpi_rcv_rtt",
			       data->__tcpi_rcv_rtt);
#endif

/* Under BSD snd_rexmitpack is the same as linux total_retrans*/
#ifdef __linux__
	binn_object_set_uint32(binnobj, "tcpi_total_retrans",
			       data->tcpi_total_retrans);
#else
	binn_object_set_uint32(binnobj, "tcpi_total_retrans",
			       data->tcpi_snd_rexmitpack);
#endif

/* The last section are for kernel specific metrics in linux */
#ifdef __linux__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
	binn_object_set_uint64(binnobj, "tcpi_max_pacing_rate",
			       data->tcpi_max_pacing_rate);
	binn_object_set_uint64(binnobj, "tcpi_pacing_rate",
			       data->tcpi_pacing_rate);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
	binn_object_set_uint64(binnobj, "tcpi_bytes_acked",
			       data->tcpi_bytes_acked);
	binn_object_set_uint64(binnobj, "tcpi_bytes_received",
			       data->tcpi_bytes_received);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	binn_object_set_uint32(binnobj, "tcpi_segs_in",
			       data->tcpi_segs_in);
	binn_object_set_uint32(binnobj, "tcpi_segs_out",
			       data->tcpi_segs_out);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
	binn_object_set_uint32(binnobj, "tcpi_notsent_bytes",
			       data->tcpi_notsent_bytes);
	binn_object_set_uint32(binnobj, "tcpi_min_rtt",
			       data->tcpi_min_rtt);
	binn_object_set_uint32(binnobj, "tcpi_data_segs_in",
			       data->tcpi_data_segs_in);
	binn_object_set_uint32(binnobj, "tcpi_data_segs_out",
			       data->tcpi_data_segs_out);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
	binn_object_set_uint8(binnobj, "tcpi_delivery_rate_app_limited",
			      data->tcpi_delivery_rate_app_limited);
	binn_object_set_uint64(binnobj, "tcpi_delivery_rate",
			       data->tcpi_delivery_rate);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	binn_object_set_uint64(binnobj, "tcpi_busy_time",
			       data->tcpi_busy_time);
	binn_object_set_uint64(binnobj, "tcpi_sndbuf_limited",
			       data->tcpi_sndbuf_limited);
	binn_object_set_uint64(binnobj, "tcpi_rwnd_limited",
			       data->tcpi_rwnd_limited);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
	binn_object_set_uint32(binnobj, "tcpi_delivered",
			       data->tcpi_delivered);
	binn_object_set_uint32(binnobj, "tcpi_delivered_ce",
			       data->tcpi_delivered_ce);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)
	binn_object_set_uint64(binnobj, "tcpi_bytes_sent",
			       data->tcpi_bytes_sent);
	binn_object_set_uint64(binnobj, "tcpi_bytes_retrans",
			       data->tcpi_bytes_retrans);
	binn_object_set_uint32(binnobj, "tcpi_dsack_dups",
			       data->tcpi_dsack_dups);
	binn_object_set_uint32(binnobj, "tcpi_reord_seen",
			       data->tcpi_reord_seen);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
	binn_object_set_uint32(binnobj, "tcpi_snd_wnd",
			       data->tcpi_snd_wnd);
	binn_object_set_uint32(binnobj, "tcpi_rcv_ooopack",
			       data->tcpi_rcv_ooopack);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
	binn_object_set_uint8(binnobj, "tcpi_fastopen_client_fail",
			      data->tcpi_fastopen_client_fail);
#endif
#endif /*endif for #ifdef __linux__ */
#endif /*endif for TCP_INFO */
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
	len = snprintf(*output, buflen, "%d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d",
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
		       binn_object_uint32(binnobj, "tcpi_rcv_space"),
		       binn_object_uint32(binnobj, "tcpi_total_retrans")
		);

	/* compare the received kernel version to the version that supports
	 * any given metric. This means that a remote host that has a different
	 * kernel that the local host will be able to process the data in terms of
	 * the remote kernel version. Only necessary under linux*/
#ifdef __linux__
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
#endif /* ifdef __linux__ */
}

/* Print out the header to the file so that the column header matches the
 * data in the metrics object. That varies by kernel version so we have to
 * do tests for each possible version where they added new values to tcp_info
 * NOTE: This doesn't put the values/headers in the most useful order but the
 * resulting file is probably going to get processed by something */
void
metrics_print_header(FILE *fptr, char *extra_text, int kernel_version) {
	if (extra_text != NULL) {
		fprintf(fptr, "%s\n", extra_text);
	}
	fprintf(fptr, "timestamp, state, ca_state, retransmits, probes, backoff, options, ");
	fprintf(fptr, "snd_wscale, rcv_wscale, rto, ato, snd_mss, rcv_mss, unacked, sacked, lost, retrans, ");
	fprintf(fptr, "fackets, last_data_sent, last_ack_sent, last_data_recv, ");
	fprintf(fptr, "last_ack_recv, pmtu, rcv_ssthresh, rtt, rttvar, snd_ssthresh, ");
	fprintf(fptr, "snd_cwnd, advmss, reordering, rcv_rtt, rcv_space, total_retrans");

	/* compare the received kernel version to the version that supports
	 * any given metric. This way we can print consistent headers.
	 * Only necessary under linux*/
#ifdef __linux__
	if (kernel_version >= KERNEL_VERSION(3,15,0)) {
		fprintf(fptr, ", max_pacing_rate, pacing_rate");
	}

	if (kernel_version >= KERNEL_VERSION(4,1,0)) {
		fprintf(fptr, ", bytes_acked, bytes_received");
	}

	if (kernel_version >= KERNEL_VERSION(4,2,0)) {
		fprintf(fptr, ", segs_in, segs_out");
	}

	if (kernel_version >= KERNEL_VERSION(4,6,0)) {
		fprintf(fptr, ", notsent_bytes, min_rtt, data_segs_in, data_seg_out");
	}

	if (kernel_version >= KERNEL_VERSION(4,9,0)) {
		fprintf(fptr, ", delivery_rate_app_limited, delivery_rate");
	}

	if (kernel_version >= KERNEL_VERSION(4,10,0)) {
		fprintf(fptr, ", busy_time, sndbuf_limited, rwnd_limited");
	}

	if (kernel_version >= KERNEL_VERSION(4,18,0)) {
		fprintf(fptr, ", delivered, delivered_ce");
	}

	if (kernel_version >= KERNEL_VERSION(4,19,0)) {
		fprintf(fptr, ", bytes_sent, bytes_retrans, dsack_dups, reord_seen");
	}

	if (kernel_version >= KERNEL_VERSION(5,4,0)) {
		fprintf(fptr, ", snd_wnd, rcv_ooopack");
	}

	if (kernel_version >= KERNEL_VERSION(5,5,0)) {
		fprintf(fptr, ", fastopen_client_fail");
	}
#endif /* ifdef __linux__ */
	fprintf(fptr, "\n\n");
}
