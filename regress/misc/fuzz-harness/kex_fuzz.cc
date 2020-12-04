// libfuzzer driver for key exchange fuzzing.


#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {

#include "includes.h"
#include "ssherr.h"
#include "ssh_api.h"
#include "sshbuf.h"
#include "packet.h"
#include "myproposal.h"
#include "xmalloc.h"
#include "authfile.h"
#include "log.h"

// Define if you want to generate traces.
// #define STANDALONE 1

#define PRIV_RSA \
"-----BEGIN OPENSSH PRIVATE KEY-----\n"\
"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n"\
"NhAAAAAwEAAQAAAQEA3+epf+VGKoGPaAZXrf6S0cyumQnddkGBnVFX0A5eh37RtLug0qY5\n"\
"thxsBUbGGVr9mTd2QXwLujBwYg5l1MP/Fmg+5312Zgx9pHmS+qKULbar0hlNgptNEb+aNU\n"\
"d3o9qg3aXqXm7+ZnjAV05ef/mxNRN2ZvuEkw7cRppTJcbBI+vF3lXuCXnX2klDI95Gl2AW\n"\
"3WHRtanqLHZXuBkjjRBDKc7MUq/GP1hmLiAd95dvU7fZjRlIEsP84zGEI1Fb0L/kmPHcOt\n"\
"iVfHft8CtmC9v6+94JrOiPBBNScV+dyrgAGPsdKdr/1vIpQmCNiI8s3PCiD8J7ZiBaYm0I\n"\
"8fq5G/qnUwAAA7ggw2dXIMNnVwAAAAdzc2gtcnNhAAABAQDf56l/5UYqgY9oBlet/pLRzK\n"\
"6ZCd12QYGdUVfQDl6HftG0u6DSpjm2HGwFRsYZWv2ZN3ZBfAu6MHBiDmXUw/8WaD7nfXZm\n"\
"DH2keZL6opQttqvSGU2Cm00Rv5o1R3ej2qDdpepebv5meMBXTl5/+bE1E3Zm+4STDtxGml\n"\
"MlxsEj68XeVe4JedfaSUMj3kaXYBbdYdG1qeosdle4GSONEEMpzsxSr8Y/WGYuIB33l29T\n"\
"t9mNGUgSw/zjMYQjUVvQv+SY8dw62JV8d+3wK2YL2/r73gms6I8EE1JxX53KuAAY+x0p2v\n"\
"/W8ilCYI2Ijyzc8KIPwntmIFpibQjx+rkb+qdTAAAAAwEAAQAAAQEArWm5B4tFasppjUHM\n"\
"SsAuajtCxtizI1Hc10EW59cZM4vvUzE2f6+qZvdgWj3UU/L7Et23w0QVuSCnCerox379ZB\n"\
"ddEOFFAAiQjwBx65hbd4RRUymxtIQfjq18++LcMJW1nbVQ7c69ThQbtALIggmbS+ZE/8Gx\n"\
"jkwmIrCH0Ww8TlpsPe+mNHuyNk7UEZoXLm22lNLqq5qkIL5JgT6M2iNJpMOJy9/CKi6kO4\n"\
"JPuVwjdG4C5pBPaMN3KJ1IvAlSlLGNaXnfXcn85gWfsCjsZmH3liey2NJamqp/w83BrKUg\n"\
"YZvMR2qeWZaKkFTahpzN5KRK1BFeB37O0P84Dzh1biDX8QAAAIEAiWXW8ePYFwLpa2mFIh\n"\
"VvRTdcrN70rVK5eWVaL3pyS4vGA56Jixq86dHveOnbSY+iNb1jQidtXc8SWUt2wtHqZ32h\n"\
"Lji9/hMSKqe9SEP3xvDRDmUJqsVw0ySyrFrzm4160QY6RKU3CIQCVFslMZ9fxmrfZ/hxoU\n"\
"0X3FVsxmC4+kwAAACBAPOc1YERpV6PjANBrGR+1o1RCdACbm5myc42QzSNIaOZmgrYs+Gt\n"\
"7+EcoqSdbJzHJNCNQfF+A+vjbIkFiuZqq/5wwr59qXx5OAlijLB/ywwKmTWq6lp//Zxny+\n"\
"ka3sIGNO14eQvmxNDnlLL+RIZleCTEKBXSW6CZhr+uHMZFKKMtAAAAgQDrSkm+LbILB7H9\n"\
"jxEBZLhv53aAn4u81kFKQOJ7PzzpBGSoD12i7oIJu5siSD5EKDNVEr+SvCf0ISU3BuMpzl\n"\
"t3YrPrHRheOFhn5e3j0e//zB8rBC0DGB4CtTDdeh7rOXUL4K0pz+8wEpNkV62SWxhC6NRW\n"\
"I79JhtGkh+GtcnkEfwAAAAAB\n"\
"-----END OPENSSH PRIVATE KEY-----\n"
#define PUB_RSA \
"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDf56l/5UYqgY9oBlet/pLRzK6ZCd12QYGdUVfQDl6HftG0u6DSpjm2HGwFRsYZWv2ZN3ZBfAu6MHBiDmXUw/8WaD7nfXZmDH2keZL6opQttqvSGU2Cm00Rv5o1R3ej2qDdpepebv5meMBXTl5/+bE1E3Zm+4STDtxGmlMlxsEj68XeVe4JedfaSUMj3kaXYBbdYdG1qeosdle4GSONEEMpzsxSr8Y/WGYuIB33l29Tt9mNGUgSw/zjMYQjUVvQv+SY8dw62JV8d+3wK2YL2/r73gms6I8EE1JxX53KuAAY+x0p2v/W8ilCYI2Ijyzc8KIPwntmIFpibQjx+rkb+qdT"
#define PRIV_DSA \
"-----BEGIN OPENSSH PRIVATE KEY-----\n"\
"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsgAAAAdzc2gtZH\n"\
"NzAAAAgQCsGTfjpQ465EOkfQXJM9BOvfRQE0fqlykAls+ncz+T7hrbeScRu8xpwzsznJNm\n"\
"xlW8o6cUDiHmBJ5OHgamUC9N7YJeU/6fnOAZifgN8mqK6k8pKHuje8ANOiYgHLl0yiASQA\n"\
"3//qMyzZ+W/hemoLSmLAbEqlfWVeyYx+wta1Vm+QAAABUAvWyehvUvdHvQxavYgS5p0t5Q\n"\
"d7UAAACBAIRA9Yy+f4Kzqpv/qICPO3zk42UuP7WAhSW2nCbQdLlCiSTxcjKgcvXNRckwJP\n"\
"44JjSHOtJy/AMtJrPIbLYG6KuWTdBlEHFiG6DafvLG+qPMSL2bPjXTOhuOMbCHIZ+5WBkW\n"\
"THeG/Nv11iI01Of9V6tXkig23K370flkRkXFi9MdAAAAgCt6YUcQkNwG7B/e5M1FZsLP9O\n"\
"kVB3BwLAOjmWdHpyhu3HpwSJa3XLEvhXN0i6IVI2KgPo/2GtYA6rHt14L+6u1pmhh8sAvQ\n"\
"ksp3qZB+xh/NP+hBqf0sbHX0yYbzKOvI5SCc/kKK6yagcBZOsubM/KC8TxyVgmD5c6WzYs\n"\
"h5TEpvAAAB2PHjRbbx40W2AAAAB3NzaC1kc3MAAACBAKwZN+OlDjrkQ6R9Bckz0E699FAT\n"\
"R+qXKQCWz6dzP5PuGtt5JxG7zGnDOzOck2bGVbyjpxQOIeYEnk4eBqZQL03tgl5T/p+c4B\n"\
"mJ+A3yaorqTykoe6N7wA06JiAcuXTKIBJADf/+ozLNn5b+F6agtKYsBsSqV9ZV7JjH7C1r\n"\
"VWb5AAAAFQC9bJ6G9S90e9DFq9iBLmnS3lB3tQAAAIEAhED1jL5/grOqm/+ogI87fOTjZS\n"\
"4/tYCFJbacJtB0uUKJJPFyMqBy9c1FyTAk/jgmNIc60nL8Ay0ms8hstgboq5ZN0GUQcWIb\n"\
"oNp+8sb6o8xIvZs+NdM6G44xsIchn7lYGRZMd4b82/XWIjTU5/1Xq1eSKDbcrfvR+WRGRc\n"\
"WL0x0AAACAK3phRxCQ3AbsH97kzUVmws/06RUHcHAsA6OZZ0enKG7cenBIlrdcsS+Fc3SL\n"\
"ohUjYqA+j/Ya1gDqse3Xgv7q7WmaGHywC9CSynepkH7GH80/6EGp/SxsdfTJhvMo68jlIJ\n"\
"z+QorrJqBwFk6y5sz8oLxPHJWCYPlzpbNiyHlMSm8AAAAUUA+OGldMi76ClO/sstpdbBUE\n"\
"lq8AAAAAAQI=\n"\
"-----END OPENSSH PRIVATE KEY-----\n"
#define PUB_DSA \
"ssh-dss AAAAB3NzaC1kc3MAAACBAKwZN+OlDjrkQ6R9Bckz0E699FATR+qXKQCWz6dzP5PuGtt5JxG7zGnDOzOck2bGVbyjpxQOIeYEnk4eBqZQL03tgl5T/p+c4BmJ+A3yaorqTykoe6N7wA06JiAcuXTKIBJADf/+ozLNn5b+F6agtKYsBsSqV9ZV7JjH7C1rVWb5AAAAFQC9bJ6G9S90e9DFq9iBLmnS3lB3tQAAAIEAhED1jL5/grOqm/+ogI87fOTjZS4/tYCFJbacJtB0uUKJJPFyMqBy9c1FyTAk/jgmNIc60nL8Ay0ms8hstgboq5ZN0GUQcWIboNp+8sb6o8xIvZs+NdM6G44xsIchn7lYGRZMd4b82/XWIjTU5/1Xq1eSKDbcrfvR+WRGRcWL0x0AAACAK3phRxCQ3AbsH97kzUVmws/06RUHcHAsA6OZZ0enKG7cenBIlrdcsS+Fc3SLohUjYqA+j/Ya1gDqse3Xgv7q7WmaGHywC9CSynepkH7GH80/6EGp/SxsdfTJhvMo68jlIJz+QorrJqBwFk6y5sz8oLxPHJWCYPlzpbNiyHlMSm8="
#define PRIV_ECDSA \
"-----BEGIN OPENSSH PRIVATE KEY-----\n"\
"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n"\
"1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTDJ0VlMv+0rguNzaJ1DF2KueHaxRSQ\n"\
"6LpIxGbulrg1a8RPbnMXwag5GcDiDllD2lDUJUuBEWyjXA0rZoZX35ELAAAAoE/Bbr5PwW\n"\
"6+AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMMnRWUy/7SuC43N\n"\
"onUMXYq54drFFJDoukjEZu6WuDVrxE9ucxfBqDkZwOIOWUPaUNQlS4ERbKNcDStmhlffkQ\n"\
"sAAAAhAIhE6hCID5oOm1TDktc++KFKyScjLifcZ6Cgv5xSSyLOAAAAAAECAwQFBgc=\n"\
"-----END OPENSSH PRIVATE KEY-----\n"
#define PUB_ECDSA \
"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMMnRWUy/7SuC43NonUMXYq54drFFJDoukjEZu6WuDVrxE9ucxfBqDkZwOIOWUPaUNQlS4ERbKNcDStmhlffkQs="
#define PRIV_ED25519 \
"-----BEGIN OPENSSH PRIVATE KEY-----\n"\
"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"\
"QyNTUxOQAAACAz0F5hFTFS5nhUcmnyjFVoDw5L/P7kQU8JnBA2rWczAwAAAIhWlP99VpT/\n"\
"fQAAAAtzc2gtZWQyNTUxOQAAACAz0F5hFTFS5nhUcmnyjFVoDw5L/P7kQU8JnBA2rWczAw\n"\
"AAAEDE1rlcMC0s0X3TKVZAOVavZOywwkXw8tO5dLObxaCMEDPQXmEVMVLmeFRyafKMVWgP\n"\
"Dkv8/uRBTwmcEDatZzMDAAAAAAECAwQF\n"\
"-----END OPENSSH PRIVATE KEY-----\n"
#define PUB_ED25519 \
"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDPQXmEVMVLmeFRyafKMVWgPDkv8/uRBTwmcEDatZzMD"

static int prepare_key(struct shared_state *st, int keytype, int bits);

struct shared_state {
	size_t nkeys;
	struct sshkey **privkeys, **pubkeys;
};

struct test_state {
	struct sshbuf *smsgs, *cmsgs; /* output, for standalone mode */
	struct sshbuf *sin, *cin; /* input; setup per-test in do_kex_with_key */
	struct sshbuf *s_template, *c_template; /* main copy of input */
};

static int
do_send_and_receive(struct ssh *from, struct ssh *to,
    struct sshbuf *store, int clobber, size_t *n)
{
	u_char type;
	size_t len;
	const u_char *buf;
	int r;

	for (*n = 0;; (*n)++) {
		if ((r = ssh_packet_next(from, &type)) != 0) {
			debug_fr(r, "ssh_packet_next");
			return r;
		}
		if (type != 0)
			return 0;
		buf = ssh_output_ptr(from, &len);
		debug_f("%zu%s", len, clobber ? " ignore" : "");
		if (len == 0)
			return 0;
		if ((r = ssh_output_consume(from, len)) != 0) {
			debug_fr(r, "ssh_output_consume");
			return r;
		}
		if (store != NULL && (r = sshbuf_put(store, buf, len)) != 0) {
			debug_fr(r, "sshbuf_put");
			return r;
		}
		if (!clobber && (r = ssh_input_append(to, buf, len)) != 0) {
			debug_fr(r, "ssh_input_append");
			return r;
		}
	}
}

static int
run_kex(struct test_state *ts, struct ssh *client, struct ssh *server)
{
	int r = 0;
	size_t cn, sn;

	/* If fuzzing, replace server/client input */
	if (ts->sin != NULL) {
		if ((r = ssh_input_append(server, sshbuf_ptr(ts->sin),
		    sshbuf_len(ts->sin))) != 0) {
			error_fr(r, "ssh_input_append");
			return r;
		}
		sshbuf_reset(ts->sin);
	}
	if (ts->cin != NULL) {
		if ((r = ssh_input_append(client, sshbuf_ptr(ts->cin),
		    sshbuf_len(ts->cin))) != 0) {
			error_fr(r, "ssh_input_append");
			return r;
		}
		sshbuf_reset(ts->cin);
	}
	while (!server->kex->done || !client->kex->done) {
		cn = sn = 0;
		debug_f("S:");
		if ((r = do_send_and_receive(server, client,
		    ts->smsgs, ts->cin != NULL, &sn)) != 0) {
			debug_fr(r, "S->C");
			break;
		}
		debug_f("C:");
		if ((r = do_send_and_receive(client, server,
		    ts->cmsgs, ts->sin != NULL, &cn)) != 0) {
			debug_fr(r, "C->S");
			break;
		}
		if (cn == 0 && sn == 0) {
			debug_f("kex stalled");
			r = SSH_ERR_PROTOCOL_ERROR;
			break;
		}
	}
	debug_fr(r, "done");
	return r;
}

static void
store_key(struct shared_state *st, struct sshkey *pubkey,
    struct sshkey *privkey)
{
	if (st == NULL || pubkey->type < 0 || pubkey->type > INT_MAX ||
	    privkey->type != pubkey->type ||
	    ((size_t)pubkey->type < st->nkeys &&
	     st->pubkeys[pubkey->type] != NULL))
		abort();
	if ((size_t)pubkey->type >= st->nkeys) {
		st->pubkeys = (struct sshkey **)xrecallocarray(st->pubkeys,
		    st->nkeys, pubkey->type + 1, sizeof(*st->pubkeys));
		st->privkeys = (struct sshkey **)xrecallocarray(st->privkeys,
		    st->nkeys, privkey->type + 1, sizeof(*st->privkeys));
		st->nkeys = privkey->type + 1;
	}
	debug_f("store %s at %d", sshkey_ssh_name(pubkey), pubkey->type);
	st->pubkeys[pubkey->type] = pubkey;
	st->privkeys[privkey->type] = privkey;
}

static int
prepare_keys(struct shared_state *st)
{
	if (prepare_key(st, KEY_RSA, 2048) != 0 ||
	    prepare_key(st, KEY_DSA, 1024) != 0 ||
	    prepare_key(st, KEY_ECDSA, 256) != 0 ||
	    prepare_key(st, KEY_ED25519, 256) != 0) {
		error_f("key prepare failed");
		return -1;
	}
	return 0;
}

static struct sshkey *
get_pubkey(struct shared_state *st, int keytype)
{
	if (st == NULL || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->pubkeys == NULL || st->pubkeys[keytype] == NULL)
		abort();
	return st->pubkeys[keytype];
}

static struct sshkey *
get_privkey(struct shared_state *st, int keytype)
{
	if (st == NULL || keytype < 0 || (size_t)keytype >= st->nkeys ||
	    st->privkeys == NULL || st->privkeys[keytype] == NULL)
		abort();
	return st->privkeys[keytype];
}

static int
do_kex_with_key(struct shared_state *st, struct test_state *ts,
    const char *kex, int keytype)
{
	struct ssh *client = NULL, *server = NULL;
	struct sshkey *privkey = NULL, *pubkey = NULL;
	struct sshbuf *state = NULL;
	struct kex_params kex_params;
	const char *ccp, *proposal[PROPOSAL_MAX] = { KEX_CLIENT };
	char *myproposal[PROPOSAL_MAX] = {0}, *keyname = NULL;
	int i, r;

	ts->cin = ts->sin = NULL;
	if (ts->c_template != NULL &&
	    (ts->cin = sshbuf_fromb(ts->c_template)) == NULL)
		abort();
	if (ts->s_template != NULL &&
	    (ts->sin = sshbuf_fromb(ts->s_template)) == NULL)
		abort();

	pubkey = get_pubkey(st, keytype);
	privkey = get_privkey(st, keytype);
	keyname = xstrdup(sshkey_ssh_name(privkey));
	debug_f("%s %s clobber %s %zu", kex, keyname,
	    ts->cin == NULL ? "server" : "client",
	    ts->cin == NULL ? sshbuf_len(ts->sin) : sshbuf_len(ts->cin));
	for (i = 0; i < PROPOSAL_MAX; i++) {
		ccp = proposal[i];
		if (i == PROPOSAL_SERVER_HOST_KEY_ALGS)
			ccp = keyname;
		else if (i == PROPOSAL_KEX_ALGS && kex != NULL)
			ccp = kex;
		if ((myproposal[i] = strdup(ccp)) == NULL) {
			error_f("strdup prop %d", i);
			goto fail;
		}
	}
	memcpy(kex_params.proposal, myproposal, sizeof(myproposal));
	if ((r = ssh_init(&client, 0, &kex_params)) != 0) {
		error_fr(r, "init client");
		goto fail;
	}
	if ((r = ssh_init(&server, 1, &kex_params)) != 0) {
		error_fr(r, "init server");
		goto fail;
	}
	if ((r = ssh_add_hostkey(server, privkey)) != 0 ||
	    (r = ssh_add_hostkey(client, pubkey)) != 0) {
		error_fr(r, "add hostkeys");
		goto fail;
	}
	if ((r = run_kex(ts, client, server)) != 0) {
		error_fr(r, "kex");
		goto fail;
	}
	/* XXX rekex, set_state, etc */
 fail:
	for (i = 0; i < PROPOSAL_MAX; i++)
		free(myproposal[i]);
	sshbuf_free(ts->sin);
	sshbuf_free(ts->cin);
	sshbuf_free(state);
	ssh_free(client);
	ssh_free(server);
	free(keyname);
	return r;
}

static int
prepare_key(struct shared_state *st, int kt, int bits)
{
	const char *pubstr = NULL;
	const char *privstr = NULL;
	char *tmp, *cp;
	struct sshkey *privkey = NULL, *pubkey = NULL;
	struct sshbuf *b = NULL;
	int r;

	switch (kt) {
	case KEY_RSA:
		pubstr = PUB_RSA;
		privstr = PRIV_RSA;
		break;
	case KEY_DSA:
		pubstr = PUB_DSA;
		privstr = PRIV_DSA;
		break;
	case KEY_ECDSA:
		pubstr = PUB_ECDSA;
		privstr = PRIV_ECDSA;
		break;
	case KEY_ED25519:
		pubstr = PUB_ED25519;
		privstr = PRIV_ED25519;
		break;
	default:
		abort();
	}
	if ((b = sshbuf_from(privstr, strlen(privstr))) == NULL)
		abort();
	if ((r = sshkey_parse_private_fileblob(b, "", &privkey, NULL)) != 0) {
		error_fr(r, "priv %d", kt);
		abort();
	}
	sshbuf_free(b);
	tmp = cp = xstrdup(pubstr);
	if ((pubkey = sshkey_new(KEY_UNSPEC)) == NULL)
		abort();
	if ((r = sshkey_read(pubkey, &cp)) != 0) {
		error_fr(r, "pub %d", kt);
		abort();
	}
	free(tmp);

	store_key(st, pubkey, privkey);
	return 0;
}

#if defined(STANDALONE)

#if 0 /* use this if generating new keys to embed above */
static int
prepare_key(struct shared_state *st, int keytype, int bits)
{
	struct sshkey *privkey = NULL, *pubkey = NULL;
	int r;

	if ((r = sshkey_generate(keytype, bits, &privkey)) != 0) {
		error_fr(r, "generate");
		abort();
	}
	if ((r = sshkey_from_private(privkey, &pubkey)) != 0) {
		error_fr(r, "make pubkey");
		abort();
	}
	store_key(st, pubkey, privkey);
	return 0;
}
#endif

int main(void)
{
	static struct shared_state *st;
	struct test_state *ts;
	const int keytypes[] = { KEY_RSA, KEY_DSA, KEY_ECDSA, KEY_ED25519, -1 };
	const char *kextypes[] = {
		"sntrup4591761x25519-sha512@tinyssh.org",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"diffie-hellman-group1-sha1",
		NULL,
	};
	int i, j;
	char *path;
	FILE *f;

	if (st == NULL) {
		st = (struct shared_state *)xcalloc(1, sizeof(*st));
		prepare_keys(st);
	}
	/* Run each kex method for each key and save client/server packets */
	for (i = 0; keytypes[i] != -1; i++) {
		for (j = 0; kextypes[j] != NULL; j++) {
			ts = (struct test_state *)xcalloc(1, sizeof(*ts));
			ts->smsgs = sshbuf_new();
			ts->cmsgs = sshbuf_new();
			do_kex_with_key(st, ts, kextypes[j], keytypes[i]);
			xasprintf(&path, "S2C-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			if ((f = fopen(path, "wb+")) == NULL)
				abort();
			if (fwrite(sshbuf_ptr(ts->smsgs), 1,
			    sshbuf_len(ts->smsgs), f) != sshbuf_len(ts->smsgs))
				abort();
			fclose(f);
			free(path);
			//sshbuf_dump(ts->smsgs, stderr);
			xasprintf(&path, "C2S-%s-%s",
			    kextypes[j], sshkey_type(st->pubkeys[keytypes[i]]));
			debug_f("%s", path);
			if ((f = fopen(path, "wb+")) == NULL)
				abort();
			if (fwrite(sshbuf_ptr(ts->cmsgs), 1,
			    sshbuf_len(ts->cmsgs), f) != sshbuf_len(ts->cmsgs))
				abort();
			fclose(f);
			free(path);
			//sshbuf_dump(ts->cmsgs, stderr);
			sshbuf_free(ts->smsgs);
			sshbuf_free(ts->cmsgs);
			free(ts);
		}
	}
	for (i = 0; keytypes[i] != -1; i++) {
		xasprintf(&path, "%s.priv",
		    sshkey_type(st->privkeys[keytypes[i]]));
		debug_f("%s", path);
		if (sshkey_save_private(st->privkeys[keytypes[i]], path,
		    "", "", SSHKEY_PRIVATE_OPENSSH, NULL, 0) != 0)
			abort();
		free(path);
		xasprintf(&path, "%s.pub",
		    sshkey_type(st->pubkeys[keytypes[i]]));
		debug_f("%s", path);
		if (sshkey_save_public(st->pubkeys[keytypes[i]], path, "") != 0)
			abort();
		free(path);
	}
}
#else /* !STANDALONE */
static void
do_kex(struct shared_state *st, struct test_state *ts, const char *kex)
{
	do_kex_with_key(st, ts, kex, KEY_RSA);
	do_kex_with_key(st, ts, kex, KEY_DSA);
	do_kex_with_key(st, ts, kex, KEY_ECDSA);
	do_kex_with_key(st, ts, kex, KEY_ED25519);
}

static void
kex_tests(struct shared_state *st, struct test_state *ts)
{
	do_kex(st, ts, "sntrup4591761x25519-sha512@tinyssh.org");
	do_kex(st, ts, "curve25519-sha256@libssh.org");
	do_kex(st, ts, "ecdh-sha2-nistp256");
	do_kex(st, ts, "diffie-hellman-group1-sha1");
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	static struct shared_state *st;
	struct test_state *ts;
	u_char crbuf[SSH_MAX_PRE_BANNER_LINES * 4];
	u_char zbuf[4096] = {0};
	static LogLevel loglevel = SYSLOG_LEVEL_INFO;

	if (st == NULL) {
		if (getenv("DEBUG") != NULL || getenv("KEX_FUZZ_DEBUG") != NULL)
			loglevel = SYSLOG_LEVEL_DEBUG3;
		log_init("kex_fuzz",
		    loglevel, SYSLOG_FACILITY_AUTH, 1);
		st = (struct shared_state *)xcalloc(1, sizeof(*st));
		prepare_keys(st);
	}

	/* Ensure that we can complete (fail) banner exchange at least */
	memset(crbuf, '\n', sizeof(crbuf));

	ts = (struct test_state *)xcalloc(1, sizeof(*ts));
	if ((ts->s_template = sshbuf_new()) == NULL ||
	    sshbuf_put(ts->s_template, data, size) != 0 ||
	    sshbuf_put(ts->s_template, crbuf, sizeof(crbuf)) != 0 ||
	    sshbuf_put(ts->s_template, zbuf, sizeof(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->s_template);
	free(ts);

	ts = (struct test_state *)xcalloc(1, sizeof(*ts));
	if ((ts->c_template = sshbuf_new()) == NULL ||
	    sshbuf_put(ts->c_template, data, size) != 0 ||
	    sshbuf_put(ts->c_template, crbuf, sizeof(crbuf)) != 0 ||
	    sshbuf_put(ts->c_template, zbuf, sizeof(zbuf)) != 0)
		abort();
	kex_tests(st, ts);
	sshbuf_free(ts->c_template);
	free(ts);

	return 0;
}
#endif /* STANDALONE */
} /* extern "C" */
