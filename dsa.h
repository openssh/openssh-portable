#ifndef DSA_H
#define DSA_H

Key	*dsa_serverkey_from_blob(char *serverhostkey, int serverhostkeylen);
Key	*dsa_get_serverkey(char *filename);
int	dsa_make_serverkey_blob(Key *key, unsigned char **blobp, unsigned int *lenp);

int
dsa_sign(
    Key *key,
    unsigned char **sigp, int *lenp,
    unsigned char *hash, int hlen);

int
dsa_verify(
    Key *key,
    unsigned char *signature, int signaturelen,
    unsigned char *hash, int hlen);

#endif
