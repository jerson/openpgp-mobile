#ifndef OPENPGP_BRIDGE_H
#define OPENPGP_BRIDGE_H

typedef struct  { char *publicKey; char *privateKey; } KeyPair;
typedef struct  { char *hash; char *cipher; char *compression; char *compressionLevel; char *rsaBits; } KeyOptions;
typedef struct  { char *name; char *comment; char *email; char *passphrase; KeyOptions *keyOptions; } Options;

void errorGenerateThrow(char *message);
KeyPair *create_keyPair(char *publicKey, char *privateKey);

#endif
