#include "openpgp_bridge.h"
#include <iostream>
#include <stdint.h>
#include <cstdlib>

void errorGenerateThrow(char * message)
{
  throw *message;
}
KeyPair *create_keyPair(char *publicKey, char *privateKey)
{
    KeyPair *output = (KeyPair *)malloc(sizeof(KeyPair));
    output->publicKey = publicKey;
    output->privateKey = privateKey;
    return output;
}