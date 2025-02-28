import json

# sam said global.secrets is a file
with open('/global.secrets', 'r') as f:
    secrets_json = f.read()

secrets_dict = json.loads(secrets_json)

subscription_key_array = str(list(bytes.fromhex(secrets_dict['subscription_key'])))[1:-1]
chacha_zero_array = str(list(bytes.fromhex(secrets_dict["channel_keys"]["0"])))[1:-1]

header_file_content = f"""#ifndef SECRETS_H
#define SECRETS_H

#include "adv_crypto.h"

uint8_t subscription_decrypt_key[CHACHAPOLY_KEY_SIZE] = """ + "{" + subscription_key_array + "}" + """;

uint8_t channel_0_key[CHACHAPOLY_KEY_SIZE] = """ + "{" + chacha_zero_array + "}" + """;

#endif // SECRETS_H
"""

with open('/decoder/inc/secrets.h', 'w') as f:
    f.write(header_file_content)

