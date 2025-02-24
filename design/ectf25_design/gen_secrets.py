"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse
import json
from pathlib import Path
from loguru import logger
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

KEY_SIZE = 32
RSA_KEY_SIZE = 2048

def generate_rsa_key_pair():
    """Generate an RSA key pair.
    
    :returns: The RSA key pair, or None if there's an error
    """
    try:
        key = RSA.generate(RSA_KEY_SIZE)
        private_key = key
        public_key = key.public_key().export_key()
        return private_key, public_key
    except Exception as e:
        logger.error(f"Error generating RSA key pair: {e}")
        return None
    
def write_file(filepath: Path, content, args, mode: str, backup_mode: str):
    """Write content to a file.

    :param filepath: Path to the file
    :param content: Data to write
    :param args: Arguments inputed when the code is run
    :param mode: File open mode
    :param backup_mode File open mode when args.force is false
    """
    try:
        with open(filepath, mode if args.force else backup_mode) as file:
            file.write(content)
    except Exception as e:
            logger.error(f"Error creating and writing to {filepath} : {e}")


def gen_secrets(channels: list[int], args):
    """Generate the contents of the .json secrets file and the .h secrets file

    This will be passed to the Encoder, ectf25_design.gen_subscription, and the build
    process of the decoder

    :param channels: List of channel numbers
    :param args: The arguments inputed when the code is run
    """

    # Generate chacha keys for each channel 
    chacha_keys = []
    try:
        chacha_keys = [get_random_bytes(KEY_SIZE) for _ in range(9)]
    except Exception as e:
        logger.error(f"Error generating chacha keys: {e}")

    # Generate hmac key
    try:
        hmac_key = get_random_bytes(KEY_SIZE)
    except Exception as e:
        logger.error(f"Error generating hmac key: {e}")

    # Generate RSA key pair and save them to files
    private_key, public_key = generate_rsa_key_pair()

    rsa_keys_directory = Path("rsa_keys")
    rsa_keys_directory.mkdir(parents=True, exist_ok=True)

    # private_key_filename = rsa_keys_directory / f"private_key.pem"
    # public_key_filename = rsa_keys_directory / f"public_key.pem"

    # write_file(private_key_filename, private_key.export_key(), args, "wb", "xb")
    # write_file(public_key_filename, public_key, args, "wb", "xb")

    rsa_private_hex = private_key.export_key(format="DER").hex()
    rsa_public_hex = public_key.hex()

    # Format secrets for C and write them to .h file
    rsa_private_array = str(list(private_key.export_key(format="DER")))[1:-1]
    hmac_key_array = str(list(hmac_key))[1:-1]
    chacha_zero_array = str(list(chacha_keys[0]))[1:-1]

    # print(f"Poly Key: {poly_key_array}")
    # print(f"Chacha Key: {chacha_zero_array}")
    # print(f"RSA Key: {rsa_private_array}")
    header_file_content = f"""#ifndef SECRETS_H
#define SECRETS_H

#include "adv_crypto.h"

uint8_t subscription_decrypt_key[{len(bytes.fromhex(rsa_private_hex))}] = """ + "{" + rsa_private_array + "}" + """;

uint8_t subscription_verify_key[MAC_KEY_SIZE] = """ + "{" + hmac_key_array + "}" + """;

uint8_t channel_0_key[CHACHAPOLY_KEY_SIZE] = """ + "{" + chacha_zero_array + "}" + """;

#endif // SECRETS_H
"""

    # Create global.secrets directory for .h file and .json file
    secrets_directory = Path("global.secrets")
    secrets_directory.mkdir(parents=True, exist_ok=True)

    header_file_path = "global.secrets/secrets.h"
    write_file(header_file_path, header_file_content, args, "w", "x")

    hmac_hex = hmac_key.hex()
    chacha_hex = {str(i): chacha_keys[i].hex() for i in range(len(chacha_keys))}
    print(chacha_hex)

    # Format secrets and write them to .json file
    secrets = {
        "channel_keys": chacha_hex,
        "hmac_key": hmac_hex,
        # "rsa_private_key": rsa_private_hex,
        "rsa_public_key": rsa_public_hex,
    }

    python_secrets_file = "global.secrets/secrets.json"
    json_content = json.dumps(secrets).encode()
    write_file(python_secrets_file, json_content, args, "wb", "xb")

def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force", 
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
        " be provided in this list",
    )
    return parser.parse_args()

def main():
    """Main function of gen_secrets

    """
    # Parse the command line arguments.
    args = parse_args()

    # Call generate secrets to create the .json and .h files.
    gen_secrets(args.channels, args)

if __name__ == "__main__":
    main()
