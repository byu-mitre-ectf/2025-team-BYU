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
    
    :returns: A tuple containing (private_key, public_key) as bytes, or None if there's an error
    """
    try:
        key = RSA.generate(RSA_KEY_SIZE)
        private_key = key.export_key()
        public_key = key.public_key().export_key()
        return private_key, public_key
    except Exception as e:
        logger.error(f"Error generating RSA key pair: {e}")
        return None

def gen_secrets(channels: list[int], args) -> bytes:
    """Generate the contents of the .json secrets file and the .h secrets file

    This will be passed to the Encoder, ectf25_design.gen_subscription, and the build
    process of the decoder

    :param channels: List of channel numbers that will be valid in this deployment.
        Channel 0 is the emergency broadcast, which will always be valid and will
        NOT be included in this list

    :returns: Contents of the .json secrets file
    """
    chacha_keys = []
    try:
        chacha_keys = [get_random_bytes(KEY_SIZE) for _ in range(9)]
    except Exception as e:
        logger.error(f"Error generating chacha keys: {e}")

    nonces_directory = Path("nonces")
    nonces_directory.mkdir(parents=True, exist_ok=True)

    for i in range(9):
        nonce_filename = nonces_directory / f"nonce_{i}.txt"         
        try:
            with open(nonce_filename, "w" if args.force else "xb") as nonce_file:
                nonce_file.write("0")
        except Exception as e:
            logger.error(f"Error writing to {nonce_filename}: {e}")

    try:
        poly1305_key = get_random_bytes(KEY_SIZE)
    except Exception as e:
        logger.error(f"Error generating poly1305 key: {e}")

    private_key, public_key = generate_rsa_key_pair()
    print(str(list(private_key)))

    rsa_keys_directory = Path("rsa_keys")
    rsa_keys_directory.mkdir(parents=True, exist_ok=True)

    private_key_filename = rsa_keys_directory / f"private_key.pem"
    public_key_filename = rsa_keys_directory / f"public_key.pem"

    try:
        with open(private_key_filename, "wb" if args.force else "xb") as private_file:
            private_file.write(private_key)
    except Exception as e:
            logger.error(f"Error saving private key to {private_key_filename} : {e}")

    try:
        with open(public_key_filename, "wb" if args.force else "xb") as public_file:
            public_file.write(public_key)
    except Exception as e:
            logger.error(f"Error saving public key to {public_key_filename}: {e}")

    rsa_private_hex = private_key.hex()
    rsa_public_hex = public_key.hex()

    rsa_private_array = str(list(private_key))[1:-1]
    poly_key_array = str(list(poly1305_key))[1:-1]
    chacha_zero_array = str(list(chacha_keys[0]))[1:-1]

    header_file_content = """#define SECRETS_H
#ifndef SECRETS_H

#include "adv_crypto.h"

uint8_t subscription_decrypt_key[RSA_KEY_SIZE] = """ + "{{" + rsa_private_array + "}}" + """;

uint8_t subscription_verify_key[POLY_KEY_SIZE] = """ + "{{" + poly_key_array + "}}" + """;

uint8_t channel_0_key[CHACHAPOLY_KEY_SIZE] = """ + "{{" + chacha_zero_array + "}}" + """;

#endif // SECRETS_H
"""

    header_file_path = "secrets.h"
    try:
        with open(header_file_path, "w" if args.force else "xb") as header_file:
            header_file.write(header_file_content)
    except Exception as e:
        logger.error(f"Error creating C header file. : {e}")

    poly_hex = poly1305_key.hex()
    chacha_hex = [key.hex() for key in chacha_keys]

    secrets = {
        "chacha_keys": chacha_hex,
        "poly1305_key": poly_hex,
        "rsa_private_key": rsa_private_hex,
        "rsa_public_key": rsa_public_hex,
    }

    # NOTE: if you choose to use JSON for your file type, you will not be able to
    # store binary data, and must either use a different file type or encode the
    # binary data to hex, base64, or another type of ASCII-only encoding
    return json.dumps(secrets).encode()

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

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.channels, args)

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this, but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated secrets: {secrets}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote encoder secrets to {str(args.secrets_file.absolute())}")

if __name__ == "__main__":
    main()
