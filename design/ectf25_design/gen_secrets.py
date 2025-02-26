"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse, json
from pathlib import Path
from loguru import logger
from Crypto.Random import get_random_bytes

# Key size in Bytes
KEY_SIZE = 32
    
def write_file(filepath: Path, content, args, mode: str, backup_mode: str):

    """Write content to a file, handling optional overwriting.

        Parameters:
            filepath (Path): The path to the file to be written.
            content (str or bytes): The data to write to the file.
            args (Namespace): Parsed command-line arguments, including `force` flag.
            mode (str): File open mode when overwriting is allowed.
            backup_mode (str): File open mode when `--force` is not provided (prevents overwriting).

        Raises:
            Logs an error message if writing to the file fails.
    """

    try:
        with open(filepath, mode if args.force else backup_mode) as file:
            file.write(content)
    except Exception as e:
            pass

def gen_secrets(channels: list[int], args):

    """Generate the contents of the .json secrets file and the .h secrets file.

    The generated secrets will be used by the Encoder, `ectf25_design.gen_subscription`, 
    and the decoder's build process.

    Parameters:
        channels (list[int]): List of channel numbers.
        args (Namespace): Parsed command-line arguments.
    """


    # Ensure channel list includes channel 0 (default) and remove duplicates 
    channels.append(0)
    channels = list(set(channels))

    # Generate ChaCha20 keys for each channel
    chacha_keys = dict()
    for channel in channels:
        if 0 <= channel <= 0xffffffff:  # Validate channel range from 1 to 4,294,967,295
            chacha_keys[str(channel)] = get_random_bytes(KEY_SIZE).hex()

    # Generate a global subscription key
    subscription_key = get_random_bytes(KEY_SIZE)

    # Convert keys to array format for the .h file
    subscription_key_array = str(list(subscription_key))[1:-1]
    chacha_zero_array = str(list(bytes.fromhex(chacha_keys["0"])))[1:-1]

    # Generate the secrets.h file content
    header_file_content = """#ifndef SECRETS_H
#define SECRETS_H

#include "adv_crypto.h"

uint8_t subscription_decrypt_key[CHACHAPOLY_KEY_SIZE] = """ + "{" + subscription_key_array + "}" + """;

uint8_t channel_0_key[CHACHAPOLY_KEY_SIZE] = """ + "{" + chacha_zero_array + "}" + """;

#endif // SECRETS_H
"""

    # Create the secrets directory if it doesn't exist
    secrets_directory = Path("global.secrets")
    secrets_directory.mkdir(parents=True, exist_ok=True)

    # Write the secrets.h file
    header_file_path = f"{secrets_directory}/secrets.h"
    write_file(header_file_path, header_file_content, args, "w", "x")

    # Convert secrets to JSON format
    secrets = {
        "channel_keys": chacha_keys,
        "subscription_key": subscription_key.hex(),
    }

    # Write the secrets.json file
    json_content = json.dumps(secrets).encode()
    python_secrets_file = f"{secrets_directory}/secrets.json"
    write_file(python_secrets_file, json_content, args, "wb", "xb")

def parse_args():

    """Define and parse the command line arguments

        NOTE: Your design must not change this function

        This function sets up and parses the required command-line arguments for
        generating secrets.

        Returns:
            argparse.Namespace: Parsed command-line arguments.
    """

    # Create an argument parser instance
    parser = argparse.ArgumentParser()

    # Optional flag to force overwrite of an existing secrets file
    parser.add_argument(
        "--force", 
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )

    # Required argument: Path to the secrets file
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )

    # Required argument: List of channels
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
        " be provided in this list",
    )

    # Parse and return the command-line arguments
    return parser.parse_args()

def main():
    """Main function of gen_secrets

        This function handles the overall logic of the program by parsing
        command line arguments and generating the secrets based on those arguments.
    """

    # Parse the command-line arguments
    args = parse_args()

    # Call the gen_secrets function to generate the necessary .json and .h files
    gen_secrets(args.channels, args)

if __name__ == "__main__":
    main()
