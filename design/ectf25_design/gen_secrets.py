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
from Crypto.Random import get_random_bytes

KEY_SIZE = 32
    
def write_file(filepath: Path, content, mode: str):
    """Write content to a file.

    :param filepath: Path to the file
    :param content: Data to write
    :param mode: File open mode
    """
    try:
        with open(filepath, mode) as file:
            file.write(content)
    except Exception as e:
            logger.error(f"Error creating and writing to {filepath} : {e}")


def gen_secrets(channels: list[int]):
    """Generate the contents of the .json secrets file and the .h secrets file

    This will be passed to the Encoder, ectf25_design.gen_subscription, and the build
    process of the decoder

    :param channels: List of channel numbers
    """

    # Generate chacha keys for each channel 
    chacha_keys = dict()
    channels.append(0)
    channels = list(set(channels))
    for channel in channels:
        # is this the correct way to error handle here? What should be done if it's outside of the range?
        if 0 <= channel <= 0xffffffff:
            chacha_keys[str(channel)] = get_random_bytes(KEY_SIZE).hex()

    # Generate subscription key
    subscription_key = get_random_bytes(KEY_SIZE)

    subscription_hex = subscription_key.hex()

    # Format secrets and write them to .json file
    secrets = {
        "channel_keys": chacha_keys,
        "subscription_key": subscription_hex,
    }

    json_content = json.dumps(secrets).encode()
    return json_content

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
    secrets = gen_secrets(args.channels)

    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)


if __name__ == "__main__":
    main()
