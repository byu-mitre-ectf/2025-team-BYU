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
from Crypto.Random import get_random_bytes

# Key size in Bytes
KEY_SIZE = 32

def gen_secrets(channels: list[int]):
    """Generate the contents of the global.secrets file

    The generated secrets will be used by the Encoder, `ectf25_design.gen_subscription`, 
    and the decoder's build process. To be used by the build process and decoder, a 
    custom python file will run at build that generates a .h file with necessary data
    for the decoder to function.

    Parameters
        channels (list[int]): List of channel numbers.
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

    # Format and return secrets to be written in json form
    secrets = {
        "channel_keys": chacha_keys,
        "subscription_key": subscription_key.hex(),
    }

    json_content = json.dumps(secrets).encode()
    return json_content

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

    # Call generate secrets to create the secrets data
    secrets = gen_secrets(args.channels)

    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

if __name__ == "__main__":
    main()
