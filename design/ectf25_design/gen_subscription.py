import argparse, json, struct
from pathlib import Path
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

def gen_subscription( secrets: bytes, device_id: int, start: int, end: int, channel: int) -> bytes:

    """Generate a subscription file for a Decoder.

        This function creates a secure subscription message, which will be passed to the Decoder using `ectf25.tv.subscribe`.
 
        Parameters:
            secrets (bytes): Contents of the secrets file generated by `ectf25_design.gen_secrets`.
            device_id (int): The unique ID of the Decoder.
            start (int): The starting timestamp for the subscription validity.
            end (int): The ending timestamp for the subscription validity.
            channel (int): The channel to be enabled for the subscription.

        Returns:
            bytes: The encrypted subscription payload to be sent to the decoder.
    """

    # Parse the JSON-formatted secrets file
    secrets = json.loads(secrets)
    
    # Pack essential subscription details (Device ID, start & end timestamps, and channel number) into binary format
    packed_numbers = struct.pack("<IQQI", device_id, start, end, channel)
    
    # Retrieve the global subscription key from secrets (used for encryption)
    try:
        channel_key = secrets["channel_keys"][str(channel)]
    except:
        # what kind of error should this throw and how should it be handled?
        # accessing an invalid channel key will give you an array access error of some kind I think
        print("Couldn't find channel with that number!")
        return -1

    # Combine the packed subscription details with the channel key (converted from hex to bytes)
    source_message = packed_numbers + bytes.fromhex(channel_key)
    
    # Retrieve the global subscription key from secrets (used for encryption)
    sub_key = bytes.fromhex(secrets["subscription_key"])

    # Generate a random Additional Authenticated Data (AAD) and nonce
    aad = get_random_bytes(4)
    nonce = get_random_bytes(12)

    # Initialize ChaCha20-Poly1305 cipher with the subscription key and nonce
    cipher = ChaCha20_Poly1305.new(key=sub_key, nonce=nonce)
    cipher.update(aad + nonce)
    
    # Encrypt the subscription data and generate an authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(source_message)
    
    # Construct the final subscription message: AAD + nonce + authentication tag + ciphertext
    final_subscription = aad + nonce + tag + ciphertext
 
    # Return the securely encrypted subscription payload, ready to be sent to the decoder
    return final_subscription
 
def parse_args():

    """Define and parse the command-line arguments.

    NOTE: Your design must not change this function.

    This function sets up and parses the required command-line arguments for
    generating a subscription file.

    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """

    # Create an argument parser instance
    parser = argparse.ArgumentParser()

    # Optional flag to force overwrite of an existing subscription file
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of subscription file, overwriting existing file",
    )

    # Required argument: Path to the secrets file (must be opened in binary mode)
    parser.add_argument(
        "secrets_file",
        type=argparse.FileType("rb"),
        help="Path to the secrets file created by ectf25_design.gen_secrets",
    )

    # Required argument: Output path for the generated subscription file
    parser.add_argument(
        "subscription_file", 
        type=Path, 
        help="Subscription output"
    )

    # Required argument: Device ID (parsed as an integer, allowing different base representations)
    parser.add_argument(
        "device_id", 
        type=lambda x: int(x, 0), 
        help="Device ID of the update recipient."
    )

    # Required argument: Subscription start timestamp (parsed as an integer)
    parser.add_argument(
        "start", 
        type=lambda x: int(x, 0), 
        help="Subscription start timestamp"
    )

    # Required argument: Subscription end timestamp (parsed as an integer)
    parser.add_argument(
        "end", 
        type=int, 
        help="Subscription end timestamp"
    )

    # Required argument: Channel to subscribe to (parsed as an integer)
    parser.add_argument(
        "channel", 
        type=int, 
        help="Channel to subscribe to"
    )

    # Parse and return the command-line arguments
    return parser.parse_args()
 
def main():
    """Main function for generating a subscription.

        This function:
        1. Parses command-line arguments.
        2. Generates a subscription payload.
        3. Writes the subscription to a specified file.
    
        NOTE: You will likely not need to modify this function.
    """

    # Parse the command-line arguments
    args = parse_args()
 
    # Generate the subscription payload using the provided secrets and parameters
    subscription = gen_subscription(
        args.secrets_file.read(), 
        args.device_id, 
        args.start, 
        args.end, 
        args.channel
    )

    # this logic may need to be edited, I'm cooking dinner rn
    if subscription == -1:
        return
 
    # Attempt to write the subscription file
    # - Uses "wb" (write binary) mode if --force is specified (overwrites existing file)
    # - Uses "xb" (exclusive write binary) mode otherwise (fails if the file exists)
    with open(args.subscription_file, "wb" if args.force else "xb") as f:
        f.write(subscription)
 
if __name__ == "__main__":
    main()