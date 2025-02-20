/**
 * @file    decoder.c
 * @author  Samuel Meyers
 * @brief   eCTF Decoder Example Design Implementation
 * @date    2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_uart.h"

#include "user_settings.h"
#include "adv_crypto.h"
#include <stdlib.h>
#include "secrets.h"

/* Code between this #ifdef and the subsequent #endif will
*  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
*  the projectk.mk file. */

/**********************************************************
 ******************* PRIMITIVE TYPES **********************
 **********************************************************/

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

/**********************************************************
 *********************** CONSTANTS ************************
 **********************************************************/

#define MAX_CHANNEL_COUNT 9
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define ENC_FRAME_SIZE (FRAME_SIZE+sizeof(timestamp_t))
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define ENCRYPTED_PACKET_SIZE 280
#define ENCRYPTED_DATA_SIZE 256
#define AUTH_DATA_SIZE 8
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF

///////////////////////Hardware Constants///////////////////
#define TRAND_BASE_ADDR (0x4004D000)
#define TRAND_CTRL_OFFSET (0x00 >> 2)
#define TRAND_STATUS_OFFSET (0x04 >> 2)
#define TRAND_DATA_OFFSET (0x08 >> 2)
#define REAL_TIME_CLOCK_ADDR (0x40006000)
#define SUBSEC_CTR_OFFSET (0x04 >> 2)
#define RTC_KEYWIPE_BIT (0x01 << 15)
#define RTC_KEYGEN_BIT (0x01 << 3)
#define get_list_byte_size(a) (4 + (a * 20)) // 4 header bytes + 20 bytes per channel

/**********************************************************
 ********************* STATE MACROS ***********************
 **********************************************************/

// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))


/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
// for more information on what struct padding does, see:
// https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Structure-Layout.html
typedef struct {
    channel_id_t channel;
    uint8_t nonce[CHACHAPOLY_IV_SIZE];
    uint8_t auth_tag[AUTHTAG_SIZE];
    uint8_t encrypted_data[FRAME_SIZE+sizeof(timestamp_t)];
} encrypted_frame_packet_t;

typedef struct {
    channel_id_t channel;
    uint8_t nonce[CHACHAPOLY_IV_SIZE];
    uint8_t auth_tag[AUTHTAG_SIZE];
    timestamp_t timestamp;
    uint8_t data[FRAME_SIZE];
} frame_packet_t;

typedef struct {
    uint8_t additional_auth_data[AUTH_DATA_SIZE];
    uint8_t auth_tag[AUTHTAG_SIZE];
    uint8_t cipher_text[ENCRYPTED_DATA_SIZE];
} encrypted_update_packet_t;

typedef struct {
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    channel_id_t channel;
    uint8_t channel_key[POLY_KEY_SIZE];
} subscription_update_packet_t;

typedef struct {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

/**********************************************************
 ******************** TYPE DEFINITIONS ********************
 **********************************************************/


typedef struct {
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    uint8_t channel_key[POLY_KEY_SIZE];
} channel_status_t;

typedef struct {
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
flash_entry_t decoder_status;

// Next timestamp allowed
timestamp_t next_time_allowed = 0;

/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/
 
/** @brief Generate random sleep delay
 * 
 *  No params, void
*/
void randomSleep() {
    uint32_t* trand_base = (uint32_t*)TRAND_BASE_ADDR;

    uint32_t* real_time_clock = (uint32_t*)REAL_TIME_CLOCK_ADDR; // Base addr from user guide

    *(trand_base + TRAND_CTRL_OFFSET) = RTC_KEYWIPE_BIT; // keywipe
    *(trand_base + TRAND_CTRL_OFFSET) = RTC_KEYGEN_BIT;  // keygen
    while (*(trand_base + TRAND_STATUS_OFFSET) == 0) { // Loop for rng gen 
        ;
    }
    
    uint32_t random_num = *(trand_base + TRAND_DATA_OFFSET); // Random num value
    // Get 7 bits becaus clock period is .25 ms 
    // .25ms * 0 to .25ms * 127 = random range 0ms - 32ms
    random_num &= 0x7F;
    uint32_t base_clk = *(real_time_clock + SUBSEC_CTR_OFFSET); // Starting clk value

    while (1) { // Loop for random wait
        if (*(real_time_clock + SUBSEC_CTR_OFFSET) > (base_clk + random_num) // Delay check
          || *(real_time_clock + SUBSEC_CTR_OFFSET) < base_clk // Rollover check
          || *(real_time_clock) == 0) { // Rollover double check
            break;
        }
    }

    return;
}


/** @brief Checks whether the decoder is subscribed to a given channel
 *
 *  @param channel The channel number to be checked.
 *  @return 1 if the the decoder is subscribed to the channel.  0 if not.
*/
int is_subscribed(channel_id_t channel) {
    // Check if this is an emergency broadcast message
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    // Check if the decoder has has a subscription
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active) {
            return 1;
        }
    }
    return 0;
}


/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Lists out the actively subscribed channels over UART.
 * 
 *  @return 0 if successful.
*/
int list_channels() {
    list_response_t resp;
    pkt_len_t len = 0;

    resp.n_channels = 0;

    // delete any lingering data
    for (uint16_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        resp.channel_info[i].channel = 0;
        resp.channel_info[i].start = 0;
        resp.channel_info[i].end = 0;
    }

    // Start at i = 1 because we don't print out channel 0
    for (uint32_t i = 1; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            if (resp.n_channels >= MAX_CHANNEL_COUNT) {
                // too many channels
                // TODO: Make this a defined value
                return 1;
            }
            if (resp.channel_info[i].channel != 0 ||
                resp.channel_info[i].start != 0 ||
                resp.channel_info[i].end != 0) {
                    // data in chanel_info array corrupted
                    return 2;
            }
            resp.channel_info[resp.n_channels].channel =  decoder_status.subscribed_channels[i].id;
            resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
            resp.n_channels++;
        }
    }

    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);

    // Num_channels (32 bit) + array of channel_id (32 bit), start (64 bit), end (64 bit) : n * (160 bit)
    uint16_t expectedLen = get_list_byte_size(resp.n_channels);
    if (len !=  expectedLen) {
	printf("len was %d, expected %d\n", len, expectedLen);
        // packet wrong size 
        return 3;
    }
    // Success message
    write_packet(LIST_MSG, &resp, len);
    return 0;
}


/** @brief Updates the channel subscription for a subset of channels.
 *
 *  @param encrypted_data_t An RSA encrypted packet that contains a poly1305 authTag and the encrypted subscription_update_packet_t data.
 *
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success.  -1 if error.
*/
int update_subscription(pkt_len_t pkt_len, encrypted_update_packet_t *encryptedData) {
    // Sets the object to store the POLY 1305 hash
    uint8_t calculated_tag[AUTHTAG_SIZE];

    if (ENCRYPTED_PACKET_SIZE != pkt_len) {
        return -1;
    }
    
    // Hashes the encrypted packet with random delays to secure the process.
    randomSleep();
    int hashStatus = digest(encryptedData->cipher_text, ENCRYPTED_DATA_SIZE, encryptedData->additional_auth_data, AUTH_DATA_SIZE, subscription_verify_key, calculated_tag);
    randomSleep();

    // Checks if the hash function was successful
    if (hashStatus != 0) {
        return -1;
    }
    
    // If the calculated hash and sent hash do not match the program terminates.
    if (encryptedData->auth_tag != calculated_tag) {
        return -1;
    }
    // Another random delay to increase security of the encryption process.
    randomSleep();
    
    // Sets the object to store the decrypted update packet.
    subscription_update_packet_t update;
  
    // Decrypts the encrypted update packet with random delays to secure the decryption process.
    randomSleep();
    int decryptStatus = decrypt_asym(encryptedData->cipher_text, ENCRYPTED_DATA_SIZE, subscription_decrypt_key, sizeof(subscription_decrypt_key), (uint8_t *)&update, sizeof(subscription_update_packet_t));
    randomSleep();

    // Checks that decrypt function was successful
    if (decryptStatus != 0) {
        return -1;
    }

    // Checks if the decoder id is a valid decoder id.
    if(update.decoder_id != DECODER_ID) {
        return -1;
    }
    
    // Checks that channel is a non-emergency valid channel.
    if (update.channel < 1 || update.channel > 8) {
        return -1;
    }

    // Writes the channel subscription to RAM.
    decoder_status.subscribed_channels[update.channel].active = true;
    decoder_status.subscribed_channels[update.channel].id = update.channel;
    decoder_status.subscribed_channels[update.channel].start_timestamp = update.start_timestamp;
    decoder_status.subscribed_channels[update.channel].end_timestamp = update.end_timestamp;
    // decoder_status.subscribed_channels[update.channel].channel_key = update.channel_key;
    memcpy(decoder_status.subscribed_channels[update.channel].channel_key, update.channel_key, CHACHAPOLY_KEY_SIZE);

    // Writes the channel subscription to flash.
    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    // Success message with an empty body
    write_packet(SUBSCRIBE_MSG, NULL, 0);

    // Clears update memory locations
    memset(&update, 'A', sizeof(update)*sizeof(uint8_t));
    return 0;
}

/** @brief Processes a packet containing frame data.
 *
 *  @param pkt_len A pointer to the incoming packet.
 *  @param new_frame A pointer to the incoming packet.
 *
 *  @return 0 if successful.  -1 if data is from unsubscribed channel.
*/
int decode(pkt_len_t pkt_len, encrypted_frame_packet_t *enc_frame) {
    frame_packet_t decrypted_frame;

    //wait random amount of time between 1 and 30 milliseconds
    // randomSleep();

    int16_t encrypted_size = pkt_len - (sizeof(channel_id_t) + CHACHAPOLY_IV_SIZE + AUTHTAG_SIZE);

    // checking to see if there is at least some data to decrypt
    // timestamp is 8 bytes, frame must be at least one byte to be valid
    if (encrypted_size < sizeof(timestamp_t)+1) { 
        print_error("Packet length of DECODE frame is too small\n");
        return -1;
    }
    if (encrypted_size > FRAME_SIZE + sizeof(timestamp_t)) {
        print_error("Packet length of DECODE frame is too large\n");
        return -1;

    }
    print_debug("Packet length okay\n");

    //Is channel number an unsigned int >=0 and <=8?
    if (enc_frame->channel < 0 || enc_frame->channel > 8) {
        print_error("Channel outside of valid range\n");
        return -1;
    }
    print_debug("Channel inside valid range\n");

    //Is decoder subscribed to the channel?
    if (!is_subscribed(enc_frame->channel)) {
        print_error("Not subscribed to channel\n");
        return -1;
    }
    print_debug("Decoder is subscribed to channel\n");

    //wait random amount of time between 1 and 30 milliseconds
    // randomSleep();
    

    // decrypt frame
    // Encrypted and decrypted frames are the same size, so this should work.
    // Then the decypted data can be put into the decrypted frame.
    uint8_t *plaintext = (uint8_t *)malloc(encrypted_size);
    if (!decrypt_sym(enc_frame->encrypted_data, encrypted_size, enc_frame->auth_tag,\
     (uint8_t *)&enc_frame->channel, 
     (uint8_t *)&decoder_status.subscribed_channels[enc_frame->channel].channel_key, (uint8_t *)&enc_frame->nonce,\
     plaintext)) {
        print_error("Decryption failed\n");
        return -1;
    } 
    print_debug("Decryption succeeded\n");
    memcpy(&decrypted_frame, &plaintext, sizeof(enc_frame));
    free(plaintext);

    //is the timestamp within decoder's subscription period
    if (decrypted_frame.timestamp < decoder_status.subscribed_channels[decrypted_frame.channel].start_timestamp ||\
     decrypted_frame.timestamp > decoder_status.subscribed_channels[decrypted_frame.channel].end_timestamp) {
        print_error("Timestamp outside of subscription time\n");

        // delete key from memory and mark channel as unsubscribed
        memset(decoder_status.subscribed_channels[decrypted_frame.channel].channel_key, 0, CHACHAPOLY_KEY_SIZE);
        decoder_status.subscribed_channels[decrypted_frame.channel].active = false;
        decoder_status.subscribed_channels[decrypted_frame.channel].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
        decoder_status.subscribed_channels[decrypted_frame.channel].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;

        // write deleted key from disk
        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

        return -1;
    }
    print_debug("Timestamp inside subscription time\n");


    //is the timestamp >= next allowed
    if (decrypted_frame.timestamp < next_time_allowed) {
        print_error("Timestamp is less than next time allowed\n");
        return -1;
    }
    print_debug("Timestamp greater than or equal to next time allowed");

    //play decoded TV frame
    //encrypted_size-sizeof(timestamp_t) is guarenteed to be positive because of our check above
    //prevents type issues.
    write_packet(DECODE_MSG, decrypted_frame.data, encrypted_size-sizeof(timestamp_t));

    //set next allowed timestamp to current frame's timestamp+1
    next_time_allowed = decrypted_frame.timestamp + 1;

    return 0;
}

/** @brief Initializes peripherals for system boot.
*/
void init() {
    int ret;

    // Initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();

    // Read starting flash values into our flash status struct
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        /* If this is the first boot of this decoder, mark all channels as unsubscribed.
        *  This data will be persistent across reboots of the decoder. Whenever the decoder
        *  processes a subscription update, this data will be updated.
        */
        print_debug("First boot.  Setting flash...\n");

        decoder_status.first_boot = FLASH_FIRST_BOOT;

        channel_status_t subscription[MAX_CHANNEL_COUNT];

        for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
            memset(&subscription[i].channel_key, 0, sizeof(subscription[i].channel_key));
        }

        // set the channel 0 key in memory
        subscription[0].start_timestamp = 0;
        subscription[0].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
        subscription[0].active = true;
        memcpy(subscription[0].channel_key, channel_0_key, CHACHAPOLY_KEY_SIZE);

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT*sizeof(channel_status_t));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }

    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1);
    }
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    char output_buf[128] = {0};
    // also could do length checks if this proves problematic
    uint8_t uart_buf[0x10000];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    print_debug("Decoder Booted!\n");

    // process commands forever
    while (1) {
        print_debug("Ready\n");

        STATUS_LED_GREEN();

        result = read_packet(&cmd, uart_buf, &pkt_len);

        if (result < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host\n");
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
            STATUS_LED_CYAN();

            list_channels();
            break;

        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            decode(pkt_len, (encrypted_frame_packet_t *)uart_buf);
            break;

        // Handle subscribe command
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            update_subscription(pkt_len, (encrypted_update_packet_t *)uart_buf);
            break;

        // Handle bad command
        default:
            STATUS_LED_ERROR();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}
