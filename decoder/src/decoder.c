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
#define MAX_FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define ENCRYPTED_DATA_SIZE 56
#define AUTH_DATA_SIZE 4
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF

/////////////////////// Hardware Constants ///////////////////
// User Guide to the MAX78000 : https://www.analog.com/media/en/technical-documentation/user-guides/max78000-user-guide.pdf
// Offsets to peripheral registers from Page 37
#define GCR_BASE (0x40000000)
#define TRAND_BASE_ADDR (0x4004D000)
#define REAL_TIME_CLOCK_ADDR (0x40006000)
// GCR Offset from Page 80 and shift for trand disable from Page 91
#define GCR_PCLKDIS1_BASE (GCR_BASE + 0x48)
#define GCR_TRAND_DISABLE (1<<2)
// Shifts for trand from Page 367
#define TRAND_DATA_OFFSET (0x08 >> 2)
// Real Time clock shifts from Page 279
#define SUBSEC_CTR_OFFSET (0x04 >> 2)
#define RTC_CTRL_ADDR (REAL_TIME_CLOCK_ADDR + 0x10)
#define RTC_BUSY (0x01 << 3)
#define RTC_BUSY_SHIFT 3
#define RTC_WRITE_ENABLE (0x01 << 15)
#define RTC_ENABLE (0x01)
#define RTC_SSEC_MAX 0xfff

#define SLEEP_MASK 0x7f
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
    timestamp_t timestamp;
    uint8_t data[MAX_FRAME_SIZE];
} frame_packet_t;

typedef struct {
    channel_id_t channel;
    uint8_t nonce[CHACHAPOLY_IV_SIZE];
    uint8_t auth_tag[AUTHTAG_SIZE];
    uint8_t encrypted_data[sizeof(frame_packet_t)];
} encrypted_frame_packet_t;

typedef struct {
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    channel_id_t channel;
    uint8_t channel_key[CHACHAPOLY_KEY_SIZE];
} subscription_update_packet_t;

typedef struct {
    uint8_t aad_p1[AUTH_DATA_SIZE];
    uint8_t nonce[CHACHAPOLY_IV_SIZE];
    uint8_t auth_tag[AUTHTAG_SIZE];
    uint8_t cipher_text[ENCRYPTED_DATA_SIZE];
} encrypted_update_packet_t;

typedef struct {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;


/**********************************************************
 ******************** TYPE DEFINITIONS ********************
 **********************************************************/

typedef struct {
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    uint8_t channel_key[CHACHAPOLY_KEY_SIZE];
} channel_status_t;

typedef struct {
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

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

/** @brief Initializes the Real Time Clock on the hardware
 * 
 * No params, void. See page 91
 */
void init_trng() {
    volatile uint32_t* pclkdis1 = (volatile uint32_t*)GCR_PCLKDIS1_BASE;
    *pclkdis1 &= ~GCR_TRAND_DISABLE;
}

/** @brief Initializes the Real Time Clock on the hardware
 * 
 * No params, void. See page 287
 */
void init_rtc() {
    volatile uint32_t* real_time_clock = (volatile uint32_t*)RTC_CTRL_ADDR;
    while ((*(real_time_clock) & RTC_BUSY)>>RTC_BUSY_SHIFT == 1);
    *(real_time_clock) |= RTC_WRITE_ENABLE;
    while ((*(real_time_clock) & RTC_BUSY)>>RTC_BUSY_SHIFT == 1);
    *(real_time_clock) |= RTC_ENABLE;
    while ((*(real_time_clock) & RTC_BUSY)>>RTC_BUSY_SHIFT == 1);
}
 
/** @brief Generate a random, 32-bit unsigned integer
 * 
 *  No params, void.
 *  Utilizes the TRNG Module on the MAX78000
 *  See page 367 of the User Guide for more information
 */
uint32_t true_random(void) {
    volatile uint32_t* trand_base = (volatile uint32_t*)TRAND_BASE_ADDR; 
    // Every time that offset is accessed, it clears the status bit and regenerates a random number  
    uint32_t random_num = *(trand_base + TRAND_DATA_OFFSET);
    return random_num;
}


/** @brief Generate random sleep delay
 * 
 *  No params, void. 
 *  Utilizes the Real Time Clock of the MAX78000
 *  See page 279 of the User Guide for more information
*/
void randomSleep(void) {
    volatile uint32_t* real_time_clock = (volatile uint32_t*)REAL_TIME_CLOCK_ADDR; // Base addr from user guide
    
    uint32_t random_num = true_random(); // Random num value
    // Get 7 bits becaus clock period is .25 ms 
    // .25ms * 0 to .25ms * 127 = random range 0ms - 32ms
    random_num &= SLEEP_MASK;

    uint32_t base_clk = *(real_time_clock + SUBSEC_CTR_OFFSET); // Starting clk value
    uint16_t loop_cap = (base_clk + random_num) & RTC_SSEC_MAX;
    bool rollover = loop_cap < base_clk;

    while (1) { // Loop for random wait
        if ((!rollover && *(real_time_clock + SUBSEC_CTR_OFFSET) > (loop_cap)) // Delay check
          || (rollover && *(real_time_clock + SUBSEC_CTR_OFFSET) < SLEEP_MASK && *(real_time_clock + SUBSEC_CTR_OFFSET) < loop_cap)) { // Rollover check
            break;
        }
    }

}


/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Lists out the actively subscribed channels over UART.
 * 
 *  @return 0 if successful.
*/
int list_channels(void) {
    list_response_t resp;
    pkt_len_t len = 0;

    resp.n_channels = 0;

    // delete any lingering data
    memset(&resp, 0, sizeof(list_response_t));

    // start at i = 1 because we don't print out channel 0
    for (uint32_t i = 1; i < MAX_CHANNEL_COUNT; i++) {
        // check to see if there's an VALID subscription for that channel - just checking if it has been updated from UINT_MAX
        if (decoder_status.subscribed_channels[i].start_timestamp != DEFAULT_CHANNEL_TIMESTAMP) {
            // double check that we have space to fit the channel info in resp
            if (resp.n_channels >= MAX_CHANNEL_COUNT) {
                return -1;
            }

            // check to see if the channel_info array is corrupted
            if ((resp.channel_info[resp.n_channels].channel != 0) || (resp.channel_info[resp.n_channels].start != 0) || (resp.channel_info[resp.n_channels].end != 0)) {
                return -1;
            }

            // if all is good, add the channel info to resp
            resp.channel_info[resp.n_channels].channel =  decoder_status.subscribed_channels[i].id;
            resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
            resp.n_channels++;
        }
    }

    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);

    // n_channels (32 bit) + array of channel_id (32 bit), start (64 bit), end (64 bit) : n * (160 bit)
    uint16_t expectedLen = get_list_byte_size(resp.n_channels);

    if (len != expectedLen) {
        // wrong packet size
        return -1;
    }

    // return the array of channels
    write_packet(LIST_MSG, &resp, len);
    return 0;
}


/** @brief Updates the channel subscription using a provided encrypted update packet.
 *
 *  @param pkt_len The length of the message received over UART
 *  @param encryptedData A Chacha20-Poly1305 encrypted packet that contains a random data, a chacha-poly IV, a poly1305 authTag and the encrypted subscription_update_packet_t data.
 *
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success. -1 if error.
*/
int update_subscription(pkt_len_t pkt_len, encrypted_update_packet_t *encryptedData) {
    // ensure that the UART message size matches the expected size of an encrypted update packet
    if (sizeof(encrypted_update_packet_t) != pkt_len) {
        return -1;
    }
    
    // stores the decrypted update packet
    subscription_update_packet_t update;

    // set up buffer to store decrypted frame data
    uint8_t *plaintext = malloc(sizeof(subscription_update_packet_t));
    memset(plaintext, 'A', sizeof(subscription_update_packet_t));

    // decrypt the encrypted update packet with random delays
    randomSleep();
    // decrypt_sym(ciphertext, len, authTag, aad, key, iv, plaintext)
    int32_t dec_val = decrypt_sym(encryptedData->cipher_text, ENCRYPTED_DATA_SIZE, (uint8_t *)&encryptedData->auth_tag, \
        (uint8_t *)&encryptedData->aad_p1, \
        subscription_decrypt_key, (uint8_t *)&encryptedData->nonce, \
        plaintext);

    // check if the decryption function ran successfully
    if (dec_val != 0) {
        return -1;
    }

    // take care of any potential memory corruption concerns with the malloc call
    memcpy(&update, plaintext, sizeof(subscription_update_packet_t));
    memset(plaintext, 'A', sizeof(subscription_update_packet_t));
    free(plaintext);
    plaintext = NULL;

    randomSleep();
    // check if the decoder id corresponds to our decoder ID
    if (update.decoder_id != DECODER_ID) {
        return -1;
    }
    
    // update channel can be any uint32_t, so we don't need a check

    // check that the start_timestamp is before the end_timestamp
    if (update.start_timestamp > update.end_timestamp) {
        return -1;
    }

    randomSleep();
    // subscription updates do not need to be active, apparently

    // should throw an error if we try to update channel 0
    if (update.channel == 0) {
        return -1;
    }

    // if a valid subscription for that channel ALREADY exists, make sure the end_timestamp is later
    uint8_t current_idx = 0;
    for (int i = 1; i < 9; i++) {
        // if this index isn't active, we can overwrite it
        if (!decoder_status.subscribed_channels[i].active && current_idx == 0) {
            current_idx = i;
        }
        if (decoder_status.subscribed_channels[i].active && decoder_status.subscribed_channels[i].id == update.channel) {
            // we MUST accept the more recent one
            // if we find the channel id in our structure, we want the current index to be set to that index to overwrite
            current_idx = i;
            break;
        }
    }
    // make sure we don't accidentally overwrite the emergency channel : something in the default behavior failed; should never reach here
    if (current_idx == 0) {
        return -1;
    }

    // write the channel subscription to RAM
    decoder_status.subscribed_channels[current_idx].active = true;
    decoder_status.subscribed_channels[current_idx].id = update.channel;
    decoder_status.subscribed_channels[current_idx].start_timestamp = update.start_timestamp;
    decoder_status.subscribed_channels[current_idx].end_timestamp = update.end_timestamp;
    memcpy(decoder_status.subscribed_channels[current_idx].channel_key, update.channel_key, CHACHAPOLY_KEY_SIZE);

    // write all channel subscriptions to flash
    int32_t ret;
    ret = flash_simple_erase_page(FLASH_STATUS_ADDR);
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1);
    }
    
    ret = flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1);
    }

    // send a success message with an empty body
    write_packet(SUBSCRIBE_MSG, NULL, 0);

    // clear memory to prevent uninitialized memory bugs
    memset(&update, 'A', sizeof(update));
    return 0;
}

/** @brief Processes a packet containing frame data.
 *
 *  @param pkt_len The length of the encrypted frame packet
 *  @param enc_frame A pointer to the incoming encrypted frame packet
 *
 *  @return 0 if successful. -1 if data is from unsubscribed channel.
*/
int decode(pkt_len_t pkt_len, encrypted_frame_packet_t *enc_frame) {
    frame_packet_t decrypted_frame;

    randomSleep();

    /* assuming the channel, nonce, and tag are present in the encrypted
       frame packet, calculate the size of the encrypted frame */
    pkt_len_t encrypted_size = pkt_len - (sizeof(channel_id_t) + CHACHAPOLY_IV_SIZE + AUTHTAG_SIZE);

    // ensure there is at least one byte in the frame (other than the timestamp) to decrypt
    if (encrypted_size < sizeof(timestamp_t)+1) {
        return -1;
    }

    // ensure that no more than 64 bytes of encrypted data is sent with the timestamp
    if (encrypted_size > MAX_FRAME_SIZE + sizeof(timestamp_t)) {
        return -1;
    }

    randomSleep();
    // channel number can be anything, but we need to make sure it's actually in the grid
    uint8_t current_idx = 0xff;
  
    for (int i = 0; i < 9; i++) {
        if (decoder_status.subscribed_channels[i].id == enc_frame->channel) {
            current_idx = i;
            if (decoder_status.subscribed_channels[i].active == false) {
                // make sure that channel is ACTIVE, not just subscribed
                return -1;
            }
            break;
        }
    }
    // if current_idx didn't update, it's a bad channel and we can die
    if (current_idx == 0xff) { return -1; }

    // set up buffer to store decrypted frame data
    uint8_t *plaintext = malloc(sizeof(frame_packet_t));
    memset(plaintext, 'A', sizeof(frame_packet_t));
    
    // decrypt the encrypted frame using the corresponding channel key and the ChaChaPoly1305 cipher
    // randomSleep();
    int32_t dec_val = decrypt_sym(enc_frame->encrypted_data, encrypted_size, enc_frame->auth_tag,
        (uint8_t *)&enc_frame->channel,
        (uint8_t *)&decoder_status.subscribed_channels[current_idx].channel_key, (uint8_t *)&enc_frame->nonce,
        plaintext);

    // check if the decryption function ran successfully
    if (dec_val != 0) {
        return -1;
    }

    // fill in the decrypted frame object
    memcpy(&decrypted_frame, plaintext, sizeof(frame_packet_t));
    memset(plaintext, 'A', sizeof(frame_packet_t));
    free(plaintext);
    plaintext = NULL;

    // if the timestamp is BEFORE our subscription period, just quit
    if (decrypted_frame.timestamp < decoder_status.subscribed_channels[current_idx].start_timestamp) {
        return -1;
    }

    // is the timestamp within decoder's subscription period?
    if (decrypted_frame.timestamp > decoder_status.subscribed_channels[current_idx].end_timestamp) {
        // we can't delete the key :sob:
        memset(decoder_status.subscribed_channels[current_idx].channel_key, 0, CHACHAPOLY_KEY_SIZE);
        decoder_status.subscribed_channels[current_idx].active = false;

        int32_t ret;
        // write deleted key from disk
        ret = flash_simple_erase_page(FLASH_STATUS_ADDR);
        if (ret < 0) {
            STATUS_LED_ERROR();
            // if uart fails to initialize, do not continue to execute
            while (1);
        }

        ret = flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
        if (ret < 0) {
            STATUS_LED_ERROR();
            // if uart fails to initialize, do not continue to execute
            while (1);
        }
        
        return -1;
    }

    // is the timestamp >= next allowed
    if (decrypted_frame.timestamp < next_time_allowed) {
        return -1;
    }

    // play decoded TV frame
    write_packet(DECODE_MSG, decrypted_frame.data, encrypted_size-sizeof(timestamp_t));

    // set next allowed timestamp to current frame's timestamp+1
    next_time_allowed = decrypted_frame.timestamp + 1;

    return 0;
}

/** @brief Initializes peripherals for system boot.
*/
void init() {
    int32_t ret;

    // initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();

    // read starting flash values into our flash status struct
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

    // if first_boot is set, then set all channels to NULL and fill in channel 0
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        /* If this is the first boot of this decoder, mark all channels as unsubscribed.
        *  This data will be persistent across reboots of the decoder. Whenever the decoder
        *  processes a subscription update, this data will be updated.
        */

        // mark the decoder as having booted before, and thus all the data in decoder_status can be trusted
        decoder_status.first_boot = FLASH_FIRST_BOOT;

        channel_status_t subscription[MAX_CHANNEL_COUNT];

        // I think this is still fine because we don't care about ids
        for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
            subscription[i].id = 0;
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
            memset(&subscription[i].channel_key, 0, sizeof(subscription[i].channel_key));
        }

        // set the channel 0 key in memory
        subscription[EMERGENCY_CHANNEL].id = EMERGENCY_CHANNEL;
        subscription[EMERGENCY_CHANNEL].start_timestamp = 0;
        subscription[EMERGENCY_CHANNEL].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
        subscription[EMERGENCY_CHANNEL].active = true;
        memcpy(subscription[EMERGENCY_CHANNEL].channel_key, channel_0_key, CHACHAPOLY_KEY_SIZE);

        // write the starting channel subscriptions into RAM
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT*sizeof(channel_status_t));

        // write the starting channel subscriptions into flash
        ret = flash_simple_erase_page(FLASH_STATUS_ADDR);
        if (ret < 0) {
            STATUS_LED_ERROR();
            // if uart fails to initialize, do not continue to execute
            while (1);
        }

        ret = flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
        if (ret < 0) {
            STATUS_LED_ERROR();
            // if uart fails to initialize, do not continue to execute
            while (1);
        }
    }

    init_trng();
    init_rtc();

    // initialize the UART peripheral to enable serial I/O
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
    // also could do length checks if this size proves problematic
    uint8_t uart_buf[0x10000];
    msg_type_t cmd;
    int result;
    int retval;
    uint16_t pkt_len;

    // initialize the device
    init();

    // process commands forever
    while (1) {
        result = read_packet(&cmd, uart_buf, &pkt_len);

        if (result < 0) {
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
            retval = list_channels();
            if (retval < 0) { print_error("Failed list channels"); }
            break;

        // Handle decode command
        case DECODE_MSG:
            retval = decode(pkt_len, (encrypted_frame_packet_t *)uart_buf);
            if (retval < 0) { print_error("Failed decode"); }
            break;

        // Handle subscribe command
        case SUBSCRIBE_MSG:
            retval = update_subscription(pkt_len, (encrypted_update_packet_t *)uart_buf);
            if (retval < 0) { print_error("Failed update subscription"); }
            break;

        // Handle bad command
        default:
            break;
        }
    }
}