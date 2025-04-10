#ifndef YKB_PROTOCOL_H
#define YKB_PROTOCOL_H

#include <stdint.h>
#include <string.h>

#define YKB_PROTOCOL_VERSION 1

#ifndef YKB_PROTOCOL_DATA_LENGTH
// Length of data buffer per one transfer
#define YKB_PROTOCOL_DATA_LENGTH 55
#endif // YKB_PROTOCOL_DATA_LENGTH

/* Errors */

#define YKB_PARSE_ERR_DATA_NULL -1
#define YKB_PARSE_ERR_BAD_VERSION -2
#define YKB_PARSE_ERR_BAD_REQUEST -3
#define YKB_PARSE_ERR_PREVIOUS_EXPECTED -4
#define YKB_PARSE_ERR_PACKET_COUNT_INVALID -5
#define YKB_PARSE_ERR_PACKET_COUNT_MISMATCH -6
#define YKB_PARSE_ERR_PACKET_NUMBER_MISMATCH -7
#define YKB_PARSE_ERR_PACKET_NUMBER_INVALID -8
#define YKB_PARSE_ERR_PACKET_SIZE_INVALID -9
#define YKB_PARSE_ERR_CRC_INVALID -10

#define YKB_PARSE_CONT_ERR_BADARGS -11
#define YKB_PARSE_CONT_ERR_OVERFLOW -12

#define YKB_PACK_ERR_BADARGS -1
#define YKB_PACK_ERR_NOMEM -2

/* Requests */

#define YKB_REQUEST_NONE 0U

#define YKB_REQUEST_GET_SETTINGS (1U << 4)
#define YKB_REQUEST_GET_MAPPINGS (2U << 4)
#define YKB_REQUEST_GET_VALUES (3U << 4)
#define YKB_REQUEST_GET_THRESHOLDS (4U << 4)

#define YKB_REQUEST_SET_SETTINGS (5U << 4)
#define YKB_REQUEST_SET_MAPPINGS (6U << 4)
#define YKB_REQUEST_SET_THRESHOLDS (7U << 4)

#define YKB_REQUEST_FIRMWARE_UPDATE (8U << 4)

#define YKB_REQUEST_CALIBRATE (9U << 4)

/* Request errors */

#define YKB_REQUEST_ERROR_PARSING (10U << 4)
#define YKB_REQUEST_ERROR_OUT_OF_MEM (11U << 4)
#define YKB_REQUEST_ERROR_UNKNOWN (12U << 4)

#define IS_YKB_REQUEST(ARG)                                                    \
  ((ARG == YKB_REQUEST_NONE) || IS_YKB_GET_REQUEST(ARG) ||                     \
   IS_YKB_SET_REQUEST(ARG) || IS_YKB_REQUEST_ERROR(ARG))

#define IS_YKB_GET_REQUEST(ARG)                                                \
  ((ARG == YKB_REQUEST_GET_SETTINGS) || (ARG == YKB_REQUEST_GET_MAPPINGS) ||   \
   (ARG == YKB_REQUEST_GET_VALUES) || (ARG == YKB_REQUEST_GET_THRESHOLDS))

#define IS_YKB_SET_REQUEST(ARG)                                                \
  ((ARG == YKB_REQUEST_SET_MAPPINGS) || (ARG == YKB_REQUEST_SET_SETTINGS) ||   \
   (ARG == YKB_REQUEST_SET_THRESHOLDS) ||                                      \
   (ARG == YKB_REQUEST_FIRMWARE_UPDATE) || (ARG == YKB_REQUEST_CALIBRATE))

#define IS_YKB_REQUEST_ERROR(ARG)                                              \
  ((ARG == YKB_REQUEST_ERROR_PARSING) ||                                       \
   (ARG == YKB_REQUEST_ERROR_OUT_OF_MEM) ||                                    \
   (ARG == YKB_REQUEST_ERROR_UNKNOWN))

#ifdef __GNUC__
#define YKB_PACKED __attribute__((__packed__))
#elif defined(_MSC_VER)
#define YKB_PACKED
#pragma pack(push, 1) // For MSVC
#else
#define YKB_PACKED
#warning                                                                       \
    "Packed attribute not defined for this compiler, struct padding might occur"
#endif

typedef struct YKB_PACKED {

  uint8_t request_and_version;
  // [0-3] Protocol request (Ignored on host)
  // [4-7] Protocol version. Current version: 1

  uint8_t packet_size; // Amount of bytes in data array

  uint16_t packet_count;  // Amount of packets coming in
  uint16_t packet_number; // Current packet index.
  // 0 <= packet_number < packet_count

  uint16_t crc; // CRC of data

  uint8_t data[YKB_PROTOCOL_DATA_LENGTH];

} ykb_protocol_t;

#ifdef _MSC_VER
#pragma pack(pop) // Restore packing for MSVC
#endif

static inline uint16_t crc16(const uint8_t *data, size_t length) {

  uint16_t crc = 0xFFFF;

  if (!data || length == 0) {
    return crc;
  }

  const uint16_t polynomial = 0xA001;

  for (size_t i = 0; i < length; i++) {
    crc ^= data[i];
    for (int bit = 0; bit < 8; bit++) {
      if (crc & 0x0001) {
        crc = (crc >> 1) ^ polynomial;
      } else {
        crc = crc >> 1;
      }
    }
  }
  return crc;
}

// Get the minimum protocol pack size.
//
// Pack size is always >= 1
uint16_t ykb_protocol_get_pack_size(uint32_t data_length) {
  return (data_length / YKB_PROTOCOL_DATA_LENGTH) + 1;
}

// Packs the data array with the length of `data_length`
// into the `result` protocol array.
//
// The caller is responsive for allocating memory for the result array.
// Size of the allocation:
// `ykb_protocol_get_pack_size(data_length) * sizeof(ykb_protocol_t)`
int ykb_protocol_pack(ykb_protocol_t *result, uint8_t request,
                      const uint8_t *data, uint32_t data_length) {

  if (!result || !IS_YKB_REQUEST(request)) {
    return YKB_PACK_ERR_BADARGS;
  }

  if (IS_YKB_GET_REQUEST(request)) {
    ykb_protocol_t p = {.data = {0},
                        .request_and_version = request | YKB_PROTOCOL_VERSION,
                        .packet_count = 1,
                        .packet_number = 0,
                        .packet_size = 0,
                        .crc = 0};
    p.crc = crc16(p.data, 0);
    memcpy(result, &p, sizeof(ykb_protocol_t));
    return 0;
  }

  uint16_t total_packets = ykb_protocol_get_pack_size(data_length);

  for (uint16_t i = 0; i < total_packets; i++) {
    ykb_protocol_t p;

    p.request_and_version = request | YKB_PROTOCOL_VERSION;
    p.packet_count = total_packets;
    p.packet_number = i;

    uint16_t offset = i * YKB_PROTOCOL_DATA_LENGTH;
    uint16_t bytes_left = (data_length > offset) ? (data_length - offset) : 0;
    if (bytes_left > YKB_PROTOCOL_DATA_LENGTH) {
      bytes_left = YKB_PROTOCOL_DATA_LENGTH;
    }

    p.packet_size = bytes_left;

    if (data) {
      if (bytes_left > 0) {
        memcpy(p.data, data + offset, bytes_left);
      }
      if (bytes_left < YKB_PROTOCOL_DATA_LENGTH) {
        memset(p.data + bytes_left, 0, YKB_PROTOCOL_DATA_LENGTH - bytes_left);
      }
    }

    p.crc = crc16(p.data, bytes_left);

    memcpy(result + (sizeof(ykb_protocol_t) * i), &p, sizeof(ykb_protocol_t));
  }

  return 0;
}

// Parses ykb_protocol from `data` buffer.
//
// `previous` should be NULL if first packet expected.
//
// Returns 0 on success or 1 if success and packet is last.
int ykb_protocol_parse(const ykb_protocol_t *previous, ykb_protocol_t *next,
                       const uint8_t *data) {

  if (!data) {
    return YKB_PARSE_ERR_DATA_NULL;
  }

  ykb_protocol_t new_packet;
  memcpy(&new_packet, data, sizeof(new_packet));

  uint8_t version = new_packet.request_and_version & 0x0F;
  if (version != YKB_PROTOCOL_VERSION) {
    return YKB_PARSE_ERR_BAD_VERSION;
  }

  uint8_t request = new_packet.request_and_version & 0xF0;
  if (!IS_YKB_REQUEST(request)) {
    return YKB_PARSE_ERR_BAD_REQUEST;
  }

  if (!previous && new_packet.packet_number != 0) {
    return YKB_PARSE_ERR_PREVIOUS_EXPECTED;
  }

  if (new_packet.packet_count == 0) {
    // Packet count should always be >= 1
    return YKB_PARSE_ERR_PACKET_COUNT_INVALID;
  }

  if (previous) {
    if (new_packet.packet_count != previous->packet_count) {
      return YKB_PARSE_ERR_PACKET_COUNT_MISMATCH;
    }
    if (new_packet.packet_number != previous->packet_number + 1) {
      return YKB_PARSE_ERR_PACKET_NUMBER_MISMATCH;
    }
  }

  if (new_packet.packet_number >= new_packet.packet_count) {
    return YKB_PARSE_ERR_PACKET_NUMBER_INVALID;
  }
  if (new_packet.packet_size > YKB_PROTOCOL_DATA_LENGTH) {
    return YKB_PARSE_ERR_PACKET_SIZE_INVALID;
  }

  uint16_t crc = crc16(new_packet.data, new_packet.packet_size);
  if (crc != new_packet.crc) {
    return YKB_PARSE_ERR_CRC_INVALID;
  }

  if (next) {
    *next = new_packet;
  }

  if (new_packet.packet_number == new_packet.packet_count - 1) {
    // Last packet recevied
    return 1;
  }

  return 0;
}

int ykb_protocol_parse_continuous(

    // Function pointer for getting new data
    int (*get_new_data)(uint8_t *out_buffer, size_t bytes_needed),

    // Optional callback which is called each iteration
    void (*iteration_callback)(uint16_t iteration, uint8_t *data,
                               uint16_t data_length),

    uint8_t *result,            // Result data buffer
    uint32_t result_max_length, // Maximum data buffer length
    uint32_t *out_total         // Optional result data buffer length
) {

  if (!get_new_data) {
    return YKB_PARSE_CONT_ERR_BADARGS;
  }

  ykb_protocol_t previous;
  ykb_protocol_t next;
  int err;
  uint16_t offset = 0;
  uint8_t temp[sizeof(ykb_protocol_t)];

  ykb_protocol_t *prev_ptr = NULL;

  for (uint16_t i = 0;; i++) {
    err = get_new_data(temp, sizeof(temp));
    if (err < 0) {
      return err;
    }

    err = ykb_protocol_parse(prev_ptr, &next, temp);
    if (err < 0) {
      return err;
    }

    if (result) {
      if (offset + next.packet_size > result_max_length) {
        return YKB_PARSE_CONT_ERR_OVERFLOW;
      }
      memcpy(result + offset, next.data, next.packet_size);
    }
    offset += next.packet_size;

    previous = next;
    prev_ptr = &previous;

    if (iteration_callback) {
      iteration_callback(i, next.data, next.packet_size);
    }

    if (err == 1) {
      // Last packet
      if (out_total) {
        *out_total = offset;
      }
      break;
    }
  }

  return 0;
}

#endif // YKB_PROTOCOL_H
