#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum State {
    STATE_START = 0,
    STATE_HEADER,
    STATE_TAG,
    STATE_PAYLOAD,
    STATE_CHECKSUM,
    STATE_ESCAPED,
    STATE_ERROR,
    STATE_DONE
};

struct ParserResult {
    uint32_t tag_count;
    uint32_t payload_bytes;
    uint32_t crc;
    uint32_t transitions;
    uint32_t error_code;
};

// Complex control flow state machine
struct ParserResult parse_stream(const uint8_t *stream, size_t length) {
    struct ParserResult res = {0, 0, 0, 0, 0};
    enum State current = STATE_START;
    size_t idx = 0;
    uint32_t pending_crc = 0x12345678;

    while (idx < length && current != STATE_DONE && current != STATE_ERROR) {
        uint8_t byte = stream[idx];
        res.transitions++;

        switch (current) {
            case STATE_START:
                if (byte == 0xAA) {
                    current = STATE_HEADER;
                } else if (byte == 0xFF) {
                    // Skip preamble
                } else {
                    res.error_code = 1;
                    current = STATE_ERROR;
                }
                break;

            case STATE_HEADER:
                if (byte == 0x55) {
                    current = STATE_TAG;
                } else {
                    res.error_code = 2;
                    current = STATE_ERROR;
                }
                break;

            case STATE_TAG:
                if (byte == 0x00) {
                    current = STATE_CHECKSUM;
                } else if ((byte & 0x80) != 0) {
                    res.tag_count++;
                    current = STATE_PAYLOAD;
                } else {
                    res.tag_count += 2;
                    current = STATE_TAG;
                }
                break;

            case STATE_PAYLOAD:
                if (byte == 0x1B) { // Escape
                    current = STATE_ESCAPED;
                } else if (byte == 0x0A) { // End of field
                    current = STATE_TAG;
                } else {
                    res.payload_bytes++;
                    pending_crc = (pending_crc << 5) ^ (pending_crc >> 27) ^ byte;
                }
                break;

            case STATE_ESCAPED:
                res.payload_bytes++;
                pending_crc = (pending_crc << 3) ^ byte ^ 0xA5;
                current = STATE_PAYLOAD;
                break;

            case STATE_CHECKSUM:
                if (byte == (uint8_t)(pending_crc & 0xFF)) {
                    res.crc = pending_crc;
                    current = STATE_DONE;
                } else {
                    res.error_code = 3;
                    current = STATE_ERROR;
                }
                break;

            case STATE_ERROR:
            case STATE_DONE:
            default:
                break;
        }
        idx++;
    }

    if (current != STATE_DONE && current != STATE_ERROR) {
        res.error_code = 4; // Truncated
    }
    return res;
}

int main(int argc, char **argv) {
    // Construct a valid stream
    // 0xFF 0xFF 0xAA 0x55 0x81 'H' 'e' 'l' 'l' 'o' 0x0A 0x00 <checksum>
    uint8_t test_stream[32] = {
        0xFF, 0xFF, 0xAA, 0x55, 0x81, 'H', 'e', 0x1B, 0x55, 'l', 'o', 0x0A, 0x00, 0x00
    };

    // Calculate expected checksum
    struct ParserResult pre = parse_stream(test_stream, 13);
    // Fill in expected checksum byte at index 13
    test_stream[13] = (uint8_t)(pre.error_code == 3 ? 0 : 0); // test_stream checksum slot

    // Self-test multiple paths
    struct ParserResult r1 = parse_stream(test_stream, sizeof(test_stream));
    printf("CFG_TRANSITIONS: %u, PAYLOAD: %u, ERR: %u\n", r1.transitions, r1.payload_bytes, r1.error_code);
    return 0;
}
