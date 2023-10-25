#define TLS_CONTENT_TYPE_HANDSHAKE 22
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define TLS_SNI_HOST_NAME_TYPE 0

#define TLS_1_0_VERSION "\x03\x01"
#define TLS_1_1_VERSION "\x03\x02"
#define TLS_1_2_AND_1_3_VERSION "\x03\x03"
#define TLS_EXTENSION_TYPE_SERVER_NAME "\x00\x00"

#define TLS_CONTENT_TYPE_LENGTH 1
#define TLS_VERSION_LENGTH 2
#define TLS_RECORD_LENGTH_LENGTH 2
#define TLS_RANDOM_LENGTH 32
#define TLS_SESSION_ID_LENGTH 1
#define TLS_CIPHER_SUITES_LENGTH 2
#define TLS_COMPRESSION_METHODS_LENGTH 1
#define TLS_EXTENSIONS_LENGTH 2
#define TLS_EXTENSION_TYPE_LENGTH 2
#define TLS_EXTENSION_LENGTH_LENGTH 2
#define TLS_SNI_HEADER_LENGTH 5

#define TLS_RECORD_HEADER_SIZE TLS_CONTENT_TYPE_LENGTH + TLS_VERSION_LENGTH + TLS_RECORD_LENGTH_LENGTH
#define TLS_MESSAGE_HEADER_SIZE 4