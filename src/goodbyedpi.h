#define HOST_MAXLEN 253
#define MAX_PACKET_SIZE 9016
extern int (*debugPrint)(char const *const _Format, ...);
#ifndef DEBUG
#define debug(...)                                                             \
	if (debugPrint) {                                                            \
		debugPrint(__VA_ARGS__);                                                   \
	}
#else
#define debug(...) printf(__VA_ARGS__)
#endif

int main(int argc, char *argv[]);
void deinit_all();
