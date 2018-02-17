#define HOST_MAXLEN 253

#ifndef DEBUG
#define debug(...) do {} while (0)
#else
#define debug(...) printf(__VA_ARGS__)
#endif

int main(int argc, char *argv[]);
void deinit_all();
