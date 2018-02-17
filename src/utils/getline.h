#if !HAVE_GETDELIM
ssize_t	getdelim(char **, size_t *, int, FILE *);
#endif

#if !HAVE_GETLINE
ssize_t	getline(char **, size_t *, FILE *);
#endif
