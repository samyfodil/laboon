// dlopen at run time: our own library (constructor, TLS through
// __tls_get_addr), an Alpine library (zlib), dlsym, dlclose and a dlerror.
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

const char *m5b_target(void);

int main(void) {
	int fails = 0;
	void *h = dlopen(m5b_target(), RTLD_NOW);
	if (!h) {
		printf("FAIL dlopen libm5: %s\n", dlerror());
		return 1;
	}
	int (*add)(int, int) = (int (*)(int, int))dlsym(h, "m5_add");
	int (*tls)(void) = (int (*)(void))dlsym(h, "m5_tls");
	int *inited = (int *)dlsym(h, "m5_inited");
	if (!add || !tls || !inited) printf("FAIL dlsym\n"), fails++;
	else {
		if (add(20, 22) != 42) printf("FAIL add\n"), fails++;
		if (tls() != 41 || tls() != 42) printf("FAIL tls\n"), fails++;
		if (*inited != 7) printf("FAIL constructor\n"), fails++;
	}
	void *z = dlopen("libz.so.1", RTLD_LAZY);
	const char *(*zv)(void) = z ? (const char *(*)(void))dlsym(z, "zlibVersion") : 0;
	if (!zv) printf("FAIL zlib: %s\n", dlerror()), fails++;
	else printf("zlib %s\n", zv());
	if (dlopen("libnope.so", RTLD_NOW) || !strstr(dlerror(), "libnope")) printf("FAIL dlerror\n"), fails++;
	dlclose(h);
	printf(fails ? "m5dlopen FAIL\n" : "m5dlopen OK\n");
	return fails;
}
