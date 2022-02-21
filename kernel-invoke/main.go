package main

/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

struct ksym {
	long addr;
	char *name;
};
#define MAX_SYMS 300000
static struct ksym syms[MAX_SYMS];
static int sym_cnt;

static int ksym_cmp(const void *p1, const void *p2)
{
	return ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;
}

int load_kallsyms(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char func[256], buf[256];
	char symbol;
	void *addr;
	int i = 0;

	if (!f)
		return -ENOENT;

	while (fgets(buf, sizeof(buf), f)) {
		if (sscanf(buf, "%p %c %s", &addr, &symbol, func) != 3)
			break;
		if (!addr)
			continue;
		syms[i].addr = (long long) addr;
		syms[i].name = strdup(func);
		//printf("%llu -> %s\n", addr, syms[i].name);
		i++;
	}
	fclose(f);
	sym_cnt = i;
	qsort(syms, sym_cnt, sizeof(struct ksym), ksym_cmp);
	printf("Success! \n");
	return 0;
}

int ksym_search(unsigned long long key)
{
	int start = 0, end = sym_cnt;
	int result;

	while (start < end) {
		size_t mid = start + (end - start) / 2;

		result = key - syms[mid].addr;
		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return 1;
	}

	if (start >= 1 && syms[start - 1].addr < key &&
	    key < syms[start].addr) {
		printf("found: %s\n", &syms[start - 1].name)
		return 1;
	}

	printf("not found");
	return 0;
}

void demo(){
	printf("HELLO WORLD! \n");
}
*/
import "C"
import "strconv"

func main() {
	C.demo()
	C.load_kallsyms()
	findData("ffffffff94369938")
}

func findData(addr string) {
	d, _ := strconv.ParseUint(addr, 16, 64)
	C.ksym_search(C.ulonglong(d))
}
