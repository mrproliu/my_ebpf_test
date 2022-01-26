#include "load_so.h"
#include <dlfcn.h>

double getBook(struct Books b) {
    return b.length;
}

void setBook(struct Books b, double len, double bre, double hei) {
    return b.set(len, bre, hei);
}

double do_test_so_func(double len, double bre, double hei)
{
    void* handle;

    handle = dlopen("./test_so.so", 1);
    Books book = (Books)dlsym(handle, "instance");
    setBook(book, len, bre, hei);

    return getBook(book);
}