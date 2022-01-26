#include "test_so.h"

int test_so_func(int a,int b)
{
    return a*b;
}

Box* const Box::_instance = new Box();

// 成员函数定义
double Box::get(void)
{
    return length * breadth * height;
}

void Box::set( double len, double bre, double hei)
{
    length = len;
    breadth = bre;
    height = hei;
}

