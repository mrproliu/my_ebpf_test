struct Books
{
   double  length;
   double  breadth;
   double  height;
};

double getBook(struct Books b);
void setBook(struct Books b, double len, double bre, double hei);

int do_test_so_func(double len, double bre, double hei);