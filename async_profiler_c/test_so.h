int test_so_func(int a,int b);

class Box
{
   private:
      static Box* const _instance;
   public:
      double length;   // 长度
      double breadth;  // 宽度
      double height;   // 高度
      // 成员函数声明
      double get(void);
      void set( double len, double bre, double hei );

      static Box* instance() {
        return _instance;
      }
};