void c() {
	int d = 4;
}

void b() {
	c();
}

void f() {
	b();
}

int main() {
   int a = 1;
   int b = 2;
   int c = 3;
   f();
}