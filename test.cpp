#include <iostream>
#include <vector>


void dothing() {
	std::vector<int> vect;
	int i = 0;
	while (i < 100)
		vect.push_back(i++);
	
	for (const auto &num : vect)
		std::cout << num << std::endl;
	
	return;
}


int main() {
		dothing();
		return 0;
}