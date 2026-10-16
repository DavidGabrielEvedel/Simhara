#include <iostream>
#include <cstring>
#include <cstdlib>

void greetUser(const char* input) {
    char buffer[16];

    // VULNERABILITY 1: Potential buffer overflow
    strcpy(buffer, input);

    std::cout << "Hello, " << buffer << std::endl;
}

void executeCommand(const char* input) {
    char command[256];

    // VULNERABILITY 2: Command injection risk
    snprintf(command, sizeof(command), "echo %s", input);
    system(command);
}

int main() {
    greetUser("Simhara");
    executeCommand("test");
    return 0;
}