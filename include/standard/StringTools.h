#ifndef STRINGTOOLS
#define STRINGTOOLS
#include "StandardHeader.h"

std::vector<std::string> string_Split(const std::string& str, char delimiter) {
    std::vector<std::string> result;
    std::string current;
    
    for (char ch : str) {
        if (ch == delimiter) {
            if (!current.empty()) {
                result.push_back(current);
                current.clear();
            }
        } else {
            current += ch;
        }
    }
    
    // Add the last token
    if (!current.empty()) {
        result.push_back(current);
    }

    return result;
}
#endif