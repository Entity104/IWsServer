#ifndef DATATOOLS
    #define DATATOOLS
    #include "StandardHeader.h"

    const std::string base64_chars =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/";

    inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
    }

    inline std::vector<unsigned char> concatenate(const std::vector<unsigned char>& a, const std::vector<unsigned char>& b) {
        std::vector<unsigned char> result(a.size() + b.size());
        std::memcpy(result.data(), a.data(), a.size());
        std::memcpy(result.data() + a.size(), b.data(), b.size());
        return result;
    }
    
    inline std::string to_hex(const std::vector<unsigned char>& buffer) {
        std::ostringstream oss;
        for (unsigned char byte : buffer) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return oss.str();
    }
    inline std::string to_hex(byte* array, int lenght) {
        std::ostringstream oss;
        for (int i=0; i<lenght; i++) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(array[i]);
        }
        return oss.str();
    }

    inline uint32_t bytesToInt(byte mvb, byte b3, byte b2, byte lvb){
        return (lvb + (b2 * 256) + (b3 * 65536) + (mvb * 16777216));
    }

    inline word bytesToWord(byte b2, byte b1){
        return (b1 + (b2 * 256));
    }

    inline void GenerateRandomBytes(byte *array, int size){
        std::random_device rd; // Obtain a random number from hardware
        std::mt19937 generator(rd()); // Seed the generator

        // Generate random bytes
        for (size_t i = 0; i < size; ++i) {
            array[i] = static_cast<unsigned char>(generator() % 256); // Generate a random byte
        }
    }

    inline std::vector<byte> base64_decode(const std::string& encoded_string) {
        int in_len = encoded_string.size();
        int i = 0, j = 0, in_ = 0;
        unsigned char char_array_4[4], char_array_3[3];
        std::vector<unsigned char> ret;

        while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
            char_array_4[i++] = encoded_string[in_]; in_++;
            if (i == 4) {
                for (i = 0; i < 4; i++)
                    char_array_4[i] = base64_chars.find(char_array_4[i]);

                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (i = 0; (i < 3); i++)
                    ret.push_back(char_array_3[i]);
                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 4; j++)
                char_array_4[j] = 0;

            for (j = 0; j < 4; j++)
                char_array_4[j] = base64_chars.find(char_array_4[j]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
        }

        return ret;
    }
#endif