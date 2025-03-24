#include "TlsSession.h"
#include "TlsRecords.h"

//-----Crypto-----
void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    abort();
}
//-----CertificateSignature------//
int Signature_ECDSA_SHA256(const byte *data, size_t data_len, std::vector<byte>& signature, size_t& signature_len, const char *private_key_file) {
    // Load the private key
    FILE *key_file = fopen(private_key_file, "r");
    if (!key_file) {
        perror("Error opening private key file");
        return 0;
    }

    EVP_PKEY *private_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);

    if (!private_key) {
        handle_openssl_error();
        return 0;
    }

    // Create the signing context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        handle_openssl_error();
        EVP_PKEY_free(private_key);
        return 0;
    }

    // Initialize the signing operation
    if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, private_key)) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(private_key);
        return 0;
    }

    // Provide the data to be signed
    if (1 != EVP_DigestSignUpdate(mdctx, data, data_len)) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(private_key);
        return 0;
    }

    // Determine the size of the signature
    signature_len = 0; // Reset signature length
    if (1 != EVP_DigestSignFinal(mdctx, NULL, &signature_len)) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(private_key);
        return 0;
    }

    // Resize the vector to hold the signature
    signature.resize(signature_len);

    // Create the signature
    if (1 != EVP_DigestSignFinal(mdctx, signature.data(), &signature_len)) {
        handle_openssl_error();
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(private_key);
        return 0;
    }

    // Resize the signature vector to the actual size
    signature.resize(signature_len);

    // Clean up
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(private_key);

    return 1; // Success
}
int Signature_RSA_SHA256(const byte *data, size_t data_len, std::vector<byte>& signature, size_t& signature_len, const char *private_key_file) {
    // Load the private key from the PEM file
    FILE *key_file = fopen(private_key_file, "r");
    if (!key_file) {
        std::cerr << "Error opening private key file: " << private_key_file << std::endl;
        return 0;
    }

    // Read the RSA private key
    RSA *rsa_privkey = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);

    if (!rsa_privkey) {
        std::cerr << "Error reading private key from file." << std::endl;
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // Initialize a context for SHA-256 digest
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        std::cerr << "Failed to create digest context." << std::endl;
        RSA_free(rsa_privkey);
        return 0;
    }

    // Initialize the signing operation using SHA-256
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_RSA(pkey, rsa_privkey) <= 0) {
        std::cerr << "Failed to assign RSA key to EVP_PKEY." << std::endl;
        EVP_MD_CTX_free(mdctx);
        RSA_free(rsa_privkey);
        return 0;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        std::cerr << "Failed to initialize digest for signing." << std::endl;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // Update the context with the data to sign
    if (EVP_DigestSignUpdate(mdctx, data, data_len) <= 0) {
        std::cerr << "Failed to update digest with data." << std::endl;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // Determine the size of the signature
    if (EVP_DigestSignFinal(mdctx, NULL, &signature_len) <= 0) {
        std::cerr << "Failed to finalize digest sign and calculate signature length." << std::endl;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // Ensure that the signature length is valid
    if (signature_len > 0) {
        signature.resize(signature_len);
    } else {
        std::cerr << "Invalid signature length." << std::endl;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    // Sign the data and store the signature in the vector
    if (EVP_DigestSignFinal(mdctx, signature.data(), &signature_len) <= 0) {
        std::cerr << "Failed to finalize the signature." << std::endl;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // Resize the signature vector to the actual size
    signature.resize(signature_len);

    // Cleanup
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    return 1; // Success
}
//------HASH Functions------//
int ComputeSHA256(const std::vector<unsigned char>& data, unsigned char hash[32]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();  // Create new context
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);  // Initialize SHA-256
    EVP_DigestUpdate(ctx, data.data(), data.size());  // Update with input data
    EVP_DigestFinal_ex(ctx, hash, nullptr);  // Finalize and write the result
    EVP_MD_CTX_free(ctx);  // Clean up

    return 0;
}
//------EncryptionFunctions-----//
int Decrypt_AES_128_CBC(std::vector<byte>& data, byte key[16], byte iv[16], std::vector<byte>& plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;

    // Initialize the decryption operation
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    // Resize the plaintext vector to hold decrypted data
    plaintext.resize(data.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));

    // Decrypt the data
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, data.data(), data.size());
    plaintext_len = len;

    // Finalize decryption (handles padding)
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Resize plaintext to the actual decrypted length
    plaintext.resize(plaintext_len);

    return plaintext_len;
}
int Encrypt_AES_128_CBC_HMAC(RecordCode record_code, std::vector<byte>& data, byte key[16], byte iv[16], byte mac_key[20], std::vector<byte>& ciphertext) {
    // std::vector<byte> tmpData = {0x14,0x00,0x00,0x0c,0x84,0x4d,0x3c,0x10,0x74,0x6d,0xd7,0x22,0xf9,0x2f,0x0c,0x7e};
    // std::memcpy(data.data(), tmpData.data(), 16);
    // byte tmpKey[16] = {0x75,0x2a,0x18,0xe7,0xa9,0xfc,0xb7,0xcb,0xcd,0xd8,0xf9,0x8d,0xd8,0xf7,0x69,0xeb};
    // std::memcpy(key, tmpKey, 16);
    // byte tmpIV[16] = {0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60};
    // std::memcpy(iv, tmpIV, 16);
    // byte tmpMacKey[20] = {0x2a,0xd8,0xbd,0xd8,0xc6,0x01,0xa6,0x17,0x12,0x6f,0x63,0x54,0x0e,0xb2,0x09,0x06,0xf7,0x81,0xfa,0xd2};
    // std::memcpy(mac_key, tmpMacKey, 20);
    
    // Step 1: Prepare the data to calculate HMAC
    std::vector<unsigned char> sequence = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // 8-byte sequence
    if(record_code == 0x17) sequence[7] = 0x01;
    std::vector<unsigned char> rechdr;
    rechdr.push_back(static_cast<byte>(record_code));
    rechdr.push_back(static_cast<byte>(0x03));
    rechdr.push_back(static_cast<byte>(0x03));
    //std::cout << "rechdr = " << to_hex(rechdr) << std::endl;
    const std::vector<unsigned char> datalen = {
        static_cast<unsigned char>((data.size() >> 8) & 0xFF), 
        static_cast<unsigned char>(data.size() & 0xFF)
    };
    //std::cout << "datalen = " << to_hex(datalen) << std::endl;

    // Concatenate all parts for HMAC calculation: sequence || rechdr || datalen || data
    std::vector<unsigned char> hmac_input;
    hmac_input.insert(hmac_input.end(), sequence.begin(), sequence.end());
    hmac_input.insert(hmac_input.end(), rechdr.begin(), rechdr.end());
    hmac_input.insert(hmac_input.end(), datalen.begin(), datalen.end());
    hmac_input.insert(hmac_input.end(), data.begin(), data.end());

    // Step 2: Calculate HMAC-SHA1
    unsigned char mac[20];
    unsigned int mac_len;
    HMAC_CTX* hmac_ctx = HMAC_CTX_new();
    if (!HMAC_Init_ex(hmac_ctx, mac_key, 20, EVP_sha1(), NULL) ||
        !HMAC_Update(hmac_ctx, hmac_input.data(), hmac_input.size()) ||
        !HMAC_Final(hmac_ctx, mac, &mac_len)) {
        HMAC_CTX_free(hmac_ctx);
        throw std::runtime_error("HMAC calculation failed");
    }
    HMAC_CTX_free(hmac_ctx);

    //std::cout << "MAC: " << to_hex(mac, 20) << std::endl;
    // Step 3: Append MAC to data
    data.insert(data.end(), mac, mac + 20);

    // Step 4: Add padding (PKCS7 style)
    //std::cout << "Data size: " << data.size() << std::endl;
    size_t padding_length = 16 - (data.size() % 16);
    //std::cout << "padding: " << padding_length << std::endl;
    data.insert(data.end(), ++padding_length, static_cast<unsigned char>(--padding_length));


    //std::cout << "Data: " << to_hex(data) << std::endl;
    // Step 5: Encrypt using AES-128-CBC
    ciphertext.resize(data.size());
    int out_len1 = 0, out_len2 = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) ||
        !EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len1, data.data(), data.size()) ||
        !EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len1, &out_len2)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed");
    }

    ciphertext.resize(out_len1 + out_len2);
    EVP_CIPHER_CTX_free(ctx);

    //std::cout << "Data before encryption: " << to_hex(data) << std::endl;
    //std::cout << "Padding length: " << padding_length << std::endl;

    // After encryption
    //std::cout << "Ciphertext size: " << ciphertext.size() << std::endl;
    //std::cout << "out_len1: " << out_len1 << ", out_len2: " << out_len2 << std::endl;
    //std::cout << "Ciphertext: " << to_hex(ciphertext) << std::endl;

    return 0; // Success
}
//-----KeyDerivation-----//
std::vector<unsigned char> hmac_sha256(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data) {
    std::vector<unsigned char> result(SHA256_DIGEST_LENGTH);
    unsigned int len = 0;
    HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(), result.data(), &len);
    return result;
}
int FirstKeyDerivation(byte PreMasterSecret[32], byte MasterSecretArray[32], HandsahkeVariables handshakeVariables){
    //Example
        //byte tempClientRandom[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
        //std::memcpy(handshakeVariables.clientRandom, tempClientRandom, 32);
        //byte tempServerRandom[32] = {0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};
        //std::memcpy(handshakeVariables.serverRandom, tempServerRandom, 32);

    // Seed = "master secret" + client_random + server_random
    std::vector<unsigned char> seed = {'m', 'a', 's', 't', 'e', 'r', ' ', 's', 'e', 'c', 'r', 'e', 't'};
    seed.insert(seed.end(), handshakeVariables.clientRandom, handshakeVariables.clientRandom + 32);
    seed.insert(seed.end(), handshakeVariables.serverRandom, handshakeVariables.serverRandom + 32);
    // a0 = seed
    std::vector<unsigned char> a0 = seed;
    // a1 = HMAC-SHA256(PreMasterSecret, a0)
    std::vector<unsigned char> a1 = hmac_sha256(std::vector<unsigned char>(PreMasterSecret, PreMasterSecret + 32), a0);
    // a2 = HMAC-SHA256(PreMasterSecret, a1)
    std::vector<unsigned char> a2 = hmac_sha256(std::vector<unsigned char>(PreMasterSecret, PreMasterSecret + 32), a1);
    // p1 = HMAC-SHA256(PreMasterSecret, a1 + seed)
    std::vector<unsigned char> a1_seed = concatenate(a1, seed);
    std::vector<unsigned char> p1 = hmac_sha256(std::vector<unsigned char>(PreMasterSecret, PreMasterSecret + 32), a1_seed);
    // p2 = HMAC-SHA256(PreMasterSecret, a2 + seed)
    std::vector<unsigned char> a2_seed = concatenate(a2, seed);
    std::vector<unsigned char> p2 = hmac_sha256(std::vector<unsigned char>(PreMasterSecret, PreMasterSecret + 32), a2_seed);
    // MasterSecret = p1[all 32 bytes] + p2[first 16 bytes]
    std::vector<unsigned char> MasterSecret(48);
    std::memcpy(MasterSecret.data(), p1.data(), 32);
    std::memcpy(MasterSecret.data() + 32, p2.data(), 16);

    // Convert MasterSecret Vector to byte array
    std::memcpy(MasterSecretArray, MasterSecret.data(), 48);

    return 1;
}
int SecondKeyDerivation(byte MasterSecret[48], HandsahkeVariables handshakeVariables, EncryptionKeys* encKeys){
    //Example
        //byte tempClientRandom[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
        //std::memcpy(handshakeVariables.clientRandom, tempClientRandom, 32);
        //byte tempServerRandom[32] = {0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};
        //std::memcpy(handshakeVariables.serverRandom, tempServerRandom, 32);
    
    // Seed = "master secret" + server_random + client_random
    std::vector<unsigned char> seed = {'k', 'e', 'y', ' ', 'e', 'x', 'p', 'a', 'n', 's', 'i', 'o', 'n'};
    seed.insert(seed.end(), handshakeVariables.serverRandom, handshakeVariables.serverRandom + 32);
    seed.insert(seed.end(), handshakeVariables.clientRandom, handshakeVariables.clientRandom + 32);
    // a0 = seed
    std::vector<unsigned char> a0 = seed;
    // a1 = HMAC-SHA256(MasterSecret, a0)
    std::vector<unsigned char> a1 = hmac_sha256(std::vector<unsigned char>(MasterSecret, MasterSecret + 48), a0);
    // a2 = HMAC-SHA256(MasterSecret, a1)
    std::vector<unsigned char> a2 = hmac_sha256(std::vector<unsigned char>(MasterSecret, MasterSecret + 48), a1);
    // a3 = HMAC-SHA256(MasterSecret, a2)
    std::vector<unsigned char> a3 = hmac_sha256(std::vector<unsigned char>(MasterSecret, MasterSecret + 48), a2);
    // a4 = HMAC-SHA256(MasterSecret, a3)
    std::vector<unsigned char> a4 = hmac_sha256(std::vector<unsigned char>(MasterSecret, MasterSecret + 48), a3);

    // p1 = HMAC-SHA256(MasterSecret, a1 + seed)
    std::vector<unsigned char> a1_seed = concatenate(a1, seed);
    std::vector<unsigned char> p1 = hmac_sha256(std::vector<unsigned char>(MasterSecret, MasterSecret + 48), a1_seed);
    // p2 = HMAC-SHA256(MasterSecret, a2 + seed)
    std::vector<unsigned char> a2_seed = concatenate(a2, seed);
    std::vector<unsigned char> p2 = hmac_sha256(std::vector<unsigned char>(MasterSecret, MasterSecret + 48), a2_seed);
    // p3 = HMAC-SHA256(MasterSecret, a3 + seed)
    std::vector<unsigned char> a3_seed = concatenate(a3, seed);
    std::vector<unsigned char> p3 = hmac_sha256(std::vector<unsigned char>(MasterSecret, MasterSecret + 48), a3_seed);
    // p4 = HMAC-SHA256(MasterSecret, a4 + seed)
    std::vector<unsigned char> a4_seed = concatenate(a4, seed);
    std::vector<unsigned char> p4 = hmac_sha256(std::vector<unsigned char>(MasterSecret, MasterSecret + 48), a4_seed);

    std::vector<unsigned char> p;
    p.insert(p.end(), p1.begin(), p1.end());
    p.insert(p.end(), p2.begin(), p2.end());
    p.insert(p.end(), p3.begin(), p3.end());
    p.insert(p.end(), p4.begin(), p4.end());

    // Copy the first 20 bytes to clientMACkey
    std::memcpy(encKeys->clientMACkey, p.data(), 20);
    // Copy the next 20 bytes to serverMACkey
    std::memcpy(encKeys->serverMACkey, p.data() + 20, 20);
    // Copy the next 16 bytes to clientWRITEkey
    std::memcpy(encKeys->clientWRITEkey, p.data() + 40, 16);
    // Copy the next 16 bytes to serverWRITEkey
    std::memcpy(encKeys->serverWRITEkey, p.data() + 56, 16);
    // Copy the next 16 bytes to clientIV
    std::memcpy(encKeys->clientIV, p.data() + 72, 16);
    // Copy the next 16 bytes to serverIV
    std::memcpy(encKeys->serverIV, p.data() + 88, 16);

    
    // Output extracted values in hex
    // std::cout << "Client Write MAC Key: " << to_hex(encKeys->clientMACkey, 20) << std::endl;
    // std::cout << "Server Write MAC Key: " << to_hex(encKeys->serverMACkey, 20) << std::endl;
    // std::cout << "Client Write Key: " << to_hex(encKeys->clientWRITEkey, 16) << std::endl;
    // std::cout << "Server Write Key: " << to_hex(encKeys->serverWRITEkey, 16) << std::endl;
    // std::cout << "Client Write IV: " << to_hex(encKeys->clientIV, 16) << std::endl;
    // std::cout << "Server Write IV: " << to_hex(encKeys->serverIV, 16) << std::endl;
    
    return 0;
}
//-----ServerVerifyData-----//
int ServerVerifyData(byte HandshakeSHA256[32], byte MasterSecret[48], byte VerifyData[12]){
    std::vector<unsigned char> seed = {'s', 'e', 'r', 'v', 'e', 'r', ' ', 'f', 'i', 'n', 'i', 's', 'h', 'e', 'd'};
    seed.insert(seed.end(), HandshakeSHA256, HandshakeSHA256 + 32);
    // a0 = seed
    std::vector<unsigned char> a0 = seed;
    // a1 = HMAC-SHA256(MasterSecret, a0)
    std::vector<unsigned char> a1 = hmac_sha256(std::vector<unsigned char>(MasterSecret, MasterSecret + 48), a0);
    // p1 = HMAC-SHA256(MasterSecret, a1 + seed)
    std::vector<unsigned char> a1_seed = concatenate(a1, seed);
    std::vector<unsigned char> p1 = hmac_sha256(std::vector<unsigned char>(MasterSecret, MasterSecret + 48), a1_seed);
    std::memcpy(VerifyData, p1.data(), 12);
    return 0;
}