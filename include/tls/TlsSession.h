#ifndef TLSSESSION
    #define TLSSESSION
    //Acceptor libs
        #include "standard/StandardHeader.h"
        #include "libs/AsioHeader.h"
        #include "TlsRecords.h"
        #include "libs/curve25519.h"
        #include "libs/OpensslHeader.h"

    struct HandsahkeVariables{
        byte clientRandom[32];
        byte serverRandom[32];
        byte serverPublicKey[32];
        byte serverPrivateKey[32];
        byte clientPublicKey[32];
        byte masterSecret[48];
        byte serverVerifyData[12];
        //The HandshakeMessagge is composed of the handshake data and header of:
        //(clientHello, serverHello, serverCert, serverKeyExchange, serverHelloDone, clientKeyExchange, clientHelloDone decrypted data)
        std::vector<byte> allHandshakeMessages;
    };

    struct EncryptionKeys{
        byte clientMACkey[20];
        byte serverMACkey[20];
        byte clientWRITEkey[16];
        byte serverWRITEkey[16];
        byte clientIV[16];
        byte serverIV[16];
    };
    #include "EncFunctions.h"

    class TlsSession : public std::enable_shared_from_this<TlsSession> {
    public:
        //-----TlsSession-----//
        u_int64_t sessionNumber;
        //-----PrivateKey-----//
        char* prikey_path = "/home/pietrobattocchio/IWsServer/cert/privkey.pem";
        //-----Socket and Buffer------//
        std::error_code ec;
        tcp::socket socket_;
        asio::streambuf requestBuffer_;
        //-----HandshakeVariables-----//
        bool clientChangeCipher = false;
        bool isHandshakeDone = false;
        HandsahkeVariables HandshakeVar;
        HandsahkeVariables* tempHandshakeVariables;

        //-----Encryption Keys------//
        int (*Signature_function)(const byte*, size_t, std::vector<byte>&, size_t&, const char*) = nullptr;
        int (*Encrypt_function)(RecordCode record_code, std::vector<byte>& data, byte key[16], byte iv[16], byte mac_key[20], std::vector<byte>& ciphertext) = nullptr;
        int (*Decrypt_function)(std::vector<byte>& data, byte key[16], byte iv[16], std::vector<byte>& plaintext) = nullptr;
        EncryptionKeys encKeys;

        //-----TlsRecordManager-----//
        void RecordManager(byte data[5]){
            RecordHeader RecordHeader_(data);
            switch(RecordHeader_.RecordCode_){
                case RecordCode::Handshake:
                    if(clientChangeCipher) HandshakeHandler_ClientHandshakeFinished(RecordHeader_.RecordHeader_Length);
                    else HandshakeManager(this->SYNC_ReadBytes(4));
                    break;
                case RecordCode::ChangeCipherSpec:
                    //std::cout << "---ChangeCipherSpec lenght: " << RecordHeader_.RecordHeader_Length << "---" << std::endl;
                    ClientChangeCipherSpec(this->SYNC_ReadBytes(1));
                    break;
                case RecordCode::ApplicationData:
                    //std::cout << "---ApplicationData lenght: " << RecordHeader_.RecordHeader_Length << "---" << std::endl;
                    ApplicatonDataClient(this->SYNC_ReadBytes(static_cast<int>(RecordHeader_.RecordHeader_Length)));
                    break;
                case RecordCode::Alert:
                    break;
                default:
                    break;
            }
        }

        //-----CipherSuitManager-----//
        CipherSuites CipherSuiteChooser(std::vector<byte> ciphers){
            //Implement the choosing function:
            return TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
        }
        void CipherSuiteSetter(CipherSuites cipher, SignAlgorithem& sigAlgo){
            switch(cipher){
                case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
                    prikey_path = "/home/pietrobattocchio/IWsServer/cert/ECDSA/privkey.pem";
                    sigAlgo = ECDSA_SHA256;
                    Signature_function = &Signature_ECDSA_SHA256;
                    Encrypt_function = Encrypt_AES_128_CBC_HMAC;
                    Decrypt_function = Decrypt_AES_128_CBC;
                    break;
                case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
                    prikey_path = "/home/pietrobattocchio/IWsServer/cert/RSA/privkey.pem";
                    sigAlgo = RSA_SHA256;
                    Signature_function = Signature_RSA_SHA256;
                    Encrypt_function = Encrypt_AES_128_CBC_HMAC;
                    Decrypt_function = Decrypt_AES_128_CBC;
                    break;
            }
        }

        //-----TlsHandshakeManger-----//
        //Client
        void HandshakeManager(std::vector<byte>HandshakeData){
            HandshakeHeader HandshakeHeader_(HandshakeData);
            switch(HandshakeHeader_.HandshakeCode_){
                case HandshakeCode::ClientHelloCode:
                    //Insert the ClientHello HanshakeHeader
                    tempHandshakeVariables->allHandshakeMessages.insert(tempHandshakeVariables->allHandshakeMessages.end(), std::begin(HandshakeData), std::end(HandshakeData));
                    HandshakeHandler_ClientHello(HandshakeHeader_.HandshakeHeader_Length);
                    break;
                case HandshakeCode::ClientKeyExchangeCode:
                    //Insert the ClientKeyExchange HandshakeHeader
                    tempHandshakeVariables->allHandshakeMessages.insert(tempHandshakeVariables->allHandshakeMessages.end(), std::begin(HandshakeData), std::end(HandshakeData));
                    HandshakeHandler_ClientKeyExchange(HandshakeHeader_.HandshakeHeader_Length);
                    break;
                default:
                    break;
            }
        }
        void HandshakeHandler_ClientHello(uint32_t lenght){
            std::cout << "[CLIENT " << sessionNumber << "] ClientHello Received" << std::endl;
            std::vector<byte> buffer = this->SYNC_ReadBytes(lenght);
            clientChangeCipher = false;
            
            std::cout << "Problem in the pointer" << std::endl;
            //Insert the client hello into the all Handshake
            tempHandshakeVariables->allHandshakeMessages.insert(tempHandshakeVariables->allHandshakeMessages.end(), std::begin(buffer), std::end(buffer));

            //Get the clientRandom
            ClientHello ClientHello_(buffer);
            std::memcpy(tempHandshakeVariables->clientRandom, ClientHello_.ClientRandom_, 32 * sizeof(byte));
            //Generate the serverRandom
            GenerateRandomBytes(tempHandshakeVariables->serverRandom, 32);
            //Chose and set the cipherSuite
            //###TODO takeciphersuites
            std::vector<byte> clientCipher;
            SignAlgorithem chosenSign;
            CipherSuites chosenCipher = CipherSuiteChooser(clientCipher);
            CipherSuiteSetter(chosenCipher, chosenSign);
            std::cout << "[CLIENT] ChipherChosen" << std::endl;
            //Generate all the FirstSend messages
            std::vector<byte> server_hello_bytes = HandshakeHandler_ServerHello(chosenCipher);
            tempHandshakeVariables->allHandshakeMessages.insert(tempHandshakeVariables->allHandshakeMessages.end(), std::begin(server_hello_bytes)+5, std::end(server_hello_bytes));
            std::vector<byte> server_certificate_bytes = HandshakeHandler_ServerCertificate();
            tempHandshakeVariables->allHandshakeMessages.insert(tempHandshakeVariables->allHandshakeMessages.end(), std::begin(server_certificate_bytes)+5, std::end(server_certificate_bytes));
            std::vector<byte> server_keyexchange_bytes = HandshakeHandler_ServerKeyExchange(chosenSign);
            tempHandshakeVariables->allHandshakeMessages.insert(tempHandshakeVariables->allHandshakeMessages.end(), std::begin(server_keyexchange_bytes)+5, std::end(server_keyexchange_bytes));
            std::vector<byte> server_serverhellodone_bytes = HandshakeHandler_ServerHelloDone();
            tempHandshakeVariables->allHandshakeMessages.insert(tempHandshakeVariables->allHandshakeMessages.end(), std::begin(server_serverhellodone_bytes)+5, std::end(server_serverhellodone_bytes));

            //Merge all the messages and send
            std::vector<byte> firstSend(server_hello_bytes);
            firstSend.insert(firstSend.end(), std::begin(server_certificate_bytes), std::end(server_certificate_bytes));
            firstSend.insert(firstSend.end(), std::begin(server_keyexchange_bytes), std::end(server_keyexchange_bytes));
            firstSend.insert(firstSend.end(), std::begin(server_serverhellodone_bytes), std::end(server_serverhellodone_bytes));
            std::cout << "[SERVER] Sending ServerHello,ServerCertificate,ServerHelloDone" << std::endl;
            this->ASYNC_Write(firstSend);
            
            //Enqueue the next read
            this->ASYNC_ReadRecordHeader();
        }
        void HandshakeHandler_ClientKeyExchange(uint32_t lenght){
            std::cout << "[CLIENT " << sessionNumber << "] ClientKeyExchange Received" << std::endl;
            std::vector<byte> buffer = this->SYNC_ReadBytes(lenght);
            //Insert the ClientKeyExchange
            tempHandshakeVariables->allHandshakeMessages.insert(tempHandshakeVariables->allHandshakeMessages.end(), std::begin(buffer), std::end(buffer));
            buffer.erase(buffer.begin());
            std::memcpy(tempHandshakeVariables->clientPublicKey, buffer.data(), 32);

            //std::cout << "Client Key: " << to_hex(tempHandshakeVariables->clientPublicKey, 32) << std::endl;
            this->ASYNC_ReadRecordHeader();
        }
        void HandshakeHandler_ClientHandshakeFinished(uint32_t lenght){
            std::cout << "[CLIENT " << sessionNumber << "] ClientHandshakeFinished Received" << std::endl;
            std::vector<byte> buffer = this->SYNC_ReadBytes(lenght);

            HandshakeHandler_ServerEncryptionKeysCalculation();

            //Decypt the ClientHandshakeFinished
            //Try Decrypt:
            // std::vector<byte> encData = {0x22,0x7b,0xc9,0xba,0x81,0xef,0x30,0xf2,0xa8,0xa7,0x8f,0xf1,0xdf,0x50,0x84,0x4d,0x58,0x04,0xb7,0xee,0xb2,0xe2,0x14,0xc3,0x2b,0x68,0x92,0xac,0xa3,0xdb,0x7b,0x78,0x07,0x7f,0xdd,0x90,0x06,0x7c,0x51,0x6b,0xac,0xb3,0xba,0x90,0xde,0xdf,0x72,0x0f};
            // std::vector<byte> decData;
            // byte IV[16] = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f};
            // byte Key[16] = {0xf6,0x56,0xd0,0x37,0xb1,0x73,0xef,0x3e,0x11,0x16,0x9f,0x27,0x23,0x1a,0x84,0xb6};
            // Decrypt_AES_128_CBC(encData, Key, IV,decData);
            // decData.resize(16);
            // tempHandshakeVariables->allHandshakeMessages.insert(tempHandshakeVariables->allHandshakeMessages.end(), std::begin(decData), std::end(decData));
            // std::cout << "Dec Data:" << to_hex(decData) << std::endl;
            // std::cout << "Data to Hash:" << to_hex(tempHandshakeVariables->allHandshakeMessages)<< std::endl;
            ClientHandshakeFinished clientHandshakeDone_(buffer);
            std::vector<byte> decData;
            Decrypt_AES_128_CBC(clientHandshakeDone_.EncryptedData, encKeys.clientWRITEkey, clientHandshakeDone_.EncryptionIV, decData);
            decData.resize(16);
            std::cout << "Dec from client:" << to_hex(decData) << std::endl;
            tempHandshakeVariables->allHandshakeMessages.insert(tempHandshakeVariables->allHandshakeMessages.end(), std::begin(decData), std::end(decData));
            
            //std::cout << "Data to Hash:" << to_hex(tempHandshakeVariables->allHandshakeMessages)<< std::endl;
            byte sha256Handshake[32];
            ComputeSHA256(tempHandshakeVariables->allHandshakeMessages, sha256Handshake);
            ServerVerifyData(sha256Handshake, tempHandshakeVariables->masterSecret, tempHandshakeVariables->serverVerifyData);
            
            std::vector<byte> serverChangeCipher_bytes = ServerChangeCipherSpec();
            std::vector<byte> serverHandshakeFinished_bytes = HandshakeHandler_ServerHandshakeFinished();

            std::vector<byte> secondSend(serverChangeCipher_bytes);
            secondSend.insert(secondSend.end(), serverHandshakeFinished_bytes.begin(), serverHandshakeFinished_bytes.end());

            std::cout << "[SERVER] Sending ChangeCipher,ServerHandshakeFinished" << std::endl;
            this->ASYNC_Write(secondSend);
            //std::cout << "---SUCCESS---" << std::endl;

            this->ASYNC_ReadRecordHeader();
        }

        //Server
        std::vector<byte> HandshakeHandler_ServerHello(CipherSuites chosenCipher){
            //Generate the ServerHello
            ServerHello ServerHello_(chosenCipher);
            //Fill the ServerRandom
            std::memcpy(ServerHello_.ServerRandom_, tempHandshakeVariables->serverRandom, 32 * sizeof(byte));

            return ServerHello_.GetData();
        }
        std::vector<byte> HandshakeHandler_ServerCertificate(){
            //Generate the ServerCertificate
            ServerCertificate ServerCertificate_;

            return ServerCertificate_.GetData();
        }
        int HandhsakeHandler_ServerKeyGeneration(byte *public_key_, byte *private_key_){
            EVP_PKEY_CTX *pctx = NULL;
            EVP_PKEY *pkey = NULL;
            byte public_key[32], private_key[32];
            size_t public_key_len = sizeof(public_key);
            size_t private_key_len = sizeof(private_key);

            // Create context for key generation
            pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
            if (!pctx) {
                fprintf(stderr, "Error: EVP_PKEY_CTX_new_id failed\n");
                ERR_print_errors_fp(stderr);
                return 1;
            }

            // Generate the key pair
            if (EVP_PKEY_keygen_init(pctx) <= 0) {
                fprintf(stderr, "Error: EVP_PKEY_keygen_init failed\n");
                ERR_print_errors_fp(stderr);
                EVP_PKEY_CTX_free(pctx);
                return 1;
            }

            if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
                fprintf(stderr, "Error: EVP_PKEY_keygen failed\n");
                ERR_print_errors_fp(stderr);
                EVP_PKEY_CTX_free(pctx);
                return 1;
            }

            // Extract the public key
            if (EVP_PKEY_get_raw_public_key(pkey, public_key, &public_key_len) <= 0) {
                fprintf(stderr, "Error: EVP_PKEY_get_raw_public_key failed\n");
                ERR_print_errors_fp(stderr);
                EVP_PKEY_free(pkey);
                EVP_PKEY_CTX_free(pctx);
                return 1;
            }

            // Extract the private key
            if (EVP_PKEY_get_raw_private_key(pkey, private_key, &private_key_len) <= 0) {
                fprintf(stderr, "Error: EVP_PKEY_get_raw_private_key failed\n");
                ERR_print_errors_fp(stderr);
                EVP_PKEY_free(pkey);
                EVP_PKEY_CTX_free(pctx);
                return 1;
            }

            //Return the value of the key pair
            std::memcpy(public_key_, public_key, 32 * sizeof(byte));
            std::memcpy(private_key_, private_key, 32 * sizeof(byte));

            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(pctx);
            return 0;
        }
        std::vector<byte> HandshakeHandler_ServerKeyExchange(SignAlgorithem signAlgo){
            //Generate Server key pair x25519
            if (HandhsakeHandler_ServerKeyGeneration(tempHandshakeVariables->serverPublicKey, tempHandshakeVariables->serverPrivateKey) != 0) {
                std::cerr << "Error Generating the keys" << std::endl;
            } else {
                //std::cout << "Keys Generated" << std::endl;
            }

            //Merge the data to sign (clientRandom, serverRandom, cureInfo, serverPublicKey)
            std::vector<byte> data;
            data.insert(data.end(), std::begin(tempHandshakeVariables->clientRandom), std::end(tempHandshakeVariables->clientRandom));
            data.insert(data.end(), std::begin(tempHandshakeVariables->serverRandom), std::end(tempHandshakeVariables->serverRandom));
            data.push_back(0x03);
            data.push_back(0x00);
            data.push_back(0x1d);
            data.push_back(0x20);
            data.insert(data.end(), std::begin(tempHandshakeVariables->serverPublicKey), std::end(tempHandshakeVariables->serverPublicKey));

            size_t data_len = data.size();
            std::vector<byte> dataToSign(data.begin(), data.end());

            /*
            std::vector<byte> ClientRand(client_random_, client_random_ + 32);
            std::vector<byte> ServerRand(server_random_, server_random_ + 32);
            std::vector<byte> PublicKey(public_key, public_key + 32);
            std::vector<byte> CurveInfo({0x03, 0x00, 0x1d, 0x20});
            
            std::cout << "ClientRandom: " << to_hex(ClientRand) << std::endl;
            std::cout << "ServerRandom: " << to_hex(ServerRand) << std::endl;
            std::cout << "CurveInfo: " << to_hex(CurveInfo) << std::endl;
            std::cout << "PublicKey: " << to_hex(PublicKey) << std::endl;
            std::cout << "Data to sign: " << to_hex(data) << std::endl;
            */

            // Prepare for signature
            std::vector<byte> signature(256);
            size_t signature_len;
            Signature_function(dataToSign.data(), data_len, signature, signature_len, prikey_path);
            //std::cout << "Signature: " << to_hex(std::vector<byte>(signature.begin(), signature.begin() + signature_len)) << std::endl;
            
            // Prepare and return the ServerKeyExchange data
            ServerKeyExchange ServerKeyExchange_(signAlgo, tempHandshakeVariables->serverPublicKey, signature_len, signature);
            return ServerKeyExchange_.GetData();
        }
        std::vector<byte> HandshakeHandler_ServerHelloDone(){
            ServerHelloDone ServerHelloDone_;
            return ServerHelloDone_.GetData();
        }
        int HandshakeHandler_ServerEncryptionKeysCalculation(){
            // Key Exchange context
            //Example
                //byte tempClientPublicKey[32] = {0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54};
                //std::memcpy(tempHandshakeVariables->clientPublicKey, tempClientPublicKey, 32);
                //byte tempServerPrivateKey[32] = {0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
                //std::memcpy(tempHandshakeVariables->serverPrivateKey, tempServerPrivateKey, 32);

            byte PreMasterSecret[32];

            // Calculate the PreMasterSecret
            curve25519_donna(PreMasterSecret, tempHandshakeVariables->serverPrivateKey, tempHandshakeVariables->clientPublicKey);
            //std::cout << "Shared Secret: " << to_hex(std::vector<unsigned char>(PreMasterSecret, PreMasterSecret + 32)) << std::endl;

            byte MasterSecret[48];
            FirstKeyDerivation(PreMasterSecret, MasterSecret, *tempHandshakeVariables);
            // Output MasterSecret in hex
            //std::cout << "Master Secret: " << to_hex(MasterSecret, 48) << std::endl;
            SecondKeyDerivation(MasterSecret, *tempHandshakeVariables, &encKeys);
            std::memcpy(tempHandshakeVariables->masterSecret, MasterSecret, 48);

            return 0;
        }
        std::vector<byte> HandshakeHandler_ServerHandshakeFinished(){
            byte IV[16];
            RAND_bytes(IV, 16);
            //std::cout << "IV: " << to_hex(IV, 16) << std::endl;

            std::vector<byte> dataToEnc = {0x14,0x00,0x00,0x0c};
            dataToEnc.insert(dataToEnc.end(), tempHandshakeVariables->serverVerifyData, tempHandshakeVariables->serverVerifyData + 12);
            //std::cout << "Data: " << to_hex(dataToEnc) << " lenght: " << dataToEnc.size() <<std::endl;

            std::vector<byte> cipherText;
            Encrypt_AES_128_CBC_HMAC(RecordCode::Handshake, dataToEnc, encKeys.serverWRITEkey, IV, encKeys.serverMACkey, cipherText);
            cipherText.erase(cipherText.end() - 16, cipherText.end());
            //std::cout << "Enc: " << to_hex(cipherText) << std::endl;

            //delete the handshakekeys
            std::cout << "CLIENT[" << sessionNumber << "] Deallocating the tempHandshakeVar" << std::endl;

            ServerHandshakeFinished ServerHandshakeFinished_(IV, cipherText);
            return ServerHandshakeFinished_.GetData();
        }

        //-----TlsChangeCipherSpec-----
        void ClientChangeCipherSpec(std::vector<byte>RecordData){
            std::cout << "[CLIENT " << sessionNumber << "] ClientChangeCipherSpec Received" << std::endl;
            clientChangeCipher = true;
            this->ASYNC_ReadRecordHeader();
        }
        std::vector<byte> ServerChangeCipherSpec(){
            ChangeCipherSpecClass ChangeCipherSpecClass_;
            return ChangeCipherSpecClass_.GetData();
        }

        //-----TlsApplicationData-----
        void ApplicatonDataClient(std::vector<byte>ApplicationData){
            std::cout << "[CLIENT " << sessionNumber << "] Reciving ClientApplicationData" << std::endl;
            ClientApplicationData ClientApplicationData_(ApplicationData);
            //std::cout << "IV from client: " << to_hex(ClientApplicationData_.EncryptionIV, 16) << std::endl;
            //std::cout << "Enc from client: " << to_hex(ClientApplicationData_.EncryptedData) << std::endl;

            std::vector<byte> decData;
            Decrypt_AES_128_CBC(ClientApplicationData_.EncryptedData, encKeys.clientWRITEkey, ClientApplicationData_.EncryptionIV, decData);
            std::string str(decData.begin(), decData.end());
            std::cout << "CLIENT REQUEST: " << std::endl << str << std::endl;
            ApplicatonDataServer();
        }
        void ApplicatonDataServer(){
            //Sending basic Responce
            std::string response = 
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 22\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Benvenuto al FantaProf";

            // Create a vector of bytes containing the entire response
            std::vector<unsigned char> byte_vector(response.begin(), response.end());
            byte IV[16];
            RAND_bytes(IV, 16);
            std::cout << "ByteVector: " << to_hex(byte_vector) << std::endl;
            std::cout << "IV: " << to_hex(IV, 16) << std::endl;
            std::cout << "serverWRITEkey: " << to_hex(encKeys.serverWRITEkey, 16) << std::endl;
            std::cout << "serverMACkey: " << to_hex(encKeys.serverMACkey, 16) << std::endl;

            std::vector<byte> cipherText(1);
            std::cout << "Encrypting:" << std::endl;
            Encrypt_AES_128_CBC_HMAC(RecordCode::ApplicationData, byte_vector, encKeys.serverWRITEkey, IV, encKeys.serverMACkey, cipherText);
            std::cout << "trimming:" << std::endl;
            cipherText.erase(cipherText.end() - 16, cipherText.end());

            //std::cout << "Enc: " << to_hex(cipherText) << std::endl;
            std::cout << "Sending:" << std::endl;
            ServerApplicationData ServerApplicationData_(IV, cipherText);
            this->ASYNC_Write(ServerApplicationData_.GetData());
            this->CloseConnection();
        }

        //-----TcpComunication-----//
        void ASYNC_ReadRecordHeader() {
            auto self(shared_from_this());
            asio::async_read(socket_, requestBuffer_, asio::transfer_exactly(5),
                [this, self](std::error_code ec, std::size_t length) {
                    if (!ec) {
                        byte RecordHeader_[5]; // Array to store 5 bytes
                        // Read directly into RecordHeader_
                        asio::buffer_copy(asio::buffer(RecordHeader_), requestBuffer_.data(), length);
                        // Remove what has been read
                        requestBuffer_.consume(length);
                        RecordManager(RecordHeader_);
                    }
                }
            );
        }
        void ASYNC_ReadBytes(std::size_t bytesToRead) {
            auto self(shared_from_this());
            asio::async_read(socket_, requestBuffer_, asio::transfer_exactly(bytesToRead),
                [this, self](std::error_code ec, std::size_t length) {
                    if (!ec) {
                        //Reading the bytes
                        std::vector<byte> buffer(length);
                        asio::buffer_copy(asio::buffer(buffer), requestBuffer_.data(), length);
                        // Remove what has been read
                        requestBuffer_.consume(length);
                    }
                }
            );
        }
        std::vector<byte> SYNC_ReadBytes(std::size_t bytesToRead) {
            auto self(shared_from_this());
            asio::read(socket_, requestBuffer_, asio::transfer_exactly(bytesToRead));
            std::vector<byte> buffer(bytesToRead);
            asio::buffer_copy(asio::buffer(buffer), requestBuffer_.data(), bytesToRead);
            requestBuffer_.consume(bytesToRead);
            return buffer;
        }
        void ASYNC_Write(std::vector<byte> responce){
            auto self(shared_from_this());
            asio::async_write(socket_, asio::buffer(responce),
                [this, self](std::error_code ec, std::size_t length) {
                    if (!ec){
                        //CloseConnection(ec);
                    }else{
                        std::cerr << "Error writing the response: " << ec.message() << std::endl;
                        CloseConnection();
                    }
                }
            );
        }
        void CloseConnection(){
            socket_.shutdown(tcp::socket::shutdown_both, ec);
            std::cout << "Closing the connection to: " << socket_.remote_endpoint() << std::endl;
            socket_.close();
        }

        //-----Constructor-----//
        TlsSession(tcp::socket socket) 
            : socket_(std::move(socket)) {
        }
        void StartReading(u_int64_t connectionNumber) {
            sessionNumber = connectionNumber;
            std::cout << "Connection[" << sessionNumber << "] from: " << socket_.remote_endpoint() << std::endl;
            //Allocate the tempHandshakeVariables
            tempHandshakeVariables = &HandshakeVar;
            ASYNC_ReadRecordHeader();
        }
        ~TlsSession(){
            std::cout << "DESTROY CLIENT[" << sessionNumber << "]" << std::endl;
        }
    };
#endif