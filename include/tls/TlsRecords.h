//STANDALONE IMPLEMENTATION
#ifndef TLSRECORDS
    #define TLSRECORDS
    #include "standard/StandardHeader.h"
    #include "standard/DataTools.h"
//RECORD ENUMS
enum RecordCode : byte{
    ChangeCipherSpec = 0x14,
    Alert = 0x15,
    Handshake = 0x16,
    ApplicationData = 0x17,
    RecordCode_ERROR = 0xff
};
//HANDSHAKE ENUMS
enum TlsVersion : word{
    Tls10 = 0x0301,
    Tls11 = 0x0302,
    Tls12 = 0x0303,
    Tls13 = 0x0304,
    TlsVersion_ERROR = 0xffff
};
enum HandshakeCode : byte{
    ClientHelloCode = 0x01,
    ServerHelloCode = 0x02,
    ServerCertificateCode = 0x0b,
    ServerKeyExchangeCode = 0x0c,
    ServerHelloDoneCode = 0x0e,
    ClientKeyExchangeCode = 0x10,
    FinishedCode = 0x14,
    HandshakeCode_ERROR = 0xff
};
enum CipherSuites : word{
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xc012,
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c,
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d,
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a,
    CipherSuites_ERROR = 0xffff
};
enum CompressionCode : byte{
    CompressionCode_NULL = 0x00,
    CompressionCode_ERROR = 0xff
};
enum SignAlgorithem : word{
    ECDSA_SHA256 = 0x0403,
    RSA_SHA256 = 0x0401
};

//RECORD
class RecordHeader{
public:
    //Variables
    RecordCode RecordCode_;
    TlsVersion TlsVersion_;
    word RecordHeader_Length;

    //Constructors
    RecordHeader(){};
    RecordHeader(RecordCode RecordCode_, TlsVersion TlsVersion_, word RecordLenght_){
        this->RecordCode_ = RecordCode_;
        this->TlsVersion_ = TlsVersion_;
        this->RecordHeader_Length = RecordLenght_;
    }
    RecordHeader(byte data[5]){
        //RecordCode
        switch(data[0]){
            case RecordCode::ChangeCipherSpec:
                RecordCode_ = RecordCode::ChangeCipherSpec;
                break;
            case RecordCode::Alert:
                RecordCode_ = RecordCode::Alert;
                break;
            case RecordCode::Handshake:
                RecordCode_ = RecordCode::Handshake;
                break;
            case RecordCode::ApplicationData:
                RecordCode_ = RecordCode::ApplicationData;
                break;
            default:
                RecordCode_ = RecordCode::RecordCode_ERROR;
                break;
        }
        //TlsVersion
        switch (bytesToWord(data[1], data[2])){
            case TlsVersion::Tls10:
                TlsVersion_ = TlsVersion::Tls10;
                break;
            case TlsVersion::Tls11:
                TlsVersion_ = TlsVersion::Tls11;
                break;
            case TlsVersion::Tls12:
                TlsVersion_ = TlsVersion::Tls12;
                break;
            case TlsVersion::Tls13:
                TlsVersion_ = TlsVersion::Tls13;
                break;
            default:
                TlsVersion_ = TlsVersion::TlsVersion_ERROR;
                break;
        }
        //RecordLenght
        RecordHeader_Length = bytesToWord(data[3], data[4]);

    }
    
    //Return a vector with all the Data
    std::vector<byte> GetData(){
        std::vector<byte> data;
        //Add the Variables
        data.push_back(static_cast<byte>(RecordCode_)); 
        data.push_back(static_cast<byte>(TlsVersion_ >> 8));  // High byte
        data.push_back(static_cast<byte>(TlsVersion_ & 0xFF)); // Low byte
        data.push_back(static_cast<byte>(RecordHeader_Length >> 8));  // Hight byte
        data.push_back(static_cast<byte>(RecordHeader_Length & 0xFF)); //Low byte
        //Return
        data.shrink_to_fit();
        //std::cout << "RecordHeader_Length: " << RecordHeader_Length << std::endl;
        return data;
    }
};

//HANDSHAKE
class HandshakeHeader : RecordHeader{
public:
    //Base Length
    const u_int32_t Base_HandshakeHeader_Lenght = 4;
    //Variables
    HandshakeCode HandshakeCode_;
    u_int32_t HandshakeHeader_Length = 0;

    //Constructors
    HandshakeHeader(){
        EncapsulateToRecordHeader();
    };
    HandshakeHeader(HandshakeCode HandshakeCode_, u_int32_t HandshakeHeader_Length){
        this->HandshakeCode_ = HandshakeCode_;
        this->HandshakeHeader_Length = HandshakeHeader_Length; 
        EncapsulateToRecordHeader();
    }
    HandshakeHeader(std::vector<byte> data){
        //HandshakeCode
        switch(data[0]){
            case HandshakeCode::ClientHelloCode:
                HandshakeCode_ = HandshakeCode::ClientHelloCode;
                break;
            case HandshakeCode::ServerHelloCode:
                HandshakeCode_ = HandshakeCode::ServerHelloCode;
                break;
            case HandshakeCode::ServerCertificateCode:
                HandshakeCode_ = HandshakeCode::ServerCertificateCode;
                break;
            case HandshakeCode::ServerKeyExchangeCode:
                HandshakeCode_ = HandshakeCode::ServerKeyExchangeCode;
                break;
            case HandshakeCode::ServerHelloDoneCode:
                HandshakeCode_ = HandshakeCode::ServerHelloDoneCode;
                break;
            case HandshakeCode::ClientKeyExchangeCode:
                HandshakeCode_ = HandshakeCode::ClientKeyExchangeCode;
                break;
            case HandshakeCode::FinishedCode:
                HandshakeCode_ = HandshakeCode::FinishedCode;
                break;
            default:
                HandshakeCode_ = HandshakeCode::HandshakeCode_ERROR;
                break;
        }
        //HandshakeLength
        HandshakeHeader_Length = bytesToInt(0, data[1], data[2], data[3]);
        EncapsulateToRecordHeader();
    }

    //Return a vector with all the Data
    std::vector<byte> GetData(){
        std::vector<byte> data;
        //Get the RecordHeader
        std::vector<byte> data1 = RecordHeader::GetData();
        data.insert(data.end(), std::begin(data1), std::end(data1));
        //Add the Variables
        data.push_back(static_cast<byte>(HandshakeCode_)); 
        data.push_back(static_cast<byte>((HandshakeHeader_Length >> 16) & 0xFF)); // 3rd byte
        data.push_back(static_cast<byte>((HandshakeHeader_Length >> 8) & 0xFF));  // 2nd byte
        data.push_back(static_cast<byte>(HandshakeHeader_Length & 0xFF));         // 1st byte
        //Return
        data.shrink_to_fit();
        return data;
    }

    //Encapsulate to RecordHeader
    void EncapsulateToRecordHeader(){
        RecordCode_ = RecordCode::Handshake;
        TlsVersion_ = TlsVersion::Tls12;
        RecordHeader_Length = HandshakeHeader_Length + Base_HandshakeHeader_Lenght;
    }
};
class ClientHello{
public:
    TlsVersion TlsVersion_;
    byte ClientRandom_[32];
    byte SessionID_[1];
  
    ClientHello(std::vector<byte> data){
        //TlsVersion
        switch (bytesToWord(data[0], data[1])){
            case TlsVersion::Tls10:
                TlsVersion_ = TlsVersion::Tls10;
                break;
            case TlsVersion::Tls11:
                TlsVersion_ = TlsVersion::Tls11;
                break;
            case TlsVersion::Tls12:
                TlsVersion_ = TlsVersion::Tls12;
                break;
            case TlsVersion::Tls13:
                TlsVersion_ = TlsVersion::Tls13;
                break;
            default:
                TlsVersion_ = TlsVersion::TlsVersion_ERROR;
                break;
        }
        //ClientRandom
        std::memcpy(ClientRandom_, data.data() + 2, 32);
    }
};
class ServerHello : HandshakeHeader{
public:
    //Base Lengths
    const u_int32_t Base_ServerHello_Length = 45;
    //Variables
    TlsVersion TlsVersion_ = TlsVersion::Tls12;
    byte ServerRandom_[32];
    byte SessionID_ = {0};
    CipherSuites CipherSuites_ = CipherSuites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    CompressionCode CompressionCode_ = CompressionCode_NULL;
    byte ExtensionsLength_[2] = {0x00, 0x05};
    byte RenegotiationInfo_[5] = {0xff, 0x01, 0x00, 0x01, 0x00};

    //Constructors
    ServerHello(CipherSuites CipherSuite){
        //Default Data
        CipherSuites_ = CipherSuite;
        EncapsulateToHandshakeHeader();
    };
    ServerHello(TlsVersion TlsVersion_, byte ServerRandom_[32], byte SerssionID_, CipherSuites CipherSuites_, 
    CompressionCode CompressionCode_, byte ExtensionsLength_[2], byte RenegotiationInfo_[5]){
        this->TlsVersion_ = TlsVersion_;
        for(int i=0; i<32; i++) this->ServerRandom_[i] = ServerRandom_[i];
        this->SessionID_ = SerssionID_;
        this->CipherSuites_ = CipherSuites_;
        this->CompressionCode_ = CompressionCode_;
        for(int i=0; i<2; i++) this->ExtensionsLength_[i] = ExtensionsLength_[i];
        for(int i=0; i<5; i++) this->RenegotiationInfo_[i] = RenegotiationInfo_[i];

        EncapsulateToHandshakeHeader();
    }
    
    //Return a vector with all the Data
    std::vector<byte> GetData(){
        std::vector<byte> data;
        //Adding the HandshakeHeader
        std::vector<byte> data1 = HandshakeHeader::GetData();
        data.insert(data.end(), std::begin(data1), std::end(data1));
        //Adding the Variables
        data.push_back(static_cast<byte>(TlsVersion_ >> 8));  // High byte
        data.push_back(static_cast<byte>(TlsVersion_ & 0xFF)); // Low byte
        data.insert(data.end(), std::begin(ServerRandom_), std::end(ServerRandom_));
        data.push_back(SessionID_);
        data.push_back(static_cast<byte>(CipherSuites_ >> 8));  // High byte
        data.push_back(static_cast<byte>(CipherSuites_ & 0xFF)); // Low byte
        data.push_back(static_cast<byte>(CompressionCode_));
        data.insert(data.end(), std::begin(ExtensionsLength_), std::end(ExtensionsLength_));
        data.insert(data.end(), std::begin(RenegotiationInfo_), std::end(RenegotiationInfo_));
        //Return
        data.shrink_to_fit();
        return data;
    }

    //Backtrack HandshakeHeader
    void EncapsulateToHandshakeHeader(){
        HandshakeCode_ = HandshakeCode::ServerHelloCode;
        HandshakeHeader_Length = Base_ServerHello_Length;
        EncapsulateToRecordHeader();
    }
};
class Certificate{
public:
    //Variables
    u_int32_t cert_len;
    std::vector<byte> cert;

    //Constructor
    Certificate(int n_cert){
        switch(n_cert){
            case 1:
                cert_len = cert1_len;
                cert = base64_decode(cert1);
                break;
            case 2:
                cert_len = cert2_len;
                cert = base64_decode(cert2);
                break;
            default:
                cert_len = 0;
                break;
        }
    }

private:
    //The Certificate class is only temporarly, a better inplementation is necessary
    //ECDSA
    //const u_int32_t cert1_len = ((1208/4)*3)-1;
    //const std::string cert1 = "MIIDhTCCAwqgAwIBAgISAy0ld3UQ/gt7fidYlZB/mHUgMAoGCCqGSM49BAMDMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJFNjAeFw0yNDA4MDQyMzI5MTdaFw0yNDExMDIyMzI5MTZaMB0xGzAZBgNVBAMTEmluZmluaXR5d29sdmVzLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCAj2kp1LvpJGJcZqz2UtYNCR7e9BkguWgaWk3k+mjHU9/LAV8tTheVjTYrHp31NWNbcY+Nb8r8AZfxRxiaNUw6jggITMIICDzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFMX4Ay//AfYmbQEW8jycJ2UO9QwwMB8GA1UdIwQYMBaAFJMnRpgDqVFojpjWxEJI2yO/WJTSMFUGCCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0cDovL2U2Lm8ubGVuY3Iub3JnMCIGCCsGAQUFBzAChhZodHRwOi8vZTYuaS5sZW5jci5vcmcvMB0GA1UdEQQWMBSCEmluZmluaXR5d29sdmVzLmNvbTATBgNVHSAEDDAKMAgGBmeBDAECATCCAQMGCisGAQQB1nkCBAIEgfQEgfEA7wB1AD8XS0/XIkdYlB1lHIS+DRLtkDd/H4Vq68G/KIXs+GRuAAABkR/vY68AAAQDAEYwRAIgFYKI3C0evwVOQqKAiV7JEOGroa3B/uAa8m47sbfdV3UCIBgtU0tp424cNL78INEL6TuGtS1Ogp2vFPx6gBKFumHvAHYAdv+IPwq2+5VRwmHM9Ye6NLSkzbsp3GhCCp/mZ0xaOnQAAAGRH+9rwAAABAMARzBFAiB9rnPJh5OJxUogi/gYM8lf4dTOhew6VhAP9eYb1no4hAIhAPXv1twmoPn/HJ3Uht8+H1zzOGOM2bVEzgRTZxtS7SewMAoGCCqGSM49BAMDA2kAMGYCMQCuLxVU5kqGphGgkXcpoRLbwqBEc+WB2TkGn8l9QLMS4VaxloLLrdoS/f2aSlqUNcYCMQDRYwvEgoEOQ+iS9hjU93S+CKxeLqIgZib7L0FDzatNz7+IZnkQV9IT4qaDycsTrzk=";
    //const u_int32_t cert2_len = ((1488/4)*3)-1;
    //const std::string cert2 = "MIIEVzCCAj+gAwIBAgIRALBXPpFzlydw27SHyzpFKzgwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjQwMzEzMDAwMDAwWhcNMjcwMzEyMjM1OTU5WjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDELMAkGA1UEAxMCRTYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATZ8Z5Gh/ghcWCoJuuj+rnq2h25EqfUJtlRFLFhfHWWvyILOR/VvtEKRqotPEoJhC6+QJVV6RlAN2Z17TJOdwRJ+HB7wxjnzvdxEP6sdNgA1O1tHHMWMxCcOrLqbGL0vbijgfgwgfUwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSTJ0aYA6lRaI6Y1sRCSNsjv1iU0jAfBgNVHSMEGDAWgBR5tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAKGFmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wEwYDVR0gBAwwCjAIBgZngQwBAgEwJwYDVR0fBCAwHjAcoBqgGIYWaHR0cDovL3gxLmMubGVuY3Iub3JnLzANBgkqhkiG9w0BAQsFAAOCAgEAfYt7SiA1sgWGCIpunk46r4AExIRcMxkKgUhNlrrv1B21hOaXN/5miE+LOTbrcmU/M9yvC6MVY730GNFoL8IhJ8j8vrOLpMY22OP6baS1k9YMrtDTlwJHoGby04ThTUeBDksS9RiuHvicZqBedQdIF65pZuhpeDcGBcLiYasQr/EO5gxxtLyTmgsHSOVSBcFOn9lgv7LECPq9i7mfH3mpxgrRKSxHpOoZ0KXMcB+hHuvlklHntvcI0mMMQ0mhYj6qtMFStkF1RpCG3IPdIwpVCQqu8GV7s8ubknRzs+3C/Bm19RFOoiPpDkwvyNfvmQ14XkyqqKK5oZ8zhD32kFRQkxa8uZSuh4aTImFxknu39waBxIRXE4jKxlAmQc4QjFZoq1KmQqQg0J/1JF8RlFvJas1VcjLvYlvUB2t6npO6oQjB3l+PNf0DpQH7iUx3Wz5AjQCi6L25FjyE06q6BZ/QlmtYdl/8ZYao4SRqPEs/6cAiF+Qf5zg2UkaWtDphl1LKMuTNLotvsX99HP69V2faNyegodQ0LyTApr/vT01YPE46vNsDLgK+4cL6TrzC/a4WcmF5SRJ938zrv/duJHLXQIku5v0+EwOy59Hdm0PT/Er/84dDV0CSjdR/2XuZM3kpysSKLgD1cKiDA+IRguODCxfO9cyYIg46v9mFmBvyH04=";
    //RSA
    const u_int32_t cert1_len = ((1708/4)*3)-2;
    const std::string cert1 = "MIIE+zCCA+OgAwIBAgISA1dkUQL5ZVB3qvPniBs0SDMjMA0GCSqGSIb3DQEBCwUAMDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQDEwNSMTEwHhcNMjQxMDA0MTE0NDE0WhcNMjUwMTAyMTE0NDEzWjAhMR8wHQYDVQQDExZ3d3cuaW5maW5pdHl3b2x2ZXMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJjVNEgomKC0Tltxz9QGYPtaKaHxqczw2fDu2bO21WHomJAQjMkeP5QESbjaGvCfAaRyiuwTLL//PqQVXCM3zmaWea+P0AQVMLW8qxCGGfJG8w9Q5zSv3L0yWQ5fy/nB9sKYxpYg1qWGTCH8NJtiDyd31cLGzdegQHxtg3zKLzR6C59if0DLKpVY7Hje4wys7gQzd4EjrcLl8oDWCImIGAfQ04lVK6pUN8QRJ0FcOWOYZ6Zo5w0DZSVfDJqjQH5Wg1kV62d6tOUEQBTIorpCWkHbaCit8ligXox18S18LRGsD0YT9fU264WhWMIJGuSJCVig/wAoUS+z/muf1XeQfwIDAQABo4ICGTCCAhUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQkX2tn38lZ93rIPT5Wy1Ty2raEOzAfBgNVHSMEGDAWgBTFz0ak6vTDwHpslcQtsF6SLybjuTBXBggrBgEFBQcBAQRLMEkwIgYIKwYBBQUHMAGGFmh0dHA6Ly9yMTEuby5sZW5jci5vcmcwIwYIKwYBBQUHMAKGF2h0dHA6Ly9yMTEuaS5sZW5jci5vcmcvMCEGA1UdEQQaMBiCFnd3dy5pbmZpbml0eXdvbHZlcy5jb20wEwYDVR0gBAwwCjAIBgZngQwBAgEwggEDBgorBgEEAdZ5AgQCBIH0BIHxAO8AdQDPEVbu1S58r/OHW9lpLpvpGnFnSrAX7KwB0lt3zsw7CAAAAZJXjdE1AAAEAwBGMEQCIENMeANDnsqcrYAFe88VR5ExQpR/AkbV5sw1owStxhlKAiBFF31CxDi8bBP/+ibgvUKLro1CGsu0Bzm2/Mg/yDswkwB2AD8XS0/XIkdYlB1lHIS+DRLtkDd/H4Vq68G/KIXs+GRuAAABkleN2LwAAAQDAEcwRQIgCDUbt7h3kSO10h7X0e8NcDBK4n+HizX/uh/KKa1cTjwCIQCSGei+l8gWKOXEoR4wabPaDaxpHZjCSzXTKc3/vtaeFjANBgkqhkiG9w0BAQsFAAOCAQEAVUuOFHzPNsetT1fq/ZCQGjt1RI7yJOT/623/QJJhj2uPRIirLILV2uYwnkMj/AEpOie8obUEMoeJ052j7nsVpy/mo/Z1GakpeWC7RY+3IQbTsAjDvewXYQk4LJwaRHrqrbzqXR/fD05HeVpl5tUYWrnl0Lty9fZ7np7Fq+QJw54OMXLLLyyzyWfONCg9hKhTsTseCXZmO9e9PhM5G7/WAmUOrWFy2y+wQgZ9ORMBdfFJOP8w3KUHoy4E2XoE8lwrzDYGzZFiZwWFnW1/7GKgt3bLRz59gZYqxu3+CcYZpR8Y2SrjZ1xm3cDyhDHIZOg3Gg8n3zr/dXroBMO3/fgF6g==";
    const u_int32_t cert2_len = 1290;
    const std::string cert2 = "MIIFBjCCAu6gAwIBAgIRAIp9PhPWLzDvI4a9KQdrNPgwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjQwMzEzMDAwMDAwWhcNMjcwMzEyMjM1OTU5WjAzMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDEMMAoGA1UEAxMDUjExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoe8XBsAOcvKCs3UZxD5ATylTqVhyybKUvsVAbe5KPUoHu0nsyQYOWcJDAjs4DqwO3cOvfPlOVRBDE6uQdaZdN5R2+97/1i9qLcT9t4x1fJyyXJqC4N0lZxGAGQUmfOx2SLZzaiSqhwmej/+71gFewiVgdtxD4774zEJuwm+UE1fj5F2PVqdnoPy6cRms+EGZkNIGIBloDcYmpuEMpexsr3E+BUAnSeI++JjF5ZsmydnS8TbKF5pwnnwSVzgJFDhxLyhBax7QG0AtMJBP6dYuC/FXJuluwme8f7rsIU5/agK70XEeOtlKsLPXzze41xNG/cLJyuqC0J3U095ah2H2QIDAQABo4H4MIH1MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUxc9GpOr0w8B6bJXELbBeki8m47kwHwYDVR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wMgYIKwYBBQUHAQEEJjAkMCIGCCsGAQUFBzAChhZodHRwOi8veDEuaS5sZW5jci5vcmcvMBMGA1UdIAQMMAowCAYGZ4EMAQIBMCcGA1UdHwQgMB4wHKAaoBiGFmh0dHA6Ly94MS5jLmxlbmNyLm9yZy8wDQYJKoZIhvcNAQELBQADggIBAE7iiV0KAxyQOND1H/lxXPjDj7I3iHpvsCUf7b632IYGjukJhM1yv4Hz/MrPU0jtvfZpQtSlET41yBOykh0FX+ou1Nj4ScOt9ZmWnO8m2OG0JAtIIE3801S0qcYhyOE2G/93ZCkXufBL713qzXnQv5C/viOykNpKqUgxdKlEC+Hi9i2DcaR1e9KUwQUZRhy5j/PEdEglKg3l9dtD4tuTm7kZtB8v32oOjzHTYw+7KdzdZiw/sBtnUfhBPORNuay4pJxmY/WrhSMdzFO2q3Gu3MUBcdo27goYKjL9CTF8j/Zz55yctUoVaneCWs/ajUX+HypkBTA+c8LGDLnWO2NKq0YD/pnARkAnYGPfUDoHR9gVSp/qRx+ZWghiDLZsMwhN1zjtSC0uBWiugF3vTNzYIEFfaPG7Ws3jDrAMMYebQ95JQ+HIBD/RPBuHRTBpqKlyDnkSHDHYPiNX3adPoPAcgdF3H2/W0rmoswMWgTlLn1Wu0mrks7/qpdWfS6PJ1jty80r2VKsM/Dj3YIDfbjXKdaFU5C+8bhfJGqU3taKauuz0wHVGT3eo6FlWkWYtbt4pgdamlwVeZEW+LM7qZEJEsMNPrfC03APKmZsJgpWCDWOKZvkZcvjVuYkQ4omYCTX5ohy+knMjdOmdH9c7SpqEWBDC86fiNex+O0XOMEZSa8DA";
};
class ServerCertificate : HandshakeHeader{
public:
    const u_int32_t Base_ServerCertificate_Lenght = 3;
    u_int32_t CertificateChainLength;
    Certificate Certificate1;
    Certificate Certificate2;

    //Constructors
    ServerCertificate() : Certificate1(1), Certificate2(2){
        CertificateChainLength = (Certificate1.cert_len + 3) + (Certificate2.cert_len + 3);
        EncapuslateToHandshakeHeader();
    }

    //Return a vector with all the Data
    std::vector<byte> GetData(){
        std::vector<byte> data;
        //Adding the HandshakeHeader
        std::vector<byte> data1 = HandshakeHeader::GetData();
        data.insert(data.end(), std::begin(data1), std::end(data1));
        //Adding the Variables
        data.push_back(static_cast<byte>((CertificateChainLength >> 16) & 0xFF)); // 3rd byte
        data.push_back(static_cast<byte>((CertificateChainLength >> 8) & 0xFF));  // 2nd byte
        data.push_back(static_cast<byte>(CertificateChainLength & 0xFF));         // 1st byte

        data.push_back(static_cast<byte>((Certificate1.cert_len >> 16) & 0xFF)); // 3rd byte
        data.push_back(static_cast<byte>((Certificate1.cert_len >> 8) & 0xFF));  // 2nd byte
        data.push_back(static_cast<byte>(Certificate1.cert_len & 0xFF));         // 1st byte
        data.insert(data.end(), std::begin(Certificate1.cert), std::end(Certificate1.cert));

        data.push_back(static_cast<byte>((Certificate2.cert_len >> 16) & 0xFF)); // 3rd byte
        data.push_back(static_cast<byte>((Certificate2.cert_len >> 8) & 0xFF));  // 2nd byte
        data.push_back(static_cast<byte>(Certificate2.cert_len & 0xFF));         // 1st byte
        data.insert(data.end(), std::begin(Certificate2.cert), std::end(Certificate2.cert));

        //Return
        data.shrink_to_fit();
        return data;
    }

    //Backtrack HandshakeHeader
    void EncapuslateToHandshakeHeader(){
        HandshakeCode_ = HandshakeCode::ServerCertificateCode;
        HandshakeHeader_Length = CertificateChainLength + Base_ServerCertificate_Lenght;
        EncapsulateToRecordHeader();
    }
};
class ServerKeyExchange : HandshakeHeader{
public:
    //Base Lenghts
    const u_int32_t Base_ServerKeyExchange_Length = 40;
    //Variables
    byte CurveInfo[3] = {0x03, 0x00, 0x1d};
    byte PublicKeyLenght = 32;
    byte PublicKey[32];
    SignAlgorithem SignAlgorithem_ = ECDSA_SHA256;
    word SignatureLength = 71;
    std::vector<byte> Signature_;

    //Construcotrs
    ServerKeyExchange(SignAlgorithem SignAlgo, byte* publicKey, word signatureLength, std::vector<byte> signature){
        SignAlgorithem_ = SignAlgo;
        std::memcpy(PublicKey, publicKey, 32 * sizeof(byte));
        SignatureLength = signatureLength;
        Signature_ = signature;
        EncapsulateToHandshakeHeader(Base_ServerKeyExchange_Length + SignatureLength);
    }

    //Return a vector with all the Data
    std::vector<byte> GetData(){
        std::vector<byte> data;
        //Adding the HandshakeHeader
        std::vector<byte> data1 = HandshakeHeader::GetData();
        data.insert(data.end(), std::begin(data1), std::end(data1));
        //Adding the Variables
        data.insert(data.end(), std::begin(CurveInfo), std::end(CurveInfo));
        data.push_back(PublicKeyLenght);
        data.insert(data.end(), std::begin(PublicKey), std::end(PublicKey));
        data.push_back(static_cast<byte>(SignAlgorithem_ >> 8));  // High byte
        data.push_back(static_cast<byte>(SignAlgorithem_ & 0xFF)); // Low byte
        data.push_back(static_cast<byte>(SignatureLength >> 8));  // High byte
        data.push_back(static_cast<byte>(SignatureLength & 0xFF)); // Low byte
        data.insert(data.end(), std::begin(Signature_), std::end(Signature_));
        //Return
        data.shrink_to_fit();
        return data;
    }
    //Backtrack HandshakeHeader
    void EncapsulateToHandshakeHeader(int lenght){
        HandshakeCode_ = HandshakeCode::ServerKeyExchangeCode;
        HandshakeHeader_Length = lenght;
        EncapsulateToRecordHeader();
    }
};
class ServerHelloDone : HandshakeHeader{
public:
    ServerHelloDone(){
        EncapsulateToHandshakeHeader();
    }
    std::vector<byte> GetData(){
        std::vector<byte> data;
        //Adding the HandshakeHeader
        std::vector<byte> data1 = HandshakeHeader::GetData();
        data.insert(data.end(), std::begin(data1), std::end(data1));
        //Adding the Variables
        //Return
        data.shrink_to_fit();
        return data;
    }
    void EncapsulateToHandshakeHeader(){
        HandshakeCode_ = HandshakeCode::ServerHelloDoneCode;
        HandshakeHeader_Length = 0;
        EncapsulateToRecordHeader();
    }
};
class ClientKeyExchange{
public:
    byte KeyLength;
    byte PublicKey[32];
};
class ServerHandshakeFinished : RecordHeader{
public:
    byte EncryptionIV[16];
    std::vector<byte> EncryptedData;

    ServerHandshakeFinished(byte EncryptionIV_[16], std::vector<byte> EncryptedData_){
        // Generate random bytes
        std::memcpy(EncryptionIV, EncryptionIV_, 16);
        EncryptedData.insert(EncryptedData.end(), EncryptedData_.begin(), EncryptedData_.end());
        EncapsulateToRecordHeader();
    }

    void EncapsulateToRecordHeader(){
        RecordCode_ = RecordCode::Handshake;
        TlsVersion_ = TlsVersion::Tls12;
        RecordHeader_Length = 16 + EncryptedData.size();
    }
    //Return a vector with all the Data
    std::vector<byte> GetData(){
        std::vector<byte> data;
        //Get the RecordHeader
        std::vector<byte> data1 = RecordHeader::GetData();
        data.insert(data.end(), std::begin(data1), std::end(data1));
        //Add the Variables
        data.insert(data.end(), std::begin(EncryptionIV), std::end(EncryptionIV));
        data.insert(data.end(), EncryptedData.begin(), EncryptedData.end());
        //Return
        data.shrink_to_fit();
        return data;
    }
};

//CHANGE CIPHER SPEC
class ChangeCipherSpecClass : RecordHeader{
public:
    byte Payload = 0x01;

    ChangeCipherSpecClass(){
        EncapsulateToRecordHeader();
    }

    //Encapsulate to RecordHeader
    void EncapsulateToRecordHeader(){
        RecordCode_ = RecordCode::ChangeCipherSpec;
        TlsVersion_ = TlsVersion::Tls12;
        RecordHeader_Length = 1;
    }

    //Return a vector with all the Data
    std::vector<byte> GetData(){
        std::vector<byte> data;
        //Get the RecordHeader
        std::vector<byte> data1 = RecordHeader::GetData();
        data.insert(data.end(), std::begin(data1), std::end(data1));
        //Add the Variables
        data.push_back(static_cast<byte>(1)); 
        //Return
        data.shrink_to_fit();
        return data;
    }
};

class ClientHandshakeFinished{
public:
    byte EncryptionIV[16];
    std::vector<byte> EncryptedData;

    ClientHandshakeFinished(std::vector<byte> Data){
        std::memcpy(this->EncryptionIV, Data.data(), 16);
        EncryptedData.insert(EncryptedData.end(), Data.begin() + 16, Data.end());
    }
};

//APPLICATION DATA
class ServerApplicationData : RecordHeader{
public:
    byte EncryptionIV[16];
    std::vector<byte> EncryptedData;

    ServerApplicationData(byte EncryptionIV_[16], std::vector<byte> EncryptedData_){
        // Generate random bytes
        std::memcpy(EncryptionIV, EncryptionIV_, 16);
        EncryptedData.insert(EncryptedData.end(), EncryptedData_.begin(), EncryptedData_.end());
        EncapsulateToRecordHeader();
    }

    void EncapsulateToRecordHeader(){
        RecordCode_ = RecordCode::ApplicationData;
        TlsVersion_ = TlsVersion::Tls12;
        RecordHeader_Length = 16 + EncryptedData.size();
    }
    //Return a vector with all the Data
    std::vector<byte> GetData(){
        std::vector<byte> data;
        //Get the RecordHeader
        std::vector<byte> data1 = RecordHeader::GetData();
        data.insert(data.end(), std::begin(data1), std::end(data1));
        //Add the Variables
        data.insert(data.end(), std::begin(EncryptionIV), std::end(EncryptionIV));
        data.insert(data.end(), EncryptedData.begin(), EncryptedData.end());
        //Return
        data.shrink_to_fit();
        return data;
    }
};
class ClientApplicationData : RecordHeader{
public:
    byte EncryptionIV[16];
    std::vector<byte> EncryptedData;

    // Constructor takes const reference to avoid unnecessary copying
    ClientApplicationData(const std::vector<byte>& Data) {
        if (Data.size() < 16) {
            throw std::invalid_argument("Input data is too small");
        }

        // Copy the first 16 bytes into EncryptionIV using std::copy
        std::copy(Data.begin(), Data.begin() + 16, EncryptionIV);

        // Efficiently initialize EncryptedData with the remaining bytes
        EncryptedData.assign(Data.begin() + 16, Data.end());
    }
    // void EncapsulateToRecordHeader(){
    //     RecordCode_ = RecordCode::ApplicationData;
    //     TlsVersion_ = TlsVersion::Tls12;
    //     RecordHeader_Length = 16 + EncryptedData.size();
    // }
    //Return a vector with all the Data
    std::vector<byte> GetData(){
        std::vector<byte> data;
        //Get the RecordHeader
        std::vector<byte> data1 = RecordHeader::GetData();
        data.insert(data.end(), std::begin(data1), std::end(data1));
        //Add the Variables
        data.insert(data.end(), std::begin(EncryptionIV), std::end(EncryptionIV));
        data.insert(data.end(), EncryptedData.begin(), EncryptedData.end());
        //Return
        data.shrink_to_fit();
        return data;
    }
};

#endif