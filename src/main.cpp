//Standard Include
  #include "standard/StandardHeader.h"
  #include "standard/DataTools.h"
  #include "standard/StringTools.h"
//Libraries Include
  #include "lib/OpensslHeader.h"
  #include "lib/AsioHeader.h"

//#ACCEPTOR
  #include "Acceptor.h"

int main() {
    //Creazione del contesto ASIO e avvio SERVER
    try {
        //Inizialize OPENSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        //Inizialize ASIO
        Acceptor Acceptor_(443);
    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    //Stop OPENSSL
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}
