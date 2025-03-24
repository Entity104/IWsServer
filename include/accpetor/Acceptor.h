#ifndef ACCEPTOR
#define ACCEPTOR
//Acceptor libs
    #include "standard/StandardHeader.h"
    #include "libs/AsioHeader.h"
    #include "tls/TlsSession.h"

//The main Server that listen for upcoming request
class Acceptor{
    uint16_t port;
    asio::io_context asioContext;
    std::thread threadContext;
    asio::ip::tcp::acceptor asioAcceptor;

    u_int64_t maxConnections = 2000;
    u_int64_t currentConnections = 0;

public:
    //Server costructor (context, port)
    Acceptor(uint16_t port)
        : asioAcceptor(asioContext, tcp::endpoint(tcp::v4(), port)){
        this->port = port;
        Start();
    }
    bool Start(){
        try{
            //Queue the work before starting the thread
            ASYNC_WaitConnection();
            threadContext = std::thread([this]() {asioContext.run();});
        }
        catch(std::exception& e){
            std::cerr << "[ACCEPTOR] exeption: " << e.what() << std::endl;
            return false;
        }
        std::cout << "[ACCEPTOR] started on port: " << port << std::endl;
        return true;
    }
    bool Stop(){
        asioContext.stop();
        if(threadContext.joinable()) threadContext.join();

        std::cout << "[ACCEPTOR] stopped" << std::endl;
        return true;
    }
    void ASYNC_WaitConnection() {
        asioAcceptor.async_accept(
            [this](std::error_code ec, tcp::socket socket) {
                if (!ec) {
                    //Start a new connection based on the incoming request
                    currentConnections++;
                    std::make_shared<TlsSession>(std::move(socket))->StartReading(currentConnections);
                }
                //After a connection is sucessfull it starts waiting again
                ASYNC_WaitConnection();
            }
        );
    }
};
#endif