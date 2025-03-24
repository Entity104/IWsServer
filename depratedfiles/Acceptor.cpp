//#TLSSESSION
#include "Acceptor.h"
#include "tls/TlsSession.h"

//Server costructor (context, port)
Acceptor::Acceptor(asio::io_context& io_context, short port)
    //Creates the acceptor
    : acceptor(io_context, tcp::endpoint(tcp::v4(), port)) {
    //Start Listening...
    ASYNC_WaitConnection();
    std::cout << "[SERVER] Started on port: " << port << "...\n";
}

//ASYNC, wait for connections
void Acceptor::ASYNC_WaitConnection() {
    acceptor.async_accept(
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
