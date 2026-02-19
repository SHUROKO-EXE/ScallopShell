#pragma once

#include <MinimalSocket/core/Address.h>
#include <MinimalSocket/core/Definitions.h>
#include <MinimalSocket/tcp/TcpServer.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

class ScallopState;

class ScallopSocket {
public:
    static constexpr MinimalSocket::Port kDefaultPort = 31337;

    explicit ScallopSocket(ScallopState &state,
                           MinimalSocket::AddressFamily family = MinimalSocket::AddressFamily::IP_V4);
    ~ScallopSocket();

    bool start(MinimalSocket::Port port = kDefaultPort);
    void stop();

    bool sendLine(const std::string &line);

    bool isRunning() const { return running_.load(); }
    MinimalSocket::Port port() const { return bound_port_; }

private:

    /**
     * Try to connect to the client, handoff to handleClient() 
     * when successful. 
     */
    void acceptLoop();

    /**
     * Handle client commands, enqueue in ScallopState. When client disconnects,
     * exit the program on error. 
     */
    void handleClient(MinimalSocket::tcp::TcpConnectionBlocking connection);

    ScallopState &state_;
    MinimalSocket::AddressFamily family_;
    std::unique_ptr<MinimalSocket::tcp::TcpServer<true>> server_;
    std::thread accept_thread_;
    std::atomic<bool> running_{false};
    MinimalSocket::Port bound_port_{0};

    std::mutex active_client_mu_;
    MinimalSocket::tcp::TcpConnectionBlocking *active_client_{nullptr};
};
