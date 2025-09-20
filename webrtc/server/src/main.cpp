#include <rtc/rtc.hpp>
#include <iostream>

int main() {
    rtc::InitLogger(rtc::LogLevel::Info);

    auto pc = std::make_shared<rtc::PeerConnection>();
    auto dc = pc->createDataChannel("chat");

    dc->onOpen([](){
        std::cout << "DataChannel opened" << std::endl;
    });

    dc->onMessage([](rtc::message_variant msg){
        if (std::holds_alternative<std::string>(msg)) {
            std::cout << "Received: " << std::get<std::string>(msg) << std::endl;
        }
    });

    std::cout << "WebRTC server running. Type messages to send over the DataChannel." << std::endl;
    std::string line;
    while (std::getline(std::cin, line)) {
        dc->send(line);
    }
    return 0;
}
