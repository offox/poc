#include <opus/opus.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <iterator>

namespace {
constexpr std::size_t kRtpHeaderSize = 12;
constexpr uint8_t kRtpVersion = 2;
constexpr uint8_t kOpusPayloadType = 111;  // Dynamic payload type commonly used for Opus.
constexpr int kSampleRate = 48000;
constexpr int kChannels = 2;
constexpr int kBitsPerSample = 16;
constexpr int kFrameDurationMs = 20;  // Each RTP packet will contain 20 ms of audio.
constexpr int kFrameSize = kSampleRate / (1000 / kFrameDurationMs);
constexpr int kMaxPacketSize = 1500;

struct ServerOptions {
    std::string pcm_path;
    std::string destination_address = "127.0.0.1";
    uint16_t destination_port = 5004;
    uint16_t http_port = 8080;
    std::filesystem::path web_root = "web";
};

std::vector<uint8_t> buildWavFromPcm(const std::string& pcm_path) {
    std::ifstream input(pcm_path, std::ios::binary);
    if (!input.is_open()) {
        throw std::runtime_error("Failed to open PCM file: " + pcm_path);
    }

    std::vector<uint8_t> pcm_data((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    input.close();

    if (pcm_data.empty()) {
        throw std::runtime_error("PCM file is empty: " + pcm_path);
    }

    const uint32_t data_chunk_size = static_cast<uint32_t>(pcm_data.size());
    const uint32_t byte_rate = kSampleRate * kChannels * (kBitsPerSample / 8);
    const uint16_t block_align = kChannels * (kBitsPerSample / 8);

    std::vector<uint8_t> wav;
    wav.reserve(44 + pcm_data.size());

    auto append = [&wav](auto value) {
        using T = decltype(value);
        T little_endian_value = value;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        // Convert to little endian if needed.
        uint8_t* ptr = reinterpret_cast<uint8_t*>(&little_endian_value);
        std::reverse(ptr, ptr + sizeof(T));
#endif
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&little_endian_value);
        wav.insert(wav.end(), bytes, bytes + sizeof(T));
    };

    // RIFF header
    wav.insert(wav.end(), {'R', 'I', 'F', 'F'});
    append(static_cast<uint32_t>(36 + data_chunk_size));
    wav.insert(wav.end(), {'W', 'A', 'V', 'E'});

    // fmt chunk
    wav.insert(wav.end(), {'f', 'm', 't', ' '});
    append(static_cast<uint32_t>(16));  // Subchunk1Size for PCM
    append(static_cast<uint16_t>(1));   // AudioFormat PCM
    append(static_cast<uint16_t>(kChannels));
    append(static_cast<uint32_t>(kSampleRate));
    append(byte_rate);
    append(block_align);
    append(static_cast<uint16_t>(kBitsPerSample));

    // data chunk
    wav.insert(wav.end(), {'d', 'a', 't', 'a'});
    append(data_chunk_size);
    wav.insert(wav.end(), pcm_data.begin(), pcm_data.end());

    return wav;
}

class RtpStreamer {
   public:
    explicit RtpStreamer(ServerOptions options)
        : options_(std::move(options)),
          encoder_(nullptr, &opus_encoder_destroy),
          streaming_requested_(false) {
        int error = 0;
        OpusEncoder* enc = opus_encoder_create(kSampleRate, kChannels, OPUS_APPLICATION_AUDIO, &error);
        if (error != OPUS_OK) {
            throw std::runtime_error("Failed to create Opus encoder: " + std::string(opus_strerror(error)));
        }
        opus_encoder_ctl(enc, OPUS_SET_BITRATE(128000));
        encoder_.reset(enc);

        udp_socket_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_socket_ < 0) {
            throw std::runtime_error("Failed to create UDP socket");
        }

        std::random_device rd;
        std::mt19937 rng(rd());
        std::uniform_int_distribution<uint32_t> dist32;
        std::uniform_int_distribution<uint16_t> dist16;
        ssrc_ = dist32(rng);
        sequence_number_ = dist16(rng);
        timestamp_ = dist32(rng);

        std::memset(&destination_, 0, sizeof(destination_));
        destination_.sin_family = AF_INET;
        destination_.sin_port = htons(options_.destination_port);
        if (inet_pton(AF_INET, options_.destination_address.c_str(), &destination_.sin_addr) <= 0) {
            throw std::runtime_error("Invalid destination address: " + options_.destination_address);
        }
    }

    ~RtpStreamer() { close(udp_socket_); }

    void requestStart() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            streaming_requested_ = true;
        }
        cond_var_.notify_one();
    }

    void run() {
        while (running_) {
            std::unique_lock<std::mutex> lock(mutex_);
            cond_var_.wait(lock, [this]() { return !running_ || streaming_requested_; });
            if (!running_) {
                break;
            }
            streaming_requested_ = false;
            lock.unlock();

            try {
                streamOnce();
            } catch (const std::exception& ex) {
                std::cerr << "Streaming failed: " << ex.what() << std::endl;
            }
        }
    }

    void stop() {
        running_ = false;
        cond_var_.notify_one();
    }

   private:
    void streamOnce() {
        std::ifstream pcm(options_.pcm_path, std::ios::binary);
        if (!pcm.is_open()) {
            throw std::runtime_error("Unable to open PCM file: " + options_.pcm_path);
        }

        std::vector<int16_t> pcm_buffer(kFrameSize * kChannels);
        std::vector<unsigned char> opus_buffer(kMaxPacketSize);
        bool first_packet = true;

        while (running_ && pcm.read(reinterpret_cast<char*>(pcm_buffer.data()), pcm_buffer.size() * sizeof(int16_t))) {
            const int16_t* frame_data = pcm_buffer.data();
            int encoded_bytes = opus_encode(encoder_.get(), frame_data, kFrameSize, opus_buffer.data(), static_cast<opus_int32>(opus_buffer.size()));
            if (encoded_bytes < 0) {
                throw std::runtime_error("Opus encoding error: " + std::string(opus_strerror(encoded_bytes)));
            }

            std::array<uint8_t, kRtpHeaderSize> header{};
            header[0] = (kRtpVersion << 6);
            header[1] = kOpusPayloadType & 0x7F;
            if (first_packet) {
                header[1] |= 0x80;  // Set marker bit for the first packet in a stream.
                first_packet = false;
            }
            header[2] = static_cast<uint8_t>((sequence_number_ >> 8) & 0xFF);
            header[3] = static_cast<uint8_t>(sequence_number_ & 0xFF);
            header[4] = static_cast<uint8_t>((timestamp_ >> 24) & 0xFF);
            header[5] = static_cast<uint8_t>((timestamp_ >> 16) & 0xFF);
            header[6] = static_cast<uint8_t>((timestamp_ >> 8) & 0xFF);
            header[7] = static_cast<uint8_t>(timestamp_ & 0xFF);
            header[8] = static_cast<uint8_t>((ssrc_ >> 24) & 0xFF);
            header[9] = static_cast<uint8_t>((ssrc_ >> 16) & 0xFF);
            header[10] = static_cast<uint8_t>((ssrc_ >> 8) & 0xFF);
            header[11] = static_cast<uint8_t>(ssrc_ & 0xFF);

            sequence_number_++;
            timestamp_ += kFrameSize;

            std::vector<uint8_t> packet;
            packet.reserve(kRtpHeaderSize + encoded_bytes);
            packet.insert(packet.end(), header.begin(), header.end());
            packet.insert(packet.end(), opus_buffer.begin(), opus_buffer.begin() + encoded_bytes);

            ssize_t sent = sendto(udp_socket_, packet.data(), packet.size(), 0,
                                  reinterpret_cast<sockaddr*>(&destination_), sizeof(destination_));
            if (sent < 0) {
                throw std::runtime_error("Failed to send RTP packet");
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(kFrameDurationMs));
        }

        pcm.close();
    }

    ServerOptions options_;
    std::unique_ptr<OpusEncoder, decltype(&opus_encoder_destroy)> encoder_;
    int udp_socket_;
    sockaddr_in destination_{};
    uint32_t ssrc_;
    uint16_t sequence_number_;
    uint32_t timestamp_;

    std::atomic<bool> running_{true};
    std::atomic<bool> streaming_requested_;
    std::mutex mutex_;
    std::condition_variable cond_var_;
};

class HttpServer {
   public:
    HttpServer(uint16_t port, RtpStreamer& streamer, std::vector<uint8_t> wav_data, std::string html)
        : port_(port), streamer_(streamer), wav_data_(std::move(wav_data)), html_(std::move(html)) {}

    void run() {
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            throw std::runtime_error("Failed to create HTTP server socket");
        }

        int enable = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port_);

        if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(server_fd);
            throw std::runtime_error("Failed to bind HTTP server socket");
        }

        if (listen(server_fd, 10) < 0) {
            close(server_fd);
            throw std::runtime_error("Failed to listen on HTTP server socket");
        }

        std::cout << "HTTP server listening on port " << port_ << std::endl;

        while (true) {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(server_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
            if (client_fd < 0) {
                continue;
            }

            std::thread(&HttpServer::handleClient, this, client_fd).detach();
        }
    }

   private:
    void handleClient(int client_fd) {
        std::string request(4096, '\0');
        ssize_t bytes_read = recv(client_fd, request.data(), request.size() - 1, 0);
        if (bytes_read <= 0) {
            close(client_fd);
            return;
        }
        request.resize(static_cast<std::size_t>(bytes_read));

        std::istringstream request_stream(request);
        std::string method;
        std::string path;
        std::string version;
        request_stream >> method >> path >> version;

        if (method == "GET" && path == "/") {
            sendResponse(client_fd, "200 OK", "text/html; charset=utf-8", html_);
        } else if (method == "GET" && path.rfind("/audio", 0) == 0) {
            std::string body(wav_data_.begin(), wav_data_.end());
            sendResponse(client_fd, "200 OK", "audio/wav", body);
        } else if (method == "POST" && path == "/start") {
            streamer_.requestStart();
            const std::string body = "Streaming started";
            sendResponse(client_fd, "200 OK", "text/plain; charset=utf-8", body);
        } else {
            const std::string body = "Not Found";
            sendResponse(client_fd, "404 Not Found", "text/plain; charset=utf-8", body);
        }

        close(client_fd);
    }

    void sendResponse(int client_fd, const std::string& status, const std::string& content_type,
                      const std::string& body) {
        std::ostringstream response;
        response << "HTTP/1.1 " << status << "\r\n";
        response << "Content-Type: " << content_type << "\r\n";
        response << "Content-Length: " << body.size() << "\r\n";
        response << "Connection: close\r\n\r\n";
        response << body;
        const std::string& response_str = response.str();
        send(client_fd, response_str.data(), response_str.size(), 0);
    }

    uint16_t port_;
    RtpStreamer& streamer_;
    std::vector<uint8_t> wav_data_;
    std::string html_;
};

ServerOptions parseArguments(int argc, char* argv[]) {
    ServerOptions options;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-f" || arg == "--file") && i + 1 < argc) {
            options.pcm_path = argv[++i];
        } else if ((arg == "-d" || arg == "--dest") && i + 1 < argc) {
            options.destination_address = argv[++i];
        } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            options.destination_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if ((arg == "-H" || arg == "--http-port") && i + 1 < argc) {
            options.http_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if ((arg == "-w" || arg == "--web-root") && i + 1 < argc) {
            options.web_root = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: opus_streamer --file <path_to_pcm16_stereo> [options]\n"
                         "Options:\n"
                         "  -d, --dest <address>       Destination IPv4 address for RTP (default 127.0.0.1)\n"
                         "  -p, --port <port>          Destination UDP port for RTP (default 5004)\n"
                         "  -H, --http-port <port>     HTTP control/listen port (default 8080)\n"
                         "  -w, --web-root <path>      Directory containing index.html (default ./web)\n";
            std::exit(0);
        }
    }

    if (options.pcm_path.empty()) {
        throw std::runtime_error("PCM file must be provided using --file");
    }

    return options;
}

std::string loadHtml(const std::filesystem::path& web_root) {
    std::filesystem::path index_path = web_root / "index.html";
    std::ifstream input(index_path);
    if (!input.is_open()) {
        throw std::runtime_error("Failed to open HTML page: " + index_path.string());
    }

    std::stringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

}  // namespace

int main(int argc, char* argv[]) {
    try {
        ServerOptions options = parseArguments(argc, argv);
        std::string html = loadHtml(options.web_root);
        std::vector<uint8_t> wav = buildWavFromPcm(options.pcm_path);

        RtpStreamer streamer(options);
        std::thread streaming_thread(&RtpStreamer::run, &streamer);

        HttpServer http_server(options.http_port, streamer, std::move(wav), std::move(html));
        http_server.run();

        streamer.stop();
        streaming_thread.join();
    } catch (const std::exception& ex) {
        std::cerr << "Fatal error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
