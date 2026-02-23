#include <iomanip>
#include <sstream>
#include <thread>
#include <chrono>
#include <algorithm>
#include <array>
#include <cstring>
#include "util.hpp"
#include "util_hw.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using socket_t = SOCKET;
#define SOCK_INVALID INVALID_SOCKET
#define SOCK_CLOSE closesocket
#define SOCK_ERROR SOCKET_ERROR
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
using socket_t = int;
#define SOCK_INVALID (-1)
#define SOCK_CLOSE close
#define SOCK_ERROR (-1)
#endif

// TFTP opcodes
enum TFTP_OP : uint16_t {
    TFTP_RRQ   = 1,
    TFTP_WRQ   = 2,
    TFTP_DATA  = 3,
    TFTP_ACK   = 4,
    TFTP_ERROR = 5,
};

static constexpr size_t TFTP_BLOCK_SIZE = 512;
static constexpr int    TFTP_TIMEOUT_MS = 5000;
static constexpr int    TFTP_MAX_RETRIES = 5;

class NetworkInit {
  public:
    NetworkInit()
    {
#ifdef _WIN32
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif
    }
    ~NetworkInit()
    {
#ifdef _WIN32
        WSACleanup();
#endif
    }
};

class TFTPServer {
  private:
    socket_t sock;
    struct sockaddr_in server_addr;
    std::string firmware_path;
    std::string firmware_data;
    bool running;

    void set_socket_timeout(socket_t s, int timeout_ms)
    {
#ifdef _WIN32
        DWORD tv = timeout_ms;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
#else
        struct timeval tv;
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    }

    void send_data(socket_t s, const struct sockaddr_in &client, uint16_t block,
                   const char *data, size_t len)
    {
        std::vector<char> pkt(4 + len);
        uint16_t op     = htons(TFTP_DATA);
        uint16_t blk_be = htons(block);
        std::memcpy(&pkt[0], &op, 2);
        std::memcpy(&pkt[2], &blk_be, 2);
        if (len > 0) {
            std::memcpy(&pkt[4], data, len);
        }
        sendto(s, pkt.data(), pkt.size(), 0,
               reinterpret_cast<const struct sockaddr *>(&client), sizeof(client));
    }

    void send_error(socket_t s, const struct sockaddr_in &client, uint16_t code,
                    const char *msg)
    {
        size_t msg_len = std::strlen(msg);
        std::vector<char> pkt(5 + msg_len);
        uint16_t op       = htons(TFTP_ERROR);
        uint16_t code_be  = htons(code);
        std::memcpy(&pkt[0], &op, 2);
        std::memcpy(&pkt[2], &code_be, 2);
        std::memcpy(&pkt[4], msg, msg_len);
        pkt[4 + msg_len] = '\0';
        sendto(s, pkt.data(), pkt.size(), 0,
               reinterpret_cast<const struct sockaddr *>(&client), sizeof(client));
    }

    bool handle_read_request(const struct sockaddr_in &client, const std::string &filename)
    {
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client.sin_addr, client_ip, sizeof(client_ip));
        std::cout << "[ + ] TFTP read request from " << client_ip << ":"
                  << ntohs(client.sin_port) << " for '" << filename << "'" << std::endl;

        if (firmware_data.empty()) {
            std::cerr << "[ - ] No firmware loaded" << std::endl;
            send_error(sock, client, 1, "File not found");
            return false;
        }

        // Create a new socket for the transfer
        socket_t xfer_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (xfer_sock == SOCK_INVALID) {
            std::cerr << "[ - ] Failed to create transfer socket" << std::endl;
            return false;
        }

        set_socket_timeout(xfer_sock, TFTP_TIMEOUT_MS);

        size_t total_blocks = (firmware_data.size() + TFTP_BLOCK_SIZE - 1) / TFTP_BLOCK_SIZE;
        size_t bytes_sent   = 0;
        uint16_t block      = 1;

        std::cout << "[ * ] Sending firmware (" << firmware_data.size() << " bytes, "
                  << total_blocks << " blocks)..." << std::endl;

        while (bytes_sent < firmware_data.size()) {
            size_t chunk_sz =
                std::min(TFTP_BLOCK_SIZE, firmware_data.size() - bytes_sent);

            int retries = 0;
            bool ack_received = false;

            while (retries < TFTP_MAX_RETRIES && !ack_received) {
                send_data(xfer_sock, client, block,
                          firmware_data.data() + bytes_sent, chunk_sz);

                // Wait for ACK
                char ack_buf[4];
                struct sockaddr_in ack_from;
                socklen_t ack_len = sizeof(ack_from);

                int n = recvfrom(xfer_sock, ack_buf, sizeof(ack_buf), 0,
                                 reinterpret_cast<struct sockaddr *>(&ack_from), &ack_len);
                if (n >= 4) {
                    uint16_t ack_op, ack_blk;
                    std::memcpy(&ack_op, &ack_buf[0], 2);
                    std::memcpy(&ack_blk, &ack_buf[2], 2);
                    if (ntohs(ack_op) == TFTP_ACK && ntohs(ack_blk) == block) {
                        ack_received = true;
                    }
                }
                retries++;
            }

            if (!ack_received) {
                std::cerr << "[ - ] Transfer timeout at block " << block << std::endl;
                SOCK_CLOSE(xfer_sock);
                return false;
            }

            bytes_sent += chunk_sz;
            block++;

            // Progress indicator
            if (block % 1000 == 0 || bytes_sent == firmware_data.size()) {
                int pct = static_cast<int>(100.0 * bytes_sent / firmware_data.size());
                std::cout << "\r[ * ] Progress: " << pct << "% ("
                          << bytes_sent << "/" << firmware_data.size() << ")" << std::flush;
            }
        }

        // Send final empty block if last block was full
        if (firmware_data.size() % TFTP_BLOCK_SIZE == 0) {
            send_data(xfer_sock, client, block, nullptr, 0);
        }

        std::cout << std::endl
                  << "[ + ] Transfer complete! " << bytes_sent << " bytes sent."
                  << std::endl;
        SOCK_CLOSE(xfer_sock);
        return true;
    }

  public:
    TFTPServer() : sock(SOCK_INVALID), running(false)
    {
        std::memset(&server_addr, 0, sizeof(server_addr));
    }

    ~TFTPServer()
    {
        stop();
    }

    bool load_firmware(const std::string &path)
    {
        firmware_path = path;
        try {
            firmware_data = FileRead(path, std::ios::in | std::ios::binary);
        } catch (const std::exception &e) {
            std::cerr << "[ - ] Failed to load firmware: " << e.what() << std::endl;
            return false;
        }

        // Validate firmware header
        if (firmware_data.size() < sizeof(huawei_header)) {
            std::cerr << "[ - ] File too small for firmware header" << std::endl;
            return false;
        }

        const auto *hdr =
            reinterpret_cast<const huawei_header *>(firmware_data.data());
        if (hdr->magic_huawei != 0x504e5748) {
            std::cerr << "[ - ] Invalid firmware magic (expected HWNP)" << std::endl;
            return false;
        }

        std::cout << "[ + ] Firmware loaded: " << path << " ("
                  << firmware_data.size() << " bytes)" << std::endl;
        std::cout << "[ * ] Items: " << hdr->item_counts << std::endl;
        return true;
    }

    bool start(const std::string &bind_ip, uint16_t port)
    {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock == SOCK_INVALID) {
            std::cerr << "[ - ] Failed to create socket" << std::endl;
            return false;
        }

        int reuse = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char *>(&reuse), sizeof(reuse));

        server_addr.sin_family      = AF_INET;
        server_addr.sin_port        = htons(port);
        inet_pton(AF_INET, bind_ip.c_str(), &server_addr.sin_addr);

        if (bind(sock, reinterpret_cast<struct sockaddr *>(&server_addr),
                 sizeof(server_addr)) == SOCK_ERROR) {
            std::cerr << "[ - ] Failed to bind to " << bind_ip << ":" << port
                      << std::endl;
            SOCK_CLOSE(sock);
            sock = SOCK_INVALID;
            return false;
        }

        set_socket_timeout(sock, 1000);

        running = true;
        std::cout << "[ + ] TFTP server listening on " << bind_ip << ":" << port
                  << std::endl;
        std::cout << "[ * ] Waiting for device to request firmware..." << std::endl;
        std::cout << "[ * ] Press Ctrl+C to stop" << std::endl;
        return true;
    }

    void run()
    {
        char buf[1024];
        while (running) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);

            int n = recvfrom(sock, buf, sizeof(buf), 0,
                             reinterpret_cast<struct sockaddr *>(&client_addr),
                             &client_len);
            if (n < 4) {
                continue;
            }

            uint16_t opcode;
            std::memcpy(&opcode, buf, 2);
            opcode = ntohs(opcode);

            if (opcode == TFTP_RRQ) {
                std::string filename(buf + 2);
                handle_read_request(client_addr, filename);
            } else if (opcode == TFTP_WRQ) {
                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip,
                          sizeof(client_ip));
                std::cout << "[ * ] Write request from " << client_ip
                          << " (not supported)" << std::endl;
                send_error(sock, client_addr, 2, "Write not supported");
            }
        }
    }

    void stop()
    {
        running = false;
        if (sock != SOCK_INVALID) {
            SOCK_CLOSE(sock);
            sock = SOCK_INVALID;
        }
    }
};

static void
print_firmware_info(const std::string &path)
{
    try {
        Firmware firmware = {};
        firmware.ReadFlashFromFS(path);
        firmware.PrintHeader();
        firmware.PrintItems(true);
        firmware.CheckCRC32();
    } catch (const std::exception &e) {
        std::cerr << "[ - ] Error: " << e.what() << std::endl;
    }
}

int
main(int argc, char *argv[])
{
    auto usage_print = [&]() {
        usage(
            {
                argv[0],
                "[-i firmware.bin]",
                "[-s -b 192.168.1.10 -p 69 -f firmware.bin]",
            },
            {
                "-i  Show firmware info",
                "-s  Start TFTP server mode",
                "-b  Bind IP address (default: 192.168.1.10)",
                "-p  TFTP port (default: 69)",
                "-f  Path to firmware.bin",
            });
    };

    std::string path_fmw, bind_ip = "192.168.1.10";
    uint16_t port     = 69;
    bool finfo        = false;
    bool fserver      = false;

    for (int opt; (opt = getopt(argc, argv, "i:sf:b:p:")) != -1;) {
        switch (opt) {
            case 'i':
                path_fmw = optarg;
                finfo    = true;
                break;
            case 's':
                fserver = true;
                break;
            case 'f':
                path_fmw = optarg;
                break;
            case 'b':
                bind_ip = optarg;
                break;
            case 'p':
                port = static_cast<uint16_t>(std::stoi(optarg));
                break;
        }
    }

    if (!finfo && !fserver) {
        usage_print();
    }

    if (path_fmw.empty()) {
        usage_print();
    }

    if (finfo) {
        print_firmware_info(path_fmw);
        return 0;
    }

    if (fserver) {
        try {
            NetworkInit net;
            TFTPServer server;

            if (!server.load_firmware(path_fmw)) {
                return 1;
            }

            if (!server.start(bind_ip, port)) {
                return 1;
            }

            std::cout << std::endl;
            std::cout << "=== Huawei ONT Firmware Flash Instructions ===" << std::endl;
            std::cout << "1. Connect your PC to the ONT via Ethernet" << std::endl;
            std::cout << "2. Set your PC IP to " << bind_ip
                      << " (same subnet as ONT)" << std::endl;
            std::cout << "3. Power on the ONT while holding the reset button" << std::endl;
            std::cout << "4. The ONT will request the firmware via TFTP" << std::endl;
            std::cout << "5. Wait for transfer to complete, then release reset"
                      << std::endl;
            std::cout << "===============================================" << std::endl;
            std::cout << std::endl;

            server.run();

        } catch (const std::exception &e) {
            std::cerr << "[ - ] Error: " << e.what() << std::endl;
            return 1;
        }
    }

    return 0;
}
