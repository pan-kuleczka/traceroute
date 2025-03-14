#include <bits/stdc++.h>
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <unistd.h>

const int MAX_WAIT_TIME_MS = 1000;
const int MAX_TTL = 30;
const int ECHO_COUNT = 3;

void print_as_bytes(unsigned char *buff, ssize_t length)
{
    for (ssize_t i = 0; i < length; i++, buff++)
        printf("%.2x ", *buff);
}

// KOD Z WYKŁADU
uint16_t compute_icmp_checksum(const void *buff, int length)
{
    const uint16_t *ptr = (uint16_t *)buff;
    uint32_t sum = 0;
    assert(length % 2 == 0);
    for (; length > 0; length -= 2)
        sum += *ptr++;
    sum = (sum >> 16U) + (sum & 0xffffU);
    return (uint16_t)(~(sum + (sum >> 16U)));
}
// KONIEC KODU Z WYKŁADU

icmp createEchoHeader(int seq)
{
    icmp header;
    header.icmp_type = ICMP_ECHO;
    header.icmp_code = 0;
    header.icmp_hun.ih_idseq.icd_id = getpid();
    header.icmp_hun.ih_idseq.icd_seq = seq;
    header.icmp_cksum = 0;
    header.icmp_cksum = compute_icmp_checksum((uint16_t *)&header, sizeof(header));
    return header;
}

sockaddr_in createRecipientSockaddr(const std::string &address)
{
    struct sockaddr_in recipient;
    recipient.sin_family = AF_INET;
    int inet_pton_res = inet_pton(AF_INET, address.c_str(), &recipient.sin_addr);
    if (inet_pton_res <= 0)
        throw std::runtime_error("Invalid address");
    return recipient;
}

struct EchoResponse
{
    int32_t sender_ip;
    std::string sender_ip_str;
    bool success;
    int seq;
};

struct SocketWrapper
{
    int sockfd;

    SocketWrapper()
    {
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd < 0)
            throw std::runtime_error("socket() failed - are you root?");
    }

    ~SocketWrapper()
    {
        close(sockfd);
    }

    void setTTL(int ttl)
    {
        int setsockopt_res = setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        if (setsockopt_res < 0)
            throw std::runtime_error("setsockopt() failed");
    }

    bool pollReceive(int timeout_ms)
    {
        struct pollfd ps;
        ps.fd = sockfd;
        ps.events = POLLIN;
        ps.revents = 0;
        int ready = poll(&ps, 1, timeout_ms);

        if (ready < 0) // Error
            throw std::runtime_error("poll() failed");

        if (ready == 0) // Timeout
            return false;

        if ((ps.revents & POLLIN) == 0) // No data
            return false;

        return true;
    }

    void sendEchoRequest(const sockaddr_in &dest_addr, int seq)
    {
        icmp header = createEchoHeader(seq);
        ssize_t bytes_sent = sendto(sockfd, &header, sizeof(header), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (bytes_sent < 0)
            throw std::runtime_error("sendto() failed");
    }

    EchoResponse receiveEchoResponse()
    {
        uint8_t buffer[IP_MAXPACKET];
        struct sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);

        ssize_t packet_len = recvfrom(sockfd, buffer, IP_MAXPACKET, 0, (struct sockaddr *)&sender, &sender_len);
        if (packet_len < 0)
            throw std::runtime_error("recvfrom() failed");

        char sender_ip_str[20];
        inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));
        
        // Check the response type
        struct ip *ip_header = (struct ip *)buffer;
        uint8_t *icmp_packet = buffer + 4 * ip_header->ip_hl;
        struct icmp *icmp_header = (struct icmp *)icmp_packet;

        EchoResponse response;

        response.sender_ip = sender.sin_addr.s_addr;
        response.sender_ip_str = sender_ip_str;

        if (icmp_header->icmp_type == ICMP_ECHOREPLY)
        {
            response.success = true;
        }
        else if (icmp_header->icmp_type == ICMP_TIME_EXCEEDED)
        {
            response.success = false;

            // Get the original packet
            struct ip *original_ip_header = (struct ip *)(icmp_packet + 8);
            uint8_t *original_icmp_packet = icmp_packet + 8 + 4 * original_ip_header->ip_hl;
            struct icmp *original_icmp_header = (struct icmp *)original_icmp_packet;
            response.seq = original_icmp_header->icmp_seq;
        }
        else if (icmp_header->icmp_type == ICMP_ECHO)
        {
            // We pinged ourselves...
            response.success = true;
        }
        else
        {
            throw std::runtime_error("Unexpected ICMP type " + std::to_string(icmp_header->icmp_type));
        }

        return response;
    }
};

struct Timer
{
    std::chrono::high_resolution_clock::time_point start;

    void startTimer()
    {
        start = std::chrono::high_resolution_clock::now();
    }

    int elapsedMS()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start).count();
    }
};

int32_t main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <address>" << std::endl;
        return 1;
    }
    std::string address = argv[1];

    std::optional<SocketWrapper> socket;
    sockaddr_in recipient;

    try
    {
        socket.emplace();
        recipient = createRecipientSockaddr(address);
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    for (int ttl = 1; ttl <= MAX_TTL; ttl++)
    {
        socket->setTTL(ttl);

        int firstSeq = (ttl - 1) * ECHO_COUNT + 1;

        // Send echo requests
        for (int seq = firstSeq; seq < firstSeq + ECHO_COUNT; seq++)
            socket->sendEchoRequest(recipient, seq);

        // Start the timer
        Timer timer;
        timer.startTimer();

        int receivedSeqs = 0;
        int responseTimes[ECHO_COUNT];

        for(int i = 0; i < ECHO_COUNT; i++)
            responseTimes[i] = -1;

        std::set<std::string> responders;

        bool reachedDestination = false;
        int destinationResponseTime = -1;

        // Wait for responses
        while(timer.elapsedMS() < MAX_WAIT_TIME_MS)
        {
            int remainingTime = MAX_WAIT_TIME_MS - timer.elapsedMS();

            if (!socket->pollReceive(remainingTime))
                break; // Timeout
            
            EchoResponse response;

            // Receive the response
            try{
                response = socket->receiveEchoResponse();
            }
            catch(const std::exception &e)
            {
                std::cerr << "Error while receiving response: " << e.what() << std::endl;
                return -1;
            }

            if(response.success)
            {
                // We received a response from the destination, stop the traceroute
                reachedDestination = true;
                destinationResponseTime = timer.elapsedMS();
                break;
            }

            if (response.seq < firstSeq || response.seq >= firstSeq + ECHO_COUNT)
                continue; // This response is for a different TTL, ignore it

            int index = response.seq - firstSeq;
            if(responseTimes[index] == -1)
            {
                // This is the first response for this sequence number
                responseTimes[index] = timer.elapsedMS();
                receivedSeqs++;
            }
                
            responders.insert(response.sender_ip_str);

            if(receivedSeqs == ECHO_COUNT)
                break; // All responses received
        }

        std::string respondersStr;
        if(reachedDestination)
            respondersStr = address + " ";
        else
        {
            for(const auto &ip : responders)
                respondersStr += ip + " ";
            if(respondersStr.empty())
                respondersStr = "* ";
        }

        std::string responseTimeStr;
        if(reachedDestination)
            responseTimeStr = std::to_string(destinationResponseTime) + "ms";
        else if(receivedSeqs == 0)
            responseTimeStr = "";
        else if(receivedSeqs < ECHO_COUNT)
            responseTimeStr = "???";
        else
        {
            int avgResponseTime = 0;
            for(int i = 0; i < ECHO_COUNT; i++)
                avgResponseTime += responseTimes[i];
            avgResponseTime /= ECHO_COUNT;
            responseTimeStr = std::to_string(avgResponseTime) + "ms";
        }

        // Print the results
        std::cout << ttl << ". " << respondersStr << responseTimeStr << std::endl;
        if(reachedDestination) break;
    }

    return 0;
}
