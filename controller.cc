#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <mutex>
#include <unistd.h>

#include "src/ue_packet_handler.h"
#include "src/gnb_packet_handler.h"
#include "src/json_packet_maker.h"


#define LOOPBACK_IP ("127.123.123.24")

#define FAKE_UE_PORT (8081)
#define FAKE_gNB_PORT (9091)
#define FAKE_UE_SERVER_PORT (8080)
#define FAKE_gNB_SERVER_PORT (9090)

enum RELAY_DIR 
{
    FROM_FAKE_UE,
    FROM_FAKE_gNB
};

struct sockaddr_in fake_UE_server_addr;
struct sockaddr_in fake_gNB_server_addr;
struct sockaddr_in fake_UE_addr, fake_gNB_addr;

struct sockaddr_in scenario_handler_addr;

int fake_UE_server_sock;
int fake_gNB_server_sock;

int scenario_handler_sock;

int msg_count = 10;
std::string packet2send;


void* worker(void *arg) {
    static std::mutex m;
    std::cout << "Thread Created!\n";

    int *fake_src_sock, *fake_dst_sock;
    struct sockaddr_in *fake_src_addr, *fake_dst_addr;

    enum RELAY_DIR dir_v = *(enum RELAY_DIR *)arg;

    if (dir_v==FROM_FAKE_UE) {
        fake_src_sock=&fake_UE_server_sock; 
        fake_dst_sock=&fake_gNB_server_sock;

        fake_src_addr=&fake_UE_addr;
        fake_dst_addr=&fake_gNB_addr;
    }
    else if (dir_v==FROM_FAKE_gNB) { /*(uintptr_t)arg==21*/
        fake_src_sock=&fake_gNB_server_sock; 
        fake_dst_sock=&fake_UE_server_sock;

        fake_src_addr=&fake_gNB_addr;
        fake_dst_addr=&fake_UE_addr;
    }else {
        std::cerr << "Wrong argument to worker" << std::endl;
        return NULL;
    }

    while(1) {
        uint8_t buf[65535];
        socklen_t sn=sizeof(*fake_src_addr);

        int result;
        asn1::json_writer * json_buffer = new asn1::json_writer;
        std::cout << "Waiting" <<std::endl;
        int n=recvfrom(*fake_src_sock,buf,sizeof(buf),0,(struct sockaddr *)fake_src_addr,&sn);

        m.lock();

        json_buffer->start_array();
        if(dir_v == FROM_FAKE_UE){  //Target gNB's packet is arrive here
            result = gNB::decode_packet(buf, n, *json_buffer);
        }else if(dir_v ==FROM_FAKE_gNB){  //Target UE's packet is arrive here
            result = UE::decode_packet(buf, n, *json_buffer);
        }else{
            std::cerr << "Error: Undefined dir_v!"<< std::endl;
        }
        json_buffer->end_array();

        std::string to_scenario_handler = json_buffer->to_string();

        sendto(scenario_handler_sock, to_scenario_handler.c_str(), to_scenario_handler.length(),0, (struct sockaddr *)&scenario_handler_addr, sizeof(scenario_handler_addr));

        uint8_t buf2[65535];
        socklen_t sn2= sizeof(scenario_handler_addr);
        int n2 = recvfrom(scenario_handler_sock, buf2, sizeof(buf2), 0, (struct sockaddr *)&scenario_handler_addr, &sn2);


        if(buf2[0] == 0)
        {
            std::cout << "Relay" <<std::endl;
            if(n>0 && fake_dst_addr->sin_port>0) {
                if(result == 0)
                {
                    sendto(*fake_dst_sock,buf,n,0,(struct sockaddr *)fake_dst_addr,sizeof(*fake_dst_addr));

                    printf("fake_src_sock: %d, fake_dst_sock: %d, fake_dst_addr port: %d, fake_src_addr port: %d, size: %d\n", *fake_src_sock, *fake_dst_sock, fake_dst_addr->sin_port, fake_src_addr->sin_port, n);
                }
            }
        }else if(buf2[0] == 1)
        {
            //Handle Spoofing message here
            char json_char[65535];
            std::cout << "Spoof" << std::endl;
            uint8_t* spoofed_msg;

            for (int i=0; i<n2-1; i++) {
                json_char[i] = (char)buf2[i+1];
            }
            std::string json_string = json_char;

            spoofed_msg = jsonPacketMaker::json_to_packet(json_string, buf, n);

            if(n>0 && fake_dst_addr->sin_port>0) {
                sendto(*fake_dst_sock,spoofed_msg,n2-1,0,(struct sockaddr *)fake_dst_addr,sizeof(*fake_dst_addr));

                printf("fake_src_sock: %d, fake_dst_sock: %d, fake_dst_addr port: %d, fake_src_addr port: %d, size: %d\n", *fake_src_sock, *fake_dst_sock, fake_dst_addr->sin_port, fake_src_addr->sin_port, n);
            }
        }

        delete json_buffer;

        m.unlock();
    }
    return NULL;
};

int main(int argc, char *argv[]) {
    memset(&fake_UE_addr,0,sizeof(struct sockaddr_in));
    memset(&fake_UE_server_addr,0,sizeof(struct sockaddr_in));
    memset(&fake_gNB_addr,0,sizeof(struct sockaddr_in));
    memset(&fake_gNB_server_addr,0,sizeof(struct sockaddr_in));

    fake_UE_server_sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_IP);
    fake_gNB_server_sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_IP);
    scenario_handler_sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_IP);

    fake_UE_addr.sin_family=AF_INET;
    fake_UE_addr.sin_addr.s_addr=inet_addr(LOOPBACK_IP);
    fake_UE_addr.sin_port=htons(FAKE_UE_PORT);

    fake_gNB_addr.sin_family=AF_INET;
    fake_gNB_addr.sin_addr.s_addr=inet_addr(LOOPBACK_IP);
    fake_gNB_addr.sin_port=htons(FAKE_gNB_PORT);

    fake_UE_server_addr.sin_family=AF_INET;
    fake_UE_server_addr.sin_addr.s_addr=inet_addr(LOOPBACK_IP);
    fake_UE_server_addr.sin_port=htons(FAKE_UE_SERVER_PORT);

    scenario_handler_addr.sin_family=AF_INET;
    scenario_handler_addr.sin_addr.s_addr = inet_addr("127.0.0.3");
    scenario_handler_addr.sin_port = htons(8080);

    if(bind(fake_UE_server_sock,(struct sockaddr *)&fake_UE_server_addr,sizeof(fake_UE_server_addr))==-1) {
        printf("Bind fake_UE_server_sock Error!\n");
        exit(2);
    }

    fake_gNB_server_addr.sin_family=AF_INET;
    fake_gNB_server_addr.sin_addr.s_addr=inet_addr(LOOPBACK_IP);
    fake_gNB_server_addr.sin_port=htons(FAKE_gNB_SERVER_PORT);
    if(bind(fake_gNB_server_sock,(struct sockaddr *)&fake_gNB_server_addr,sizeof(fake_gNB_server_addr))==-1) {
        printf("Bind fake_gNB_server_sock Error!\n");
        exit(3);
    }

    pthread_t UE2gNB_proc, gNB2UE_proc;
    enum RELAY_DIR argv1 = FROM_FAKE_UE;
    enum RELAY_DIR argv2 = FROM_FAKE_gNB;
    pthread_create(&UE2gNB_proc, NULL, worker, (void*)(&argv1));
    pthread_create(&gNB2UE_proc, NULL, worker, (void*)(&argv2));

    pthread_join(UE2gNB_proc, NULL);
    pthread_join(gNB2UE_proc, NULL);
    return 0;
}
