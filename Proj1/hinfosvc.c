#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_BUFFER 1024

#define HOST_STR "/hostname"
#define CPU_STR "/cpu-name"
#define LOAD_STR "/load"

#define SYS_SYMB "\r\n"

#define OK "200 OK"
#define NOT_FOUND "404 Not Found"
#define BAD_METHOD "405 Method Not Allowed"

void error(char *msg){
    perror(msg);
    exit(EXIT_FAILURE);
}

char *response_ctor(int contentLen, char *statusCode){
    // VERSION + STATUS CODE\r\n + Content-Length: %d\n+Content-Type: text/plain;\r\n\r\n
    static char response[MAX_BUFFER];
    strcpy(response, "HTTP/1.1 ");
    strcat(response, statusCode);
    strcat(response, SYS_SYMB);
    char length[MAX_BUFFER];
    sprintf(length, "Content-Length: %d\n", contentLen);
    strcat(response, length);
    char *contentType = "Content-Type: text/plain;\r\n\r\n";
    strcat(response, contentType);
    return response;
}

void proc_load(int newsocket){
    char buffer[MAX_BUFFER];
    const char d[2] = " ";
    char* token;
    int i = 0;
    long int sum = 0, idle;
    FILE* fp = fopen("/proc/stat","r");
    fgets(buffer, MAX_BUFFER, fp);
    fclose(fp);
    token = strtok(buffer, d);
    while(token != NULL){
        token = strtok(NULL, d);
        if(token != NULL){
            sum += atol(token);
            if(i==3) idle = atol(token);
            i++;
        }
    }
    long double loadPercentage = 100 - idle * 100.0/(sum);

    sprintf(buffer, "%0.0Lf%%", loadPercentage);
    char *newbuffer = malloc(strlen(buffer) + 3);
    strcpy(newbuffer, buffer);
    strcat(newbuffer, "\n");

    int msglen = strlen(buffer);
    char *response = response_ctor(msglen, OK);
    write(newsocket, response, strlen(response));
    write(newsocket, newbuffer, strlen(newbuffer)+2);
}

void get_hostname(int newsocket){
    FILE *fp = popen("cat /proc/sys/kernel/hostname", "r");
    char buffer[MAX_BUFFER];

    fgets(buffer, MAX_BUFFER, fp);
    pclose(fp);
    int msglen = strlen(buffer) - 1;
    char *response = response_ctor(msglen, OK);
    write(newsocket, response, strlen(response));
    write(newsocket, buffer, strlen(buffer));
}

void get_cpu_name(int newsocket){
    char buffer[MAX_BUFFER];
    FILE *fp = popen("cat /proc/cpuinfo | grep 'model name'| head -n 1 | cut -d ' ' -f 4-", "r");
    fgets(buffer, MAX_BUFFER, fp);
    pclose(fp);
    int msglen = strlen(buffer) - 1;
    char *response = response_ctor(msglen, OK);

    write(newsocket, response, strlen(response));
    write(newsocket, buffer, strlen(buffer));
}

void connection_proccesing(FILE *stream, int newsocket){
    char buffer[MAX_BUFFER];
    char method[MAX_BUFFER];
    char uri[MAX_BUFFER];
    char version[MAX_BUFFER];

    fgets(buffer, MAX_BUFFER, stream);
    sscanf(buffer, "%s %s %s\n", method, uri, version);

    if(strcmp(method, "GET")){
        char *response = response_ctor(0, BAD_METHOD);
        write(newsocket, response, strlen(response));
        close(newsocket);
    }

    if(!strcmp(uri, HOST_STR)){
        get_hostname(newsocket);
        close(newsocket);
    } else if(!strcmp(uri, CPU_STR)){
        get_cpu_name(newsocket);
        close(newsocket);
    } else if(!strcmp(uri, LOAD_STR)){
        proc_load(newsocket);
        close(newsocket);
    } else {
        char *response = response_ctor(0, NOT_FOUND);
        write(newsocket, response, strlen(response));
        close(newsocket);
    }
}

void start_server(int port){
    int sockett, newsocket;
    struct sockaddr_in serveraddr;
    struct sockaddr_in clientaddr;

    FILE *stream;

    sockett = socket(AF_INET, SOCK_STREAM, 0);
    if(socket < 0) error("socket error");

    /* prevention of address in use error */
    int optval = 1;
    setsockopt(sockett, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));

    bzero((char *)&serveraddr, sizeof(serveraddr));

    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)port);

    if(bind(sockett, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
        error("bind error");
    if(listen(sockett, 5) < 0)
        error("listen error");

    int clientLen = sizeof(clientaddr);

    while(newsocket >= 0){
        newsocket = accept(sockett, (struct sockaddr *)&clientaddr, (socklen_t *)&clientLen);
        if(newsocket < 0)
            error("accept error");
        if((stream = fdopen(newsocket, "r+")) == NULL) error("fdopen error");
        connection_proccesing(stream, newsocket);
    }
}

int main(int argc, char const *argv[]){
    if(argc < 2) {
        fprintf(stderr, "No port argument found");
        return EXIT_FAILURE;
    }
    int port = atoi(argv[1]);
    start_server(port);

    return 0;
}