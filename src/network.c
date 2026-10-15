#include<stdio.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/un.h>
#include<stdlib.h>
#include<unistd.h>

#define SOCKET_PATH "/tmp/mysocket"

int main(){
    printf("no idea what i am doing hope for the best\n");

    int sockfd;
    int acceptfd;
    struct sockaddr_un sockaddr;

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

    if(sockfd == -1){
        printf("socket creating failed\n");
        return 0;
    } else {
        printf("socket created successfully\n");
    }

    bzero(&sockaddr, sizeof(sockaddr));
    sockaddr.sun_family = AF_UNIX;
    strncpy(sockaddr.sun_path, SOCKET_PATH, sizeof(sockaddr.sun_path) - 1);

    unlink(SOCKET_PATH);  // remove any leftover socket file from a previous run

    if(0 != bind(sockfd, (struct sockaddr*)&sockaddr, sizeof(sockaddr))){
        printf("bind failed.....\n");
        exit(0);
    } else {
        printf("bind complete......\n");

        if(0 != listen(sockfd, 6)){
            printf("listening failed.....\n");
            exit(0);
        } else {
            printf("listening.............\n");

            socklen_t addrlen = sizeof(sockaddr);
            acceptfd = accept(sockfd, (struct sockaddr*)&sockaddr, &addrlen);
            if(acceptfd == -1){
                printf("oops something went wrong in accept part\n");
                exit(0);
            } else {
                printf("server accepted the client\n");
            }
        }
    }

    char buff[8];
    bzero(buff, 8);

    ssize_t readsize = read(acceptfd, buff, sizeof(buff)-1);
    if(readsize < 0){
      printf("file read failed");

    }else{
      buff[readsize] = '\0';
    }
    printf("the result got from the client is : %s\n", buff);

    close(acceptfd);
    close(sockfd);
    unlink(SOCKET_PATH);  // clean up the socket file
}
