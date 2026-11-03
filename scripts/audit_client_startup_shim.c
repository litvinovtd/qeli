#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
static __thread int inside;
ssize_t read(int fd, void *buf, size_t count) {
 ssize_t (*real_read)(int,void*,size_t)=dlsym(RTLD_NEXT,"read");
 const char *root=getenv("QELI_STARTUP_FIXTURE");
 if(root && !inside) {
  inside=1;
  char link[64],path[4096],target[4096],marker[4096],release[4096];
  snprintf(link,sizeof(link),"/proc/self/fd/%d",fd);
  ssize_t n=readlink(link,path,sizeof(path)-1);
  snprintf(target,sizeof(target),"%s/client.ini",root);
  if(n>=0)path[n]=0;
  if(n>=0 && !strcmp(path,target)) {
   snprintf(marker,sizeof(marker),"%s/entered",root);
   int m=open(marker,O_WRONLY|O_CREAT|O_APPEND,0600);
   if(m>=0){write(m,"1",1);close(m);}
   snprintf(release,sizeof(release),"%s/release",root);
   const char *mode=getenv("QELI_STARTUP_MODE");
   if(!mode || strcmp(mode,"oversize")) {
    struct timespec pause={0,20000000};
    for(int i=0;i<750 && access(release,F_OK)!=0;i++)nanosleep(&pause,0);
   }
   if(mode && (!strcmp(mode,"fault") || !strcmp(mode,"oversize"))) {
    inside=0;errno=EIO;return -1;
   }
  }
  inside=0;
 }
 return real_read(fd,buf,count);
}
