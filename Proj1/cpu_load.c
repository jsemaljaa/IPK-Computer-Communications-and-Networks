#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAX_BUFFER 100

void proc_load(){
    char str[MAX_BUFFER];
	const char d[2] = " ";
	char* token;
	int i = 0;
	long int sum = 0, idle;
	long double loadPercentage;
	FILE* fp = fopen("/proc/stat","r");
	i = 0;
	fgets(str, MAX_BUFFER, fp);
	fclose(fp);
	token = strtok(str,d);
	while(token!=NULL){
		token = strtok(NULL,d);
		if(token!=NULL){
			sum += atoi(token);
			if(i==3) idle = atoi(token);
			i++;
		}
    }
    loadPercentage = 100 - (idle)*100.0/(sum);
	printf("%.0Lf%%\n", loadPercentage);
    // printf("%Lf%%\n", loadPercentage);
    return;
}

void get_hostname(){
    FILE* fp = fopen("/proc/sys/kernel/hostname", "r");
    char buffer[MAX_BUFFER]; // hostname max 100 symbols
    fgets(buffer, MAX_BUFFER, fp);
    fclose(fp);
    printf("%s", buffer);
    return;
}

void get_cpu_name(){
    char buffer[MAX_BUFFER];
    //FILE *fp = popen("cat /proc/cpuinfo | grep 'model name'| head -n 1 | awk '{for(i=4;i<=NF;++i) printf $i""FS;print ""}'", "r");
    FILE *fp = popen("cat /proc/cpuinfo | grep 'model name'| head -n 1 | cut -d ' ' -f 4-", "r");
    if(fp == NULL) {
        fprintf(stderr, "Unable to get hostname");
        return;
    }    
    while(fgets(buffer, MAX_BUFFER, fp)){
        printf("%s", buffer);
    }
    pclose(fp);
    return;
}

int main(int argC,char* argV[])
{
    proc_load();
    get_hostname();
	get_cpu_name();
	return 0;
}