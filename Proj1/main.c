#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#define BUFFER_SIZE 50

int main(int argc, char **argv)
{
  int   file;
  char  buffer[BUFFER_SIZE];
  int   read_size;

  if (argc < 2)
    {
      fprintf(stderr, "Error: usage: ./cat filename\n");
      return (-1);
    }
  file = open(argv[1], O_RDONLY);
  if (file == -1)
    {
      fprintf(stderr, "Error: %s: file not found\n", argv[1]);
      return (-1);
    }
  for(int j = 0; j < 3; ++j){
    while ((read_size = read(file, buffer, BUFFER_SIZE)) > 0)
    write(1, &buffer, read_size);

    rewind(file);
    printf("update...\n");
    sleep(0.1);  
  }

  close(file);
  return (0);
}

// #include <stdio.h>
// #include <stdlib.h>

// FILE *popen(const char *command, const char *mode);
// int pclose(FILE *stream);

// int main(void)
// {
//     FILE *cmd;
//     char result[1024];

//     cmd = popen("grep 'cpu' /proc/stat", "r");
//     if (cmd == NULL) {
//         perror("popen");
//         exit(EXIT_FAILURE);
//     }
//     while (fgets(result, sizeof(result), cmd)) {
//         printf("%s", result);
//     }
//     pclose(cmd);
//     return 0;
// }


// #include<stdlib.h>
// #include<string.h>
// #include<unistd.h>
// #include<stdio.h>

// void proc_load(){
//     char str[100];
// 	const char d[2] = " ";
// 	char* token;
// 	int i = 0;
// 	long int sum = 0, idle, lastSum = 0,lastIdle = 0;
// 	long double idleFraction;
// 	FILE* fp = fopen("/proc/stat","r");
// 	i = 0;
// 	fgets(str,100,fp);
// 	fclose(fp);
// 	token = strtok(str,d);
// 	sum = 0;
// 	while(token!=NULL){
// 		token = strtok(NULL,d);
// 		if(token!=NULL){
// 			sum += atoi(token);
// 			if(i==3) idle = atoi(token);
// 			i++;
// 		}
// 	}
	
//     idleFraction = 100 - (idle-lastIdle)*100.0/(sum-lastSum);
// 	printf("%.0Lf%%\n", idleFraction);
// }

// int main(int argC,char* argV[])
// {
// 	proc_load();
// 	return 0;
// }