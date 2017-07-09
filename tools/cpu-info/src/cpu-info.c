#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include "sys/types.h"
#include "sys/sysinfo.h"

int main(void)
{
    long double a[4], b[4], loadavg;
    long long totalPhysMem;
    long long physMemUsed;
    long long virtualMemUsed;
    FILE *fp;
    char dump[50];
    struct sysinfo memInfo;

    for(;;)
    {
        fp = fopen("/proc/stat","r");
        fscanf(fp,"%*s %Lf %Lf %Lf %Lf",&a[0],&a[1],&a[2],&a[3]);
        fclose(fp);
        sleep(1);

        fp = fopen("/proc/stat","r");
        fscanf(fp,"%*s %Lf %Lf %Lf %Lf",&b[0],&b[1],&b[2],&b[3]);
        fclose(fp);

        loadavg = ((b[0]+b[1]+b[2]) - (a[0]+a[1]+a[2])) / ((b[0]+b[1]+b[2]+b[3]) - (a[0]+a[1]+a[2]+a[3]));
        printf("CPU usage: %Lf\n",loadavg);

        sysinfo (&memInfo);

	totalPhysMem = memInfo.totalram;
        totalPhysMem *= memInfo.mem_unit;

	physMemUsed = memInfo.totalram - memInfo.freeram;
	physMemUsed *= memInfo.mem_unit;

        virtualMemUsed = memInfo.totalram - memInfo.freeram;
        virtualMemUsed += memInfo.totalswap - memInfo.freeswap;
        virtualMemUsed *= memInfo.mem_unit;

	printf("Total Physical Mem: %ld bytes\n",totalPhysMem);
	printf("Pysical Mem usage: %ld bytes\n",physMemUsed);
	printf("virtual Mem Used: %ld bytes\n",virtualMemUsed);


        sleep(1);
        printf("\e[1;1H\e[2J");
    }

    return 0;

}
