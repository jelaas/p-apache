/*
 * File: support/pacc.c
 * Implements: compiler front-end to compile p-apache configurations

   Copyright Jens Låås, 2012

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <ap_config_layout.h>
	   
	   
	   struct {
		   char *CC, *LDFLAGS, *CFLAGS, *LIBS, *LD, *libexecdir;
		   char *cfg;
		   char src[1024];
	   } conf;

struct {
	char src[1024];
	char *obj, *bin;
	char *paobj;
} fn;

#ifndef LIBEXECDIR
#ifdef DEFAULT_EXP_LIBEXECDIR
#define LIBEXECDIR DEFAULT_EXP_LIBEXECDIR
#else
#define LIBEXECDIR "/usr/lib/apache"
#endif
#endif

int main(int argc, char **argv)
{
	char *compiledate, *p;
	char tfn[1024];
	char buf[1024];
	char cmd[2048];
	int n, fd;
	time_t now;
	FILE *pah, *f, *cfg;
	unsigned long checksum = 0;
	unsigned long checksum2 = 0;

	if(argc < 2) {
	usage:
		fprintf(stderr, "Usage: pacc <config>.conf\n");
		exit(1);
	}
	if(!strcmp(argv[1], "-h")) goto usage;
	if(!strcmp(argv[1], "--help")) goto usage;

	now = time(0);
	compiledate = asctime(gmtime(&now));
	p =strchr(compiledate, '\n');
	if(p) *p = 0;

	conf.CC = getenv("CC");
	conf.LDFLAGS = getenv("LDFLAGS");
	conf.CFLAGS = getenv("CFLAGS");
	conf.LDFLAGS = getenv("LDFLAG");
	conf.LIBS = getenv("LIBS");
	conf.LD = getenv("LD");
	conf.libexecdir = getenv("LIBEXECDIR");
	if(!conf.CC) conf.CC = "gcc";
	if(!conf.CFLAGS) conf.CFLAGS = "-Wall -Os -I" LIBEXECDIR;
	if(!conf.LDFLAGS) conf.LDFLAGS = "-static";
	if(!conf.LD) conf.LD = "gcc";
	if(!conf.LIBS) conf.LIBS = "-lpcre";
	if(!conf.libexecdir) conf.libexecdir = LIBEXECDIR;

	conf.cfg = argv[1];
	
	sprintf(fn.src, "/tmp/%s.c", basename(strdup(conf.cfg)));
	fn.paobj = "/tmp/pa.o";

	fn.obj = strdup(fn.src);
	fn.obj[strlen(fn.obj)-1] = 'o';
	
	fn.bin = strdup(conf.cfg);
	p = strstr(fn.bin, ".conf");
	if(!p) {
		printf("must end with .conf\n");
		exit(1);
	}
	strcpy(p, ".pa");

	sprintf(cmd, "%s -c -DPA_INTERNAL %s %s/pa.c -o %s", conf.CC, conf.CFLAGS, conf.libexecdir, fn.paobj);
	printf(">> %s\n", cmd);
	if(system(cmd)) {
		printf("Failed to compile object file from pa.c:\n  %s\n", cmd);
		exit(1);
	}
	printf("pa.o compiled\n");
	
	unlink(fn.src);
	f = fopen(fn.src, "a");
	if(!f) {
		printf("failed to open %s\n", fn.src);
		exit(1);
	}
	fprintf(f, "char const _TC[] = { ");
	{
		int fd;
		unsigned char buf[2];
		fd = open(conf.cfg, O_RDONLY);
		if(fd == -1) {
			printf("failed to open %s\n", conf.cfg);
			exit(1);
		}
		while(read(fd, buf, 1)==1) {
			fprintf(f, "%u,", buf[0]);
			
			/* incredibly stupid checksum calculation */
			checksum += buf[0];
			checksum2 ^= buf[0];
			checksum2 <<= 1;
		}
		checksum ^= checksum2;
	}
	close(fd);
	fprintf(f, "0 };\n");
	fprintf(f, "char const *_ID = \"");
	fprintf(f, "%lu\\n", checksum);
	fprintf(f, "\";\n");
	fprintf(f, "char const *_DATE = \"");
	fprintf(f, "%s\\n", compiledate);
	fprintf(f, "\";");

	fprintf(f, "\n#include <stdio.h>\n#include <string.h>\n#include <unistd.h>\n");
	
	/* copy pa.h */
	sprintf(tfn, "%s/pa.h", conf.libexecdir);
	pah = fopen(tfn, "r");
	while(!feof(pah)) {
		n = fread(buf, 1, sizeof(buf), pah);
		if(n >0) fwrite(buf, 1, n, f);
	}
	fclose(pah);
	
	fprintf(f, "int main(int argc, char **argv)\n{if(argc>1&&!strcmp(argv[1],\"--date\")){write(1,_DATE,strlen(_DATE));_exit(0);}if(argc>1&&!strcmp(argv[1],\"--id\")){write(1,_ID,strlen(_ID));_exit(0);}if(argc>1&&!strcmp(argv[1],\"-L\")){write(1,_TC,strlen(_TC));_exit(0);}if(argc>1&&!strcmp(argv[1],\"-D\"))debug();_rf_init();\n#line 0 \"%s\"\n", conf.cfg);
	
	cfg = fopen(conf.cfg, "r");
	if(!cfg) {
		printf("failed to open %s\n", conf.cfg);
		exit(1);
	}
	while(!feof(cfg)) {
		n = fread(buf, 1, sizeof(buf), cfg);
		if(n >0) fwrite(buf, 1, n, f);
	}
	fclose(cfg);
	
	fprintf(f, "fflush(stdout);_exit(0);}\n");
	fclose(f);

	sprintf(cmd, "%s -c %s %s -o %s", conf.CC, conf.CFLAGS, fn.src, fn.obj);
	printf(">> %s\n", cmd);
	if(system(cmd)) {
		printf("Failed to compile:\n  %s\n", cmd);
		exit(1);
	}

	sprintf(cmd, "%s %s -o %s %s %s %s", conf.LD, conf.LDFLAGS, fn.bin, fn.obj, fn.paobj, conf.LIBS);
	printf(">> %s\n", cmd);
	if(system(cmd)) {
		printf("Failed link:\n  %s\n", cmd);
		exit(1);
	}
	
	exit(0);
}
