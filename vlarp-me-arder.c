#include <stdio.h>
#include <strings.h>
#include <stdarg.h>
#include <string.h>
#include <malloc.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <syslog.h>

#include <unistd.h>
#include <assert.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

struct arphdr {
	unsigned short  ar_hrd;         /* format of hardware address   */
	unsigned short  ar_pro;         /* format of protocol address   */
	unsigned char   ar_hln;         /* length of hardware address   */
	unsigned char   ar_pln;         /* length of protocol address   */
	unsigned short  ar_op;          /* ARP opcode (command)         */

	unsigned char           ar_sha[ETH_ALEN];       /* sender hardware address      */
	unsigned char           ar_sip[4];              /* sender IP address    */
	unsigned char           ar_tha[ETH_ALEN];       /* target hardware address      */
	unsigned char           ar_tip[4];              /* target IP address    */

};
#define ARPHRD_ETHER 1
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

struct vlan_ethhdr {
	unsigned char        h_dest[ETH_ALEN];          /* destination eth addr      */
	unsigned char        h_source[ETH_ALEN];        /* source ether addr */
	unsigned short       h_vlan_proto;              /* Should always be 0x8100 */
	unsigned short       h_vlan_TCI;                /* Encapsulates priority and VLAN ID */
	unsigned short       h_vlan_encapsulated_proto; /* packet type ID field (or len) */
};


struct packet {
	struct vlan_ethhdr ether; // h_(dest|source|vlan_proto|vlan_TCI|vlan_encapsulated_proto)
	struct arphdr arp; // ar_(hrd|pro|hln|pln|op)
	//unsigned char		filler[14]; /* Maak het 64 bytes */
} __attribute__ ((__packed__));

struct floodline {
	struct floodline *next;
	struct packet p;
};
static int usinglog=0;

void mylog(int level,const char *format,...) {
	va_list ap;
	va_start(ap,format);
	if(!usinglog) {
		vfprintf(stderr,format,ap);
	} else {
		vsyslog(level,format,ap);
	}
	va_end(ap);
}

void deleteList(struct floodline *list) {
	struct floodline *next;
	while(list) {
		next=list->next;
		free(list);
		list=next;
	};
}

int readConf(const char * file,struct floodline **list) {
	FILE *f;
	int n;
	char buffer[1024];
	unsigned int dmac[6];
	unsigned int smac[6];
	unsigned int vlan;
	unsigned int sip[4];
	unsigned int dip[4];
	unsigned int arpop;
	assert(list!=NULL);
	if(*list) {
		deleteList(*list);
		*list=NULL;
	}
	f=fopen(file,"r");
	if(!f) return -1;
	bzero(buffer,sizeof(buffer));
	while(fgets(buffer,sizeof(buffer),f)>0) {
		n=sscanf(
			buffer,
			"%x:%x:%x:%x:%x:%x %x:%x:%x:%x:%x:%x %u %u.%u.%u.%u %u.%u.%u.%u %u",
			&dmac[0],&dmac[1],&dmac[2],&dmac[3],&dmac[4],&dmac[5],
			&smac[0],&smac[1],&smac[2],&smac[3],&smac[4],&smac[5],
			&vlan,
			&sip[0],&sip[1],&sip[2],&sip[3],
			&dip[0],&dip[1],&dip[2],&dip[3],
			&arpop
		);
		//mylog(LOG_INFO,"Read %d items\n",n);
		if(n==22) {
			int i;
			struct floodline *current;
			current=calloc(sizeof(current[0]),1);
			if(*list) {
				current->next=*list;
			}
			*list=current;
			/* Fill in hardware */
			for(i=0;i<6;i++) current->p.ether.h_dest[i]=(unsigned char)dmac[i];
			for(i=0;i<6;i++) current->p.ether.h_source[i]=(unsigned char)smac[i];
			current->p.ether.h_vlan_proto=htons(ETH_P_8021Q);
			current->p.ether.h_vlan_TCI=htons(vlan);
			current->p.ether.h_vlan_encapsulated_proto=htons(ETH_P_ARP);
			/* Fill in arpware */
			current->p.arp.ar_hrd=htons(ARPHRD_ETHER);
			current->p.arp.ar_pro=htons(ETH_P_IP);
			current->p.arp.ar_hln=6;
			current->p.arp.ar_pln=4;
			current->p.arp.ar_op=htons(arpop);
			for(i=0;i<6;i++) current->p.arp.ar_tha[i]=(unsigned char)dmac[i];
			for(i=0;i<4;i++) current->p.arp.ar_tip[i]=(unsigned char)dip[i];
			for(i=0;i<6;i++) current->p.arp.ar_sha[i]=(unsigned char)smac[i];
			for(i=0;i<4;i++) current->p.arp.ar_sip[i]=(unsigned char)sip[i];
		}
	}
	fclose(f);
	return 0;
}

void usage(void) {
	mylog(	LOG_INFO,
		"flood --device=|-i<ethernet device> --config=|-c<config file> [--master=|-m<masterfile>] [--interval=|-t<sendinterval>] [--poll=|-p<pollinterval]\n"
		"-m decides wether to wait for the existence of the file\n"
		"-p is the polling speed in seconds for that file\n"
		"-t is the seconds to wait between sends\n"
		"-c points to the condigurationfile\n"
	);
}

int rawsocket(const char *device) {
	int interface;
	struct ifreq    ifr;
	struct sockaddr_ll      sll;
	bzero(&ifr,sizeof(ifr));
	strncpy(ifr.ifr_name,device,sizeof(ifr.ifr_name));
	interface=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if (ioctl(interface, SIOCGIFINDEX, &ifr) == -1) {
		mylog(LOG_ERR,"Cannot find device\n");
		exit(1);
	}
	bzero(&sll,sizeof(sll));
	sll.sll_family          = AF_PACKET;
	sll.sll_ifindex         = ifr.ifr_ifindex;
	sll.sll_protocol        = htons(ETH_P_ALL);
	if (bind(interface, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
		mylog(LOG_ERR,"Cannot bind to interface\n");
		exit(1);
	}
	return interface;
}

/*
 * schaamteloos gepikt van keepalived
 * (Alhoewel dit gewoon standaard is)
 */
pid_t daemonize(void) {
	pid_t pid;
	int fd;
	/* In case of fork is error. */
	pid = fork();
	if (pid < 0) {
		syslog(LOG_INFO, "daemon: fork error");
		return -1;
	}

	/* In case of this is parent process. */
	if (pid != 0) {
		return pid;
	}

	/* Become session leader and get pid. */
	pid = setsid();
	if (pid < -1) {
		syslog(LOG_INFO, "xdaemon: setsid error");
		return -1;
	}


	/* File descriptor close. */
	fd = open("/dev/null", O_RDWR, 0);
	if (fd != -1) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > 2)
		close(fd);
	}
	umask(0);
	return 0;
}
/* Create the runnnig daemon pidfile */
int pidfile_write(char *pid_file, int pid) {
	FILE *pidfile = fopen(pid_file, "w");

	if (!pidfile) {
		mylog(LOG_ERR, "pidfile_write : Can not open %s pidfile", pid_file);
		return 0;
	}
	fprintf(pidfile, "%d\n", pid);
	fclose(pidfile);
	return 1;
}

/* Remove the running daemon pidfile */
void pidfile_rm(char *pid_file) {
	unlink(pid_file);
}


int main(int argc, char **argv) {
	int r;
	struct floodline *list;
	struct floodline *current;
	struct stat statbufold,statbufnew;
	char * conffile=NULL, *masterfile=NULL, *device=NULL, *pidfile=NULL;
	int sendinterval=1;
	int pollinterval=1;
	int daemon=0;
	int interface;
	int damaster=0;
	while(1) {
		int c;
		int option_index = 0;
		static struct option long_options[] = {
			{"pidfile", 1, 0, 'f'},
			{"daemon", 0, 0, 'd'},
			{"device", 1, 0, 'i'},
			{"config", 1, 0, 'c'},
			{"master", 1, 0, 'm'},
			{"interval", 1, 0, 't'},
			{"poll", 1, 0, 'p'},
			{0, 0, 0, 0}
		};
		c=getopt_long(argc,argv,"i:c:m:p:t:",long_options,&option_index);
		if(c==-1) break;
		switch(c) {
			case 'f':
				pidfile=strdup(optarg);
				break;
			case 'd':
				daemon=1;
				break;
			case 't':
				sendinterval=atoi(optarg);
				break;
			case 'p':
				pollinterval=atoi(optarg);
				break;
			case 'i':
				device=strdup(optarg);
				break;
			case 'c':
				conffile=strdup(optarg);
				break;
			case 'm':
				masterfile=strdup(optarg);
				break;
			default:
				mylog(LOG_ERR,"?? getopt returned character code 0x%x ??\n", c);
				usage();
				exit(1);
		}
	}
	if(sendinterval<1) {
		mylog(LOG_ERR,"send interval too low");
		usage();
		exit(3);
	}
	if(pollinterval<1) {
		mylog(LOG_ERR,"poll interval too low");
		usage();
		exit(3);
	}
	if(!conffile|!device) {
		mylog(LOG_ERR,"No conffile/masterfile/device");
		usage();
		exit(3);
	}

	/* Change directory to root. */
	chdir("/");
	r=stat(conffile,&statbufold);
	if(r) {
		mylog(LOG_ERR,"Could not stat conf file");
		usage();
		exit(2);
	}


	/* Test read it */
	list=NULL;
	readConf(conffile,&list);
	deleteList(list);
	list=NULL;

	if(daemon) {
		int r;
		usinglog=1;
		openlog("vlarp-me-arder",LOG_PID,LOG_DAEMON);
		r=daemonize();
		if(r>0) exit(0);
		if(r<0) {
			mylog(LOG_ERR,"daemonize failed");
		}
		if(pidfile) {
			pidfile_write(pidfile,getpid());
		}
	}


	bzero(&statbufold,sizeof(statbufold));

	interface=rawsocket(device);
	if(interface<0) {
		mylog(LOG_ERR,"Could not open device");
		exit(4);
	}

	while(1) {
		struct timeval t;
		if(masterfile) {
			/* Wacht totdat de masterfile er staat */
			do {
				r=stat(masterfile,&statbufnew);
				if(r) {
					if(damaster) {
						mylog(LOG_INFO,"I r no longer damaster");
						damaster=0;
					}
					t.tv_usec=0;
					t.tv_sec=pollinterval;
					select(0,NULL,NULL,NULL,&t);
				}
			} while(r);
			if(!damaster) {
				mylog(LOG_INFO,"I r damaster");
				damaster=1;
			}
		}
		/* Moeten we de config opnieuw inlezen? */
		r=stat(conffile,&statbufnew);
		if(statbufnew.st_ctime!=statbufold.st_ctime || statbufnew.st_mtime!=statbufold.st_mtime || statbufnew.st_ino!=statbufold.st_ino) {
			mylog(LOG_INFO,"Rereading conf file\n");
			readConf(conffile,&list);
			statbufold=statbufnew;
		}

		/* Stuur de pakketjes */
		for(current=list;current;current=current->next) {
			write(interface,&current->p,sizeof(current->p));
		}

		/* Delay */
		t.tv_usec=0;
		t.tv_sec=sendinterval;
		r=select(0,NULL,NULL,NULL,&t);
		if(r<0) break;
	}
	mylog(LOG_INFO,"shutdown");
	close(interface);
	if(pidfile) {
		pidfile_rm(pidfile);
	}
	return(0);
}
