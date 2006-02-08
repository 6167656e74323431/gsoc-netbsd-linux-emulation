/*
 * IMPORTANT: READ BEFORE DOWNLOADING, COPYING, INSTALLING OR USING. By downloading, copying, installing or
 * using the software you agree to this license. If you do not agree to this license, do not download, install,
 * copy or use the software. 
 *
 * Intel License Agreement 
 *
 * Copyright (c) 2000, Intel Corporation
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that
 * the following conditions are met: 
 *
 * -Redistributions of source code must retain the above copyright notice, this list of conditions and the
 *  following disclaimer. 
 *
 * -Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *  following disclaimer in the documentation and/or other materials provided with the distribution. 
 *
 * -The name of Intel Corporation may not be used to endorse or promote products derived from this software
 *  without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE. 
 */
#include "config.h"

#define EXTERN

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include "util.h"

/*
 * NOTE: THIS IS A WORK IN PROGRESS. 
 *
 * For now, you must manually enter the host and target send and recv patterns 
 * (shown in the code below) beginning at line 104.  By default, this code will 
 * simulate the TCP traffic generated by an 8K iSCSI read between host and target.
 */

#define NUM_ITERS_DEFAULT         200
#define VERBOSE_FREQ_DEFAULT      20
#define PORT_DEFAULT              5001
#define HOST_SEND_PATTERN_DEFAULT "48"        /*  send iSCSI command PDU (SCSI READ) */
#define TARG_RECV_PATTERN_DEFAULT "48"
#define TARG_SEND_PATTERN_DEFAULT "48+8192"   /*  phase collapsed 8K data + status */
#define HOST_RECV_PATTERN_DEFAULT "48+8192" 

/*
 * Constants
 */

#define toSeconds(t) (t.tv_sec + (t.tv_usec/1000000.))
#define MAX_PATTERN_LEN 1024 
#define MAX_BUFFS MAX_PATTERN_LEN/2 


char usage[] = "usage: -t   <target IP>         I/O target\n"
               "       -hsp <host send pattern> e.g., 48\n"
               "       -tsp <targ recv pattern> e.g., 48\n"
               "       -hsp <targ repl pattern> e.g.. 8240\n"
               "       -hsp <host recv pattern> e.g., 48+8192\n"
               "       -n   <num iter>          number of iterations\n"
               "       -v   <freq>              verbose mode\n"
               "       -p   <port>              port number\n"
               "\nNOTE: The pattern args are not yet implemented.\n"
               "      You must manually edit usocktest.c to change\n"
               "      the request pattern which, by default, generates\n"
               "      TCP traffic identical to an 32 MB iSCSI read\n"
               "      that uses 8KB data PDUs.\n";

int main(int argc, char *argv[]) {
  int i, j, n;
  char HostSendPattern[MAX_PATTERN_LEN];
  char HostRecvPattern[MAX_PATTERN_LEN];
  char TargSendPattern[MAX_PATTERN_LEN];
  char TargRecvPattern[MAX_PATTERN_LEN];
  int HostSendSize[MAX_BUFFS];
  int HostRecvSize[MAX_BUFFS];
  int TargSendSize[MAX_BUFFS];
  int TargRecvSize[MAX_BUFFS];
  unsigned char* HostSendBuff[MAX_BUFFS];
  unsigned char* HostRecvBuff[MAX_BUFFS];
  unsigned char* TargSendBuff[MAX_BUFFS];
  unsigned char* TargRecvBuff[MAX_BUFFS];
  int NumHostSendBuffs;
  int NumHostRecvBuffs;
  int NumTargSendBuffs;
  int NumTargRecvBuffs;
  char ctrlBufferSend[MAX_PATTERN_LEN];
  char ctrlBufferRecv[MAX_PATTERN_LEN];
  unsigned ctrlBuffSize = MAX_PATTERN_LEN;
  struct timeval t_start, t_stop;
  double time;
  iscsi_socket_t iscsi_sock, iscsi_sock_new;
  int HostSendTotal, HostRecvTotal;
  int TargRecvTotal, TargSendTotal;
  int IsTarget;
  int Port = PORT_DEFAULT;
  int NumIters = NUM_ITERS_DEFAULT;
  int VerboseFreq = VERBOSE_FREQ_DEFAULT;
  char TargetIP[64] = "";

  /*
   * Parse command line
   */

  strcpy(HostSendPattern, HOST_SEND_PATTERN_DEFAULT);
  strcpy(HostRecvPattern, HOST_RECV_PATTERN_DEFAULT);
  strcpy(TargSendPattern, TARG_SEND_PATTERN_DEFAULT);
  strcpy(TargRecvPattern, TARG_RECV_PATTERN_DEFAULT);
  for (i=1; i<argc; i++) {
    if (!strcmp(argv[i], "-t")) {
      i++; strcpy(TargetIP, argv[i]);
    } else if (!strcmp(argv[i], "-p")) {
      i++; sscanf(argv[i], "%u", &Port);
    } else if (!strcmp(argv[i], "-n")) {
      i++; sscanf(argv[i], "%u", &NumIters);
    } else if (!strcmp(argv[i], "-v")) {
      i++; sscanf(argv[i], "%u", &VerboseFreq);
    } else {
      PRINT("Unknown option \"%s\"\n", argv[i]);
      PRINT("%s\n", usage);
      return -1;
    }
  }
  if (argc == 1) PRINT("%s\n", usage);
  IsTarget = (strlen(TargetIP)>0)?0:1;

  /* 
   * Convert command line string patterns here.  For now, you must 
   * manually enter these below.
   */

  NumHostSendBuffs = 1;
  HostSendSize[0]  = 48;
  NumTargRecvBuffs = 1;
  TargRecvSize[0]  = 48;
  NumHostRecvBuffs = 2;
  HostRecvSize[0]  = 48;
  HostRecvSize[1]  = 524288;
  NumTargSendBuffs = 2;
  TargSendSize[0]  = 48;
  TargSendSize[1]  = 524288;

  /* 
   * Create/bind/listen
   */

  if (iscsi_sock_create(&iscsi_sock)!=0) {
    TRACE_ERROR("iscsi_sock_create() failed\n");
    return -1;
  }
  if (IsTarget) {
    if (iscsi_sock_bind(iscsi_sock, Port)!=0) {
      TRACE_ERROR("iscsi_sock_bind() failed\n");
      return -1;
    }
    if (iscsi_sock_listen(iscsi_sock)!=0) {
      TRACE_ERROR("iscsi_sock_listen() failed\n");
      return -1;
    }
  }

  /* 
   * Accept connection
   */

accept:	
  if (IsTarget) {
    PRINT("Waiting for TCP connection on port %u\n", Port);
    if(iscsi_sock_accept(iscsi_sock, &iscsi_sock_new)!=0) {
      TRACE_ERROR("iscsi_sock_accept() failed\n");
      return -1;
    }
    PRINT("Connection accepted\n");
  } else {
    printf("Connecting to %s\n", TargetIP);
    if(iscsi_sock_connect(iscsi_sock, TargetIP, Port)!=0) {
      TRACE_ERROR("iscsi_sock_connect() failed\n");
      return -1;
    }
    PRINT("Connected\n");
    iscsi_sock_new = iscsi_sock;
  }

  /*
   * Host/Target handshake for test parameters
   */

  if (!IsTarget) {
    TRACE(TRACE_DEBUG, "Sending test parameters\n");
    sprintf(ctrlBufferSend, "%s:%s:%s:%s:%i:%i:%i",
            HostSendPattern, HostRecvPattern, TargSendPattern, TargRecvPattern,
            NumIters, VerboseFreq, Port);
    if ((n=iscsi_sock_msg(iscsi_sock_new, 1, ctrlBuffSize, ctrlBufferSend, 0))!=ctrlBuffSize) {
      TRACE_ERROR("iscsi_sock_msg() failed\n");
      return -1;
    }
    if ((n=iscsi_sock_msg(iscsi_sock_new, 0, ctrlBuffSize, ctrlBufferRecv, 0))!=ctrlBuffSize) {
      TRACE_ERROR("iscsi_sock_msg() failed\n");
      return -1;
    }
    TRACE(TRACE_DEBUG, "Test parameters sent\n");
  } else {
    char *ptr, *delim;

    TRACE(TRACE_DEBUG, "Receiving test parameters\n");
    if ((n=iscsi_sock_msg(iscsi_sock_new, 0, ctrlBuffSize, ctrlBufferRecv, 0))!=ctrlBuffSize) {
      TRACE_ERROR("iscsi_sock_msg() failed\n");
      return -1;
    }
    ptr = ctrlBufferRecv; 
    delim = strchr(ptr, ':');
    strncpy(HostSendPattern, ptr, delim-ptr+1); HostSendPattern[delim-ptr] = 0x0; ptr = delim+1;
    delim = strchr(ptr, ':');
    strncpy(HostRecvPattern, ptr, delim-ptr+1); HostRecvPattern[delim-ptr] = 0x0; ptr = delim+1;
    delim = strchr(ptr, ':');
    strncpy(TargSendPattern, ptr, delim-ptr+1); TargSendPattern[delim-ptr] = 0x0; ptr = delim+1;
    delim = strchr(ptr, ':');
    strncpy(TargRecvPattern, ptr, delim-ptr+1); TargRecvPattern[delim-ptr] = 0x0; ptr = delim+1;
    sscanf(ptr, "%i:%i", &NumIters, &VerboseFreq);
    if ((n=iscsi_sock_msg(iscsi_sock_new, 1, ctrlBuffSize, ctrlBufferSend, 0))!=ctrlBuffSize) {
      TRACE_ERROR("iscsi_sock_msg() failed\n");
      return -1;
    }
    TRACE(TRACE_DEBUG, "Test parameters received\n");
  }

  /* 
   * Check Arguments
   */
 
  HostSendTotal = 0; for (i=0; i<NumHostSendBuffs; i++) HostSendTotal += HostSendSize[i];
  TargRecvTotal = 0; for (i=0; i<NumTargRecvBuffs; i++) TargRecvTotal += TargRecvSize[i];
  if (HostSendTotal != TargRecvTotal) {
    TRACE_ERROR("Host sending size (%i) > Target receiving size (%i)\n", 
                HostSendTotal, TargRecvTotal); 
    return -1;
  }
  HostRecvTotal = 0; for (i=0; i<NumHostRecvBuffs; i++) HostRecvTotal += HostRecvSize[i];
  TargSendTotal = 0; for (i=0; i<NumTargSendBuffs; i++) TargSendTotal += TargSendSize[i];
  if (HostRecvTotal != TargSendTotal) {
    TRACE_ERROR("Host receiving size (%i) > Target sending size (%i)\n", 
                HostRecvTotal, TargSendTotal);
    return -1;
  }
  TRACE(TRACE_DEBUG, "HostSendPattern: \"%s\"\n", HostSendPattern);
  TRACE(TRACE_DEBUG, "HostRecvPattern: \"%s\"\n", HostRecvPattern);
  TRACE(TRACE_DEBUG, "TargRecvPattern: \"%s\"\n", TargRecvPattern);
  TRACE(TRACE_DEBUG, "TargSendPattern: \"%s\"\n", TargSendPattern);
  TRACE(TRACE_DEBUG, "NumIters:        %i\n", NumIters);
  TRACE(TRACE_DEBUG, "VerboseFreq:     %i\n", VerboseFreq);
  TRACE(TRACE_DEBUG, "HostSendTotal:   %i bytes\n", HostSendTotal);
  TRACE(TRACE_DEBUG, "HostRecvTotal:   %i bytes\n", HostRecvTotal);

  /*
   * Allocate buffers
   */

  for (i=0; i<NumHostSendBuffs; i++)
    if ((HostSendBuff[i]=iscsi_malloc(HostSendSize[i]))==NULL) {
      TRACE_ERROR("out of memory\n");
      return -1;
    }
  for (i=0; i<NumHostRecvBuffs; i++)
    if ((HostRecvBuff[i]=iscsi_malloc(HostRecvSize[i]))==NULL) {
      TRACE_ERROR("out of memory\n");
      return -1;
    }
  for (i=0; i<NumTargSendBuffs; i++)
    if ((TargSendBuff[i]=iscsi_malloc(TargSendSize[i]))==NULL) {
      TRACE_ERROR("out of memory\n");
      return -1;
    }
  for (i=0; i<NumTargRecvBuffs; i++)
    if ((TargRecvBuff[i]=iscsi_malloc(TargRecvSize[i]))==NULL) {
      TRACE_ERROR("out of memory\n");
      return -1;
    }


  /* 
   * Begin I/O
   */


  gettimeofday(&t_start, 0);
  for (i=0; i<NumIters; i++) {
    TRACE(TRACE_DEBUG, "begin iteration %i\n", i);
    if (!IsTarget) {

      /*  Send to target */

      for (j=0; j<NumHostSendBuffs; j++) {
        if (iscsi_sock_msg(iscsi_sock_new, 1, HostSendSize[j], HostSendBuff[j], 0)!= HostSendSize[j]) {
          TRACE_ERROR("iscsi_sock_msg() failed\n");
          return -1;
        }
        TRACE(TRACE_DEBUG, "Tx HostSendBuff[%i] (size %i)\n", j, HostSendSize[j]);
      }

      /*  Recv from target */

      for (j=0; j<NumHostRecvBuffs; j++) {
        if (iscsi_sock_msg(iscsi_sock_new, 0, HostRecvSize[j], HostRecvBuff[j], 0)!= HostRecvSize[j]) {
          TRACE_ERROR("iscsi_sock_msg() failed\n");
          return -1;
        }
        TRACE(TRACE_DEBUG, "Rx HostRecvBuff[%i] (size %i)\n", j, HostRecvSize[j]);
      }
    } else {

      /*  Recv from host */

      for (j=0; j<NumTargRecvBuffs; j++) {
        if (iscsi_sock_msg(iscsi_sock_new, 0, TargRecvSize[j], TargRecvBuff[j], 0)!= TargRecvSize[j]) {
          TRACE_ERROR("iscsi_sock_msg() failed\n");
          return -1;
        }
        TRACE(TRACE_DEBUG, "Rx TargRecvBuff[%i] (size %i)\n", j, TargRecvSize[j]);
      }

      /*  Send to host */

      for (j=0; j<NumTargSendBuffs; j++) {
        if (iscsi_sock_msg(iscsi_sock_new, 1, TargSendSize[j], TargSendBuff[j], 0)!= TargSendSize[j]) {
          TRACE_ERROR("iscsi_sock_msg() failed\n");
          return -1;
        }
        TRACE(TRACE_DEBUG, "Tx TargSendBuff[%i] (size %i)\n", j, TargSendSize[j]);
      }
    }  
    if ((!IsTarget)&&((i+1)%VerboseFreq==0)) {
      PRINT("Iter %i: %i total bytes sent, %i total bytes recv\n", 
            i+1, HostSendTotal*(i+1), HostRecvTotal*(i+1));
    }
    TRACE(TRACE_DEBUG, "end iteration %i\n", i);
  }
  gettimeofday(&t_stop, 0);

  /*
   * End I/O
   */


  /*  Free buffers */

  for (i=0; i<NumHostSendBuffs; i++) iscsi_free(HostSendBuff[i]);
  for (i=0; i<NumHostRecvBuffs; i++) iscsi_free(HostRecvBuff[i]);
  for (i=0; i<NumTargSendBuffs; i++) iscsi_free(TargSendBuff[i]);
  for (i=0; i<NumTargRecvBuffs; i++) iscsi_free(TargRecvBuff[i]);

  /*  Output stats  */

  if (IsTarget) {
    goto accept;
  } else {
    time = (double) (toSeconds(t_stop) - toSeconds(t_start));
    printf("Send Size:        %i bytes\n", HostSendTotal);
    printf("Recv Size:        %i bytes\n", HostRecvTotal);
    printf("Num Iters:        %i\n", NumIters);
    printf("Elapsed Time:     %.4f sec\n", time);
    printf("Avg RT Latency:   %.2f usec\n", (time*1000000/NumIters));
    printf("Send Performance: %.2f MB/sec sec\n", ((HostSendTotal*NumIters)/time)/1048576);
    printf("Recv Performance: %.2f MB/sec sec\n", ((HostRecvTotal*NumIters)/time)/1048576);
  } 
  return 0;
}
