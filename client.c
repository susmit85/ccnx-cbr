//susmit@cs.colostate.edu
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/keystore.h>
#include <ccn/signing.h>
#include <sys/time.h>
#include <signal.h>

#define CLI_PROGRAM "cbr_client"

char *URI;
double interval;
int num_interests_sent, total_recv_size;
int frequency;
char *packet_size = NULL;


void sig_handler(int s){
#ifdef DEBUG
      printf("Caught signal %d\n",s);
	  #endif

//[ ID] Interval       Transfer     Bandwidth
//[  3]  0.0-10.0 sec  39.4 GBytes  33.8 Gbits/sec

	printf("\n------------------------------------------------------------\n");
	printf("Client asked for /cbr/%s\n", packet_size);
	printf("------------------------------------------------------------\n");
	printf ("Frequency \t Interests sent \t Received Bytes\n");
	printf("%d \t\t %d \t\t\t %d\n", frequency, num_interests_sent, total_recv_size);
	  exit(1); 
  }


enum ccn_upcall_res incoming_interest(struct ccn_closure *selfp,
                                      enum ccn_upcall_kind kind, struct ccn_upcall_info *info) {
    //this is the callback function, all interest matching ccnx:/trace
    //will come here, handle them as appropriate
    int res = 0;
    const unsigned char *ptr;
    size_t length;
    char *new_URI;


    //switch on type of event
    switch (kind) {
    case CCN_UPCALL_FINAL:
        free(selfp);
        return CCN_UPCALL_RESULT_OK;

    case CCN_UPCALL_CONTENT:
		num_interests_sent++;

        //get the content from packet
        res = ccn_content_get_value(info->content_ccnb, info->pco->offset[CCN_PCO_E], info->pco, &ptr, &length);
        if (res < 0) {
            printf("Can not get value from content. res: %d", res);
            exit(1);
        }
        printf("Content of %d bytes received \n", info->pco->offset[CCN_PCO_E]);
		total_recv_size +=  info->pco->offset[CCN_PCO_E];

        struct timeval start_time, end_time;
        gettimeofday(&start_time,0);

        //swap random
        char *rand_str = strrchr(URI, '/');
        *rand_str  = '\0';
        new_URI = (char *) calloc(strlen(URI) + 20 + 1, sizeof(char)); //assuming rand() length 20
        sprintf(new_URI, "%s/%d", URI, rand());
#ifdef DEBUG			
        printf("URI %s \n", new_URI);
		#endif
        URI = new_URI;

        //define closure and new charbuf
        struct ccn_closure *cl;
        cl = calloc(1, sizeof(*cl));
        cl->p = &incoming_interest;

        struct ccn_charbuf *ccnb_new = ccn_charbuf_create();
        res = ccn_name_from_uri(ccnb_new, URI);

        //reexpress interest, get value and size
        res = ccn_express_interest(info->h, ccnb_new, cl, NULL);
//        res = ccn_content_get_value(ccnb_new, info->pco->offset[CCN_PCO_E], info->pco, &ptr, &length);

        gettimeofday(&end_time,0);
        int delta_usec = (end_time.tv_sec-start_time.tv_sec) * 1000 * 1000 + (end_time.tv_usec-start_time.tv_usec);


        int wait_time  = interval * 1000 * 1000 - delta_usec;
#ifdef DEBUG
        printf("Interval %lf, delta %d wait time %d\n", interval*1000*1000, delta_usec, wait_time);
#endif
        //sleep
        printf("Time for previous call is %d ms, waiting for %d ms\n", delta_usec, wait_time);
        usleep(wait_time);

        break;



    case CCN_UPCALL_INTEREST_TIMED_OUT:
        printf("Interest timed out\n");
        return CCN_UPCALL_RESULT_REEXPRESS;

    case CCN_UPCALL_CONTENT_UNVERIFIED:
        fprintf(stderr, "%s: Error - Could not verify content\n\n", CLI_PROGRAM);
        return CCN_UPCALL_RESULT_ERR;
        //return CCN_UPCALL_RESULT_REEXPRESS;

    case CCN_UPCALL_CONTENT_BAD:
        fprintf(stderr, "%s: Error - Bad content\n\n", CLI_PROGRAM);
        return CCN_UPCALL_RESULT_ERR;

    case CCN_UPCALL_INTEREST:
        break;

    default:
        printf("Unexpected response\n");
        return CCN_UPCALL_RESULT_ERR;

    }
//    free(new_URI);
    return(0);
}



void usage(void) {
    ///prints the usage and exits
    printf("Usage: %s -f FREQ -s REPLY PACKET SIZE(Bytes) [-h] \n\n", CLI_PROGRAM);
    printf("  -f FREQ        Frequency of interests, defaults to 1 per sec\n");
    printf("  -s SIZE        size of the reply packet in bytes\n");
    printf("  -h             print this help and exit\n");
    exit(1);
}

int main (int argc, char **argv) {
    char *freq_cmd = NULL;
    int opt;
    int packet_size_int = 0;


    int res = 0;

    //check if user supplied uri to trace to, read the arguments and check them
    if(argc < 3) {
        fprintf(stderr, "%s: Error - Not enough arguments\n\n", CLI_PROGRAM);
        usage();
    }

    while((opt = getopt(argc, argv, "h:f:s:")) != -1) {
		if(strrchr(optarg, '.') != NULL){
			printf("Error: Arguments must be intergers\n");
			usage();
		}
        switch(opt) {
        case 'h':
            usage();
            break;
        case 'f':
            freq_cmd = optarg;
            res = sscanf(freq_cmd, "%d", &frequency);
            if(res == 0) {
                fprintf(stderr, "%s: Error - Invalid frequency %s\n\n", CLI_PROGRAM, freq_cmd);
                usage();
            }
			interval = 1/(double) frequency;
#ifdef DEBUG
			printf("interval = %lf\n", interval);
			#endif
            break;
        case 's':
            packet_size = optarg;
            res = sscanf(packet_size, "%d", &packet_size_int);
            if(res == 0) {
                fprintf(stderr, "%s: Error - Could not convert packet size to int %s\n\n", CLI_PROGRAM, packet_size);
                usage();
            }
            break;

        case ':':
            fprintf(stderr, "%s: Error - Option `%c' needs a value\n\n", CLI_PROGRAM, optopt);
            usage();
            break;
        case '?':
            fprintf(stderr, "%s: Error - No such option: `%c'\n\n", CLI_PROGRAM, optopt);
            usage();
            break;
		default:
		    usage();
			break;
        }
    }

#ifdef DEBUG
    printf("interval %lf secs, packet size in bytes %s\n", interval, packet_size);
#endif



    //create ccn URI
    // /cbr/1500
    char *base_uri = "/cbr";
    size_t uri_length = strlen(base_uri) + 1 + strlen(packet_size) + 1 + 20 + 1;

    URI = (char *) calloc(uri_length, sizeof(char));
    if(URI == NULL) {
        fprintf(stderr, "Can not allocate memory for URI\n");
        exit(1);
    }

    //append random

    srand ((unsigned int)time (NULL)*getpid());
    snprintf(URI, uri_length, "%s/%s/%d", base_uri, packet_size, rand());

#ifdef DEBUG
    printf("URI is %s\n", URI);
#endif

    //allocate memory for interest
    struct ccn_charbuf *ccnb = ccn_charbuf_create();
    if(ccnb == NULL) {
        fprintf(stderr, "Can not allocate memory for interest\n");
        exit(1);
    }

    //adding name to interest
    res = ccn_name_from_uri(ccnb, URI);
    if(res == -1) {
        fprintf(stderr, "Failed to assign name to interest");
        exit(1);
    }


    //create the ccn handle
    struct ccn *ccn = ccn_create();
    if(ccn == NULL) {
        fprintf(stderr, "Can not create ccn handle\n");
        exit(1);
    }

    //connect to ccnd
    res = ccn_connect(ccn, NULL);
    if (res == -1) {
        fprintf(stderr, "Could not connect to ccnd... exiting\n");
        exit(1);
    }

#ifdef DEBUG
    printf("Connected to CCND, return code: %d\n", res);
#endif

	printf("------------------------------------------------------------\n");
	printf("Client asking for /cbr/%s\n", packet_size);
	printf("------------------------------------------------------------\n");

    struct ccn_closure *incoming;
    incoming = calloc(1, sizeof(*incoming));
    incoming->p = incoming_interest;

    res = ccn_express_interest(ccn, ccnb, incoming, NULL);

    //run for timeout miliseconds
    signal (SIGINT,sig_handler);

    res = ccn_run(ccn, -1);
    if (res < 0) {
        fprintf(stderr, "ccn_run error\n");
        exit(1);
    }



    ccn_charbuf_destroy(&ccnb);
    ccn_destroy(&ccn);
    exit(0);

    return(0);
}


