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

#define CLI_PROGRAM "cbr_client"
#define DEBUG

char *URI;

enum ccn_upcall_res incoming_interest(struct ccn_closure *selfp,
                                      enum ccn_upcall_kind kind, struct ccn_upcall_info *info) {
    //this is the callback function, all interest matching ccnx:/trace
    //will come here, handle them as appropriate
    int res = 0;
    const unsigned char *ptr;
    size_t length;


    //switch on type of event
    switch (kind) {
    case CCN_UPCALL_FINAL:
        free(selfp);
        return CCN_UPCALL_RESULT_OK;

    case CCN_UPCALL_CONTENT:
        //get the content from packet
        res = ccn_content_get_value(info->content_ccnb, info->pco->offset[CCN_PCO_E], info->pco, &ptr, &length);
        if (res < 0) {
            printf("Can not get value from content. res: %d", res);
            exit(1);
        }
        printf("Size received asd %d\n", info->pco->offset[CCN_PCO_E]);
//        printf("Content %s\n", ptr);
        while(1) {
            char *new_URI;

            char *rand_str = strrchr(URI, '/');
            *rand_str  = '\0';
            new_URI = (char *) calloc(strlen(URI) + 20 + 1, sizeof(char)); //assuming rand() length 20
            sprintf(new_URI, "%s/%d", URI, rand());
            printf("URI %s \n", new_URI);
            URI = new_URI;

            struct ccn_charbuf *ccnb = ccn_charbuf_create();
            res = ccn_name_from_uri(ccnb, URI);
            struct ccn_closure *incoming;
            incoming = calloc(1, sizeof(*incoming));
            incoming->p = incoming_interest;

            res = ccn_express_interest(info->h, ccnb, incoming, NULL);
            res = ccn_content_get_value(info->content_ccnb, info->pco->offset[CCN_PCO_E], info->pco, &ptr, &length);
            printf("Size received asd %d\n", info->pco->offset[CCN_PCO_E]);

            sleep(1);

        }


        break;

    case CCN_UPCALL_INTEREST_TIMED_OUT:
        printf("Interest timed out\n");
        return CCN_UPCALL_RESULT_REEXPRESS;

    case CCN_UPCALL_CONTENT_UNVERIFIED:
        fprintf(stderr, "%s: Error - Could not verify content\n\n", CLI_PROGRAM);
        return CCN_UPCALL_RESULT_ERR;

    case CCN_UPCALL_CONTENT_BAD:
        fprintf(stderr, "%s: Error - Bad content\n\n", CLI_PROGRAM);
        return CCN_UPCALL_RESULT_ERR;

    case CCN_UPCALL_INTEREST:
        //don't care about interests, will do nothing
        break;

    default:
        printf("Unexpected response\n");
        return CCN_UPCALL_RESULT_ERR;

    }

    return(0);
}



void usage(void) {
    ///prints the usage and exits
    printf("Usage: %s -t TIME -s REPLY PACKET SIZE(Bytes) [-h] \n\n", CLI_PROGRAM);
    printf("  -t TIME        time interval between consecutive interests, default 1 sec\n");
    printf("  -s SIZE        size of the reply packet in bytes\n");
    printf("  -h             print this help and exit\n");
    exit(1);
}

int main (int argc, char **argv) {
    char *interval_cmd = NULL;
    double interval;
    int opt;
    char *packet_size = NULL;
    int packet_size_int = 0;


    int res = 0;

    //check if user supplied uri to trace to, read the arguments and check them
    if(argc < 3) {
        fprintf(stderr, "%s: Error - Not enough arguments\n\n", CLI_PROGRAM);
        usage();
    }

    while((opt = getopt(argc, argv, "h:t:s:")) != -1) {
        switch(opt) {
        case 'h':
            usage();
            break;
        case 't':
            interval_cmd = optarg;
            res = sscanf(interval_cmd, "%lf", &interval);
            if(res == 0) {
                fprintf(stderr, "%s: Error - Could not convert timeout value to int %s\n\n", CLI_PROGRAM, interval_cmd);
                usage();
            }
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


    struct ccn_closure *incoming;
    incoming = calloc(1, sizeof(*incoming));
    incoming->p = incoming_interest;

    /*    while(1)
        {
        //get time


        int milisec = 100; // length of time to sleep, in miliseconds
        struct timespec req = {0};



        struct timeval tv;
        long start_time, end_time, delta;

        gettimeofday(&tv, NULL);
        start_time = (uint)tv.tv_msec * 1000;   */
    res = ccn_express_interest(ccn, ccnb, incoming, NULL);
    //get time

    /* gettimeofday(&tv, NULL);
     end_time =  (uint)tv.tv_usec * 1000;
     if (res == -1)
     {
         fprintf(stderr, "Could not express interest for %s\n", URI);
         exit(1);
     }

     printf("Expresses interest\n");


     //calculate delta
     delta = start_time - end_time;
     printf("Delta %u\n", delta);
     req.tv_sec = 0;
     req.tv_nsec = milisec * 1000000L;
     nanosleep(&req, (struct timespec *)NULL);
     nanosleep((struct timespec[]){{0, delta}}, NULL);
     }*/

    //run for timeout miliseconds
    res = ccn_run(ccn, -1);
    if (res < 0) {
        fprintf(stderr, "ccn_run error\n");
        exit(1);
    }


    //there is a memory leak for incoming, figure a way to free ccn_closure
    ccn_charbuf_destroy(&ccnb);
    ccn_destroy(&ccn);
    exit(0);

    return(0);
}


