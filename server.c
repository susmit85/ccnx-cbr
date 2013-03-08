//susmit@cs.colostate.edu

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/keystore.h>
#include <ccn/signing.h>
#include <ccn/charbuf.h>
#include <ccn/reg_mgmt.h>
#include <ccn/ccn_private.h>
#include <ccn/ccnd.h>

#define DEBUG


int construct_trace_response(struct ccn *h, struct ccn_charbuf *data,
                             const unsigned char *interest_msg, const struct ccn_parsed_interest *pi) {

    //printf("path:construct trace response");
    //**this function takes the interest, signs the content and returns to
    //upcall for further handling

    char *mymessage;
    char *tmp_mymessage;


    //copy the incoming interest name in ccn charbuf
    struct ccn_charbuf *name = ccn_charbuf_create();
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;

    int res;

    res = ccn_charbuf_append(name, interest_msg + pi->offset[CCN_PI_B_Name],
                             pi->offset[CCN_PI_E_Name] - pi->offset[CCN_PI_B_Name]);

    struct ccn_charbuf *uri = ccn_charbuf_create();
    ccn_uri_append(uri, name->buf, name->length, 1);

    char *incoming_uri = ccn_charbuf_as_string(uri);

    //get the random comp, set it to null
    char *random = strrchr(incoming_uri, '/');
    *random = '\0';

    //get the size
    char *reply_size_str = strrchr(incoming_uri, '/');

    //convert str to int
    int requested_size_int;
    sscanf(reply_size_str+1, "%d", &requested_size_int);
    int i =0;


    mymessage = (char *) malloc (sizeof(char) * requested_size_int + 1);

    //find how many bytes to fill
    int sign_overhead = 385;
    int bytes_to_fill = requested_size_int - sign_overhead;

    //if bytes to fill < 0, (if data size asked less than 385 bytes)
    if (bytes_to_fill < 0) {
        bytes_to_fill = 1; //send one char
    }

    for (i = 0; i< bytes_to_fill; i++) {
        mymessage[i] = 'a';
    }

    mymessage[i] = '\0';
    res = ccn_sign_content(h, data, name, &sp, 	mymessage, bytes_to_fill);
    printf("data length %d %d %d", data->length, bytes_to_fill, strlen(mymessage));

    if(res == -1) {
        fprintf(stderr, "Can not sign content\n");
        exit(1);
    }

    //free memory and return
    ccn_charbuf_destroy(&sp.template_ccnb);
    ccn_charbuf_destroy(&name);
    return res;
}



enum ccn_upcall_res incoming_interest(struct ccn_closure *selfp,
                                      enum ccn_upcall_kind kind, struct ccn_upcall_info *info) {

    //this is the callback function, all interest matching ccnx:/trace
    //will come here, handle them as appropriate

    int res=0;


    //store the incoming interest name
    struct ccn_charbuf *data = ccn_charbuf_create();

    //check for null, length of incoming interest name

    //define answer
    // char *MYMESSAGE="Hello World";



    //switch on type of event
    switch (kind) {
    case CCN_UPCALL_FINAL:
        return CCN_UPCALL_RESULT_OK;
        break;

    case CCN_UPCALL_CONTENT:
        //don't care
        break;


    case CCN_UPCALL_INTEREST:
        //received matching interest
        //get the interest name from incoming packet



        construct_trace_response(info->h, data, info->interest_ccnb, info->pi);
        printf("Sending binary content of length: %Zu \n", data->length);
        res = ccn_put(info->h, data->buf, data->length);
        if(res < 0)
            printf("Error sending data\n");
        break;

    default:
        break;
    }
    return(0);
}



int main(int argc, char **argv) {

    // printf("path:main");
    //no argument necessary
    if(argc != 1) {
        printf("Usage: ./server\n"); // for now, look in flags for local vs remote
        exit(1);
    }

    int res;

    //create ccn handle
    struct ccn *ccn = NULL;

    //connect to CCN
    ccn = ccn_create();
    //NOTE:check for null

    if (ccn_connect(ccn, NULL) == -1) {
        fprintf(stderr, "Could not connect to ccnd");
        exit(1);
    }

    //create prefix we are interested in, register in FIB
    struct ccn_charbuf *prefix = ccn_charbuf_create();

    //We are interested in anythin starting with ccnx:/
    res = ccn_name_from_uri(prefix, "ccnx:/cbr");
    if (res < 0) {
        fprintf(stderr, "Can not convert name to URI\n");
        exit(1);
    }

    //handle for upcalls, receive notifications of incoming interests and content.
    //specify where the reply will go
    struct ccn_closure in_interest = {.p = &incoming_interest};
    in_interest.data = &prefix;

    //set the interest filter for prefix we created
    res = ccn_set_interest_filter(ccn, prefix, &in_interest);
    if (res < 0) {
        fprintf(stderr, "Failed to register interest (res == %d)\n", res);
        exit(1);
    }

    //listen infinitely
    res = ccn_run(ccn, -1);

    //cleanup
    ccn_destroy(&ccn);
    ccn_charbuf_destroy(&prefix);
    exit(0);
}
