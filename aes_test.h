#ifndef aes_test_h
#define aes_test_h
#include "aes.h"

/*

Acceptance Test Cases for Rijndael (AES) implementation based on FIP-197 standard.
 
By: Samira C. Oliva Madrigal
 
May use aes2.h version to view every step of every round for key expansion and enc and dec
and do a file comparison of that and the NIST test vectors.

Unit testing can be done round by round, output by output by returning pointer to state/data.
*/

typedef struct tv
{
    uint16_t bit;//128,192,256
    uint8_t type;//encryption(0) or decryption(1)
    uint8_t result;//pass(0) or fail(1)
    //add members to print actual and expected
}TV;

#define REPORT "/Users/samiracarolinaolivamadrigal/Library/Autosave Information/crypto/crypto/results.html"
#define TV_SPEC "/Users/samiracarolinaolivamadrigal/Library/Autosave Information/crypto/crypto/test_aes_cipher.mem"
#define TC_COUNT 6

/*------------------------------------------------------------------------
                    convert uint8 array to uint char array
 -------------------------------------------------------------------------*/
unsigned char *uint8_to_uascii(uint8_t *a)
{
    unsigned char *b = malloc(sizeof(unsigned char)*16);
    memcpy(b, a, sizeof(unsigned char)*16);
    return b;
}

/*------------------------------------------------------------------------
                            AES-128 ENCRYPTION
 -------------------------------------------------------------------------*/
bool test_aes_128_encrypt(void)
{
    uint8_t *act_ciphertext;
    unsigned char *act_ct;
    bool res;
    
    act_ciphertext  = aes_encrypt(plaintext, key128, 0);
    act_ct = uint8_to_uascii(act_ciphertext);
    res = memcmp(act_ct, ciphertext128, sizeof(unsigned char)*16); //returns 0 if contents at mem loc are exactly the same.
    
    free(act_ct);
    free(act_ciphertext);
    
    return res == 0? true: false;
}

/*------------------------------------------------------------------------
                            AES-128 DECRYPTION
 -------------------------------------------------------------------------*/
bool test_aes_128_decrypt(void)
{
    uint8_t *act_plaintext;
    unsigned char *act_pt;
    bool res;
    
    act_plaintext  = aes_decrypt(ciphertext128, key128, 0);
    act_pt = uint8_to_uascii(act_plaintext);
    res = memcmp(act_pt, plaintext, sizeof(unsigned char)*16); //returns 0 if contents at mem loc are exactly the same.
    
    free(act_pt);
    free(act_plaintext);
    
    return res == 0? true: false;
}

/*------------------------------------------------------------------------
                            AES-192 ENCRYPTION
 -------------------------------------------------------------------------*/
bool test_aes_192_encrypt(void)
{
    uint8_t *act_ciphertext;
    unsigned char *act_ct;
    bool res;
    
    act_ciphertext  = aes_encrypt(plaintext, key192, 1);
    act_ct = uint8_to_uascii(act_ciphertext);
    res = memcmp(act_ct, ciphertext192, sizeof(unsigned char)*16); //returns 0 if contents at mem loc are exactly the same.
    
    free(act_ct);
    free(act_ciphertext);
    
    return res == 0? true: false;

}

/*------------------------------------------------------------------------
                            AES-192 DECRYPTION
 -------------------------------------------------------------------------*/
bool test_aes_192_decrypt(void)
{
    uint8_t *act_plaintext;
    unsigned char *act_pt;
    bool res;
    
    act_plaintext  = aes_decrypt(ciphertext192, key192, 1);
    act_pt = uint8_to_uascii(act_plaintext);
    res = memcmp(act_pt, plaintext, sizeof(unsigned char)*16); //returns 0 if contents at mem loc are exactly the same.
    
    free(act_pt);
    free(act_plaintext);
    
    return res == 0? true: false;
}

/*------------------------------------------------------------------------
                            AES-256 ENCRYPTION
 -------------------------------------------------------------------------*/
bool test_aes_256_encrypt(void)
{
    uint8_t *act_ciphertext;
    unsigned char *act_ct;
    bool res;
    
    act_ciphertext  = aes_encrypt(plaintext, key256, 2);
    act_ct = uint8_to_uascii(act_ciphertext);
    res = memcmp(act_ct, ciphertext256, sizeof(unsigned char)*16); //returns 0 if contents at mem loc are exactly the same.
    
    free(act_ct);
    free(act_ciphertext);
    
    return res == 0? true: false;
}

/*------------------------------------------------------------------------
                            AES-256 DECRYPTION
 -------------------------------------------------------------------------*/
bool test_aes_256_decrypt(void)
{
    uint8_t *act_plaintext;
    unsigned char *act_pt;
    bool res;
    
    act_plaintext  = aes_decrypt(ciphertext256, key256, 2);
    act_pt = uint8_to_uascii(act_plaintext);
    res = memcmp(act_pt, plaintext, sizeof(unsigned char)*16); //returns 0 if contents at mem loc are exactly the same.
    
    free(act_pt);
    free(act_plaintext);
    
    return res == 0? true: false;
}

char **get_tc_strings(TV *entry)
{
    char **p;
    
    p = (char**)malloc(sizeof(char*));
    p[0] = (char*)malloc(sizeof(char)*(strlen("AES-XXX-XXX") + 1));
    
    switch(entry->bit)
    {
        case 128:
        strncpy(p[0], "AES-128", strlen("AES-128"));
        if(entry->type == 0)
        {
            strncat(p[0], "-ENC", strlen("-ENC"));
        }
        else
        {
            strncat(p[0], "-DEC", strlen("-DEC"));
        }
        *(p[0] + strlen("AES-XXX-XXX")) = '\0';
        break;
        case 192:
        strncpy(p[0], "AES-192", strlen("AES-192"));
        if(entry->type == 0)
        {
            strncat(p[0], "-ENC", strlen("-ENC"));
        }
        else
        {
            strncat(p[0], "-DEC", strlen("-DEC"));
        }
        *(p[0] + strlen("AES-XXX-XXX")) = '\0';
        break;
        case 256:
        strncpy(p[0], "AES-256", strlen("AES-256"));
        if(entry->type == 0)
        {
            strncat(p[0], "-ENC", strlen("-ENC"));
        }
        else
        {
            strncat(p[0], "-DEC", strlen("-DEC"));
        }
        *(p[0] + strlen("AES-XXX-XXX")) = '\0';
        break;
        default:
        break;
    }
    
    if(entry->result == 0)//passing
    {
        p[1] = (char*)malloc(sizeof(char)*(strlen("PASSED")+1));
        strncpy(p[1], "PASSED", strlen("PASSED"));
        *(p[1] + strlen("PASSED")) = '\0';
    }
    else
    {
        p[1] = (char*)malloc(sizeof(char)*(strlen("FAILED")+1));
        strncpy(p[1], "PASSED", strlen("PASSED"));
        *(p[1] + strlen("PASSED")) = '\0';
    }
    
    return p;
}


/*------------------------------------------------------------------------
                    GENERATE SIMPLE HTML REPORT LOGS
 -------------------------------------------------------------------------*/
void results_to_html(TV *results)
{
    FILE *fp = fopen(REPORT, "w");
    char **p;
    
    
    unsigned char header[] = "<!DOCTYPE html><html><style>table, th, td {border: 1px solid pink;}th,td{padding: 15px;}</style><body><center><h2>AES Test Results by Samirita</h2></center></body></html>";
    unsigned char footer[] = "</body></html>";
    unsigned char table_start[] ="<br><br><br><br><center><table style=width:50%>";
    unsigned char table_end[] = "</table></center>";
    unsigned char entry_start[] = "<tr>";
    unsigned char entry_end[] = "</tr>";
    unsigned char data_start[] = "<th>";
    unsigned char data_end[] = "</th>";
    unsigned char table_cols[] = "<tr><th>TEST CASE\t</th> <th>RESULTS</th></tr>";
    
    fputs(header, fp);
    fputs(table_start, fp);
    fputs(table_cols, fp);
    
    for(int i = 0; i < TC_COUNT; i++)
    {
    
        p = get_tc_strings(&results[i]);
        fputs(entry_start, fp);
        fputs(data_start, fp);
        fputs(p[0], fp);
        fputs(data_end, fp);
        fputs(data_start, fp);
        fputs(p[1], fp);
        fputs(data_end, fp);
        fputs(data_end, fp);
        fputs(entry_end, fp);
        free(p);
    }
    
    fputs(table_end, fp);
    fputs(footer, fp);
    fclose(fp);
}

/*------------------------------------------------------------------------
                            TEST CASE SPECS
 -------------------------------------------------------------------------*/
TV *get_tv_specs(void)
{
    FILE *fp;
    TV *results;
    char buf[10];
    int i;
    
    results = (TV*)calloc(TC_COUNT, sizeof(TV));
    fp  = fopen(TV_SPEC, "r");
    i = 0;
    while(fgets(buf, 10, fp))
    {
        if(buf[0] != '#')//skip commnets
        {
            results[i].bit  = strtol(strtok(buf, ":"), (char**)NULL, 10);
            results[i].type = (uint8_t)strtol(strtok(NULL, ":"), (char**)NULL, 10);
            i++;
        }
        
    }
    fclose(fp);
    return results;
}

/*------------------------------------------------------------------------
                    RUN TEST VECTORS
 -------------------------------------------------------------------------*/
TV *run_test_vectors(void)
{
    TV *tvs = get_tv_specs();
    
    for(int i = 0; i < TC_COUNT; i++)
    {
        switch(tvs[i].bit)
        {
            case 128:
            if(tvs[i].type == 0)
                tvs[i].result = test_aes_128_encrypt();
            else
                tvs[i].result = test_aes_128_decrypt();
            break;
            case 192:
            if(tvs[i].type == 0)
                tvs[i].result = test_aes_192_encrypt();
            else
                tvs[i].result = test_aes_192_decrypt();
            break;
            case 256:
            if(tvs[i].type == 0)
                tvs[i].result = test_aes_256_encrypt();
            else
                tvs[i].result = test_aes_256_decrypt();
            break;
        default:
            break;
        }
    }

    return tvs;
}

#endif /* aes_test_h */
