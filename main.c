#include "aes_test.h"

int main(void)
{
    //KeyExpansion(cipher_key);
    
    //Test AES-128, 192, & 256 (Quantum-Secure strength)
    TV *results = run_test_vectors();
    results_to_html(results);
    free(results);
    
   return 0;
}


