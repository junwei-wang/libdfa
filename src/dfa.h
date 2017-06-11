#ifndef _DFA_H_
#define _DFA_H_

#include "common.h"
#include "gf.h"
#include "aes.h"

int dfa_aes_one_column(int column,
		       enc_mode mode,
		       int num_faluts,
		       const char * input_hex,
		       const char * output_hex,
		       const char * falut_output_hex[],
		       byte * last_round_key);

#endif//_DFA_H

