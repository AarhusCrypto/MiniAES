/*

Copyright (c) 2013, Rasmus Zakarias, Aarhus University
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
3. All advertising materials mentioning features or use of this software

must display the following acknowledgement:

This product includes software developed by Rasmus Winther Zakarias
at Aarhus University.

4. Neither the name of Aarhus University nor the
names of its contributors may be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY Rasmus Zakarias at Aarhus University
''AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Rasmus Zakarias at Aarhus University BE
LIABLE FOR ANY, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


Created: 2015-05-07

Author: Rasmus Winther Lauritsen, rwl@cs.au.dk

Changes:
2014-09-26 12:48: Initial version created
*/

#ifndef MPC_AES_H
#define MPC_AES_H

#include <minimacs/minimacs.h>
#include <carena.h>

typedef struct _dedicated_aes_minimacs_ {
	/*
	* Perform S-Box with Shift-rows and mix-columns
	*/
	MR(*sbox_srmc)(uint dst, uint op1);

	/*
	* Perform S-Box with Shift-rows
	*/
	MR(*sbox_sr)(uint dst, uint op1);

	/*
	* Perform input, the length of {data} is implied by the
	* instantiation of MiniMac.
	*
	*/
        MR(*input)(uint playerid, uint dst, byte * data);

	/*
	* Make the value at address {addr} public
	*/
	MR(*open)(uint addr);

	/*
	* Get the data as {addr}, the length is implied by the
	* instantiation of MiniMac. The caller owns the pointer
	* returned, which must be free with {oe->putmem} on the
	* OE instance used by this instance.
	*/
	byte * (*get)(uint addr);

	/*
	* Make a deep-copy of the representation at {src} and
	* store the freshly allocated copy at {dst}.
	*/
        MR(*cpy)(uint dst, uint src);
  
        /* 
         *  Apply the key-box to the state in {src} and store the 
	 *  resulting AES state codeword in {dst}.
         *
         */
        MR(*key_box)(uint dst, uint src);
         
       /*
        *  Add Round constant for {round} to the state in 
	*  {dst} and store the result in {dst} too.
        */
        MR(*rcon)(uint dst, uint round);

	/*
	* XOR {op1} with {op2} and store the result at {dst}.
	*/
	MR(*xor)(uint dst, uint op1, uint op2);

	// private details hidden for the client
	void * impl;

} *DAesMiniMac;


/**
* Create an AesPreprocessing instance that will cache in memory
* the requested number of preprocessing as long as that many instances
* are available in the file identified by {filename}
*
*
**/
AesPreprocessing AesPreprocessing_Cached_New(OE oe,const char * filename,
	uint cache_no_sbox_srmc,
	uint cache_no_decomp_val,
	uint cache_no_single,
	uint cache_no_srmc,
	uint cache_no_sr,
	uint cache_no_sbox_sr);
// clean up
void AesPreprocesing_Cached_Destroy(AesPreprocessing * prep);

/**
* Create an AesPreprocessing instance that during creation
* (this function that is) will generated the requested preprocessing
* material up front in memory.
*
**/
AesPreprocessing AesPreprocessing_Memory_New(OE oe, Cfp cfp,
	uint no_sbox_srmc,
	uint no_decomp_val,
	uint no_single,
	uint no_srmc,
	uint no_sr,
	uint no_sbox_sr);

// clean up AesPreprocessing in memory
void AesPreprocessing_Memory_Destroy(AesPreprocessing * aespre);

DAesMiniMac DAesMiniMac_DefaultNew(OE oe, const char * filename);

DAesMiniMac DAesMiniMac_New(OE oe, MiniMacsEnc menc, MiniMacsEnc smenc, Map heap, AesPreprocessing aespre, CArena arena);
int mpc_aes(OE oe, DAesMiniMac mm, byte * key, byte * plx, byte ** ctx, bool ks);
#endif
