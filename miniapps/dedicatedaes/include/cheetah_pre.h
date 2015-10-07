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


Created: 2014-09-26

Author: Rasmus Winther Lauritsen, rwl@cs.au.dk

Changes: 
2014-09-26 12:48: Initial version created
*/

/**
 * The Cheetah (fake)preprocessing is handled by this module.
 **/
#ifndef CHEETAH_PRE_H
#define CHEETAH_PRE_H

#include <osal.h>
#include <minimacs/minimacs.h>
#include <reedsolomon/reedsolomon.h>
#include <singlelinkedlist.h>
#include <common.h>
#include <map.h>
#include <rnd.h>
#include <cheetah.h>

void CheetahSBox_Destroy(OE oe,CheetahSBox * val);


void CheetahDVal_Destroy(OE oe,CheetahDVal * val);



void CheetahLVal_Destroy(OE oe,CheetahLVal * val);


/** << Interface >> Cheetah Fake Preprocessing 
 *
 * \breif This struct represents data and operations for creating fake
 * preprocessing material for the Cheetah AES MPC implementation.
 *
 * MiniMac is run in a configuration with 119 working elements makeing 
 * room for 7 parallel AES states.
 *
 */
typedef struct _cheetah_fake_proprocessing_ {
  /*!  

    \brief 

    Create {count} MiniMac representations that are singleton values
    with macs for party with id {playerid}. If no singles has been
    generated before {count} representation vectors for all players
    (e.g. {nplayers}) are generated but only the one for the given
    player are returned as a list.

    Calls with other player ids but identical count will return their
    values. If a greater or smaller {count} is given on subsequent
    calls are given null is returned.


    \param playerid    - The id of the player for which the single is
                         meant.

    \return             - A list with {count} singles.
    
  */
  MiniMacsRep (*get_single)(uint playerid);

  /*!
	When called with {playerid} zero a random value {R} and 
	{SBox} permuted by {R} with SRMC applied is created. 
	Subsequent invocations for {playerid} > 0 will create a 
	fresh set of random shares. 

	\param playersid - the id for the player for which to generate a share.

    \return CheetahSBox holding the share of {R} and the 112*256 shares for 
	        the permuted sbox with SRMC applied.
   */
  CheetahSBox(*get_sbox_srmc)(uint playerid);

  /*!
  When called with {playerid} zero a random value {R} and
  {SBox} permuted by {R} with SR (Shift Rows only) applied 
  is created. This is for the last AES round.

  Subsequent invocations for {playerid} > 0 will create a
  fresh set of random shares.

  \return CheetahSBox holding the share of {R} and the 112*256 shares for
  the permuted sbox with SRMC applied.
  */
  CheetahSBox(*get_sbox_sr)(uint playerid);

  /*!  Given a linear transformation two representations are
    created. One for a random value {R} and another for {MxR}. {MxR}
    is the linear transformation {M} applied to {R}.
   */
  CheetahLVal(*get_lintrans)(uint playerid, MATRIX * M);

  /*!
    
    \breif 

    Return {count} uniformly random values on the representations [R]
    and their bit decomposition also on the representation
    [R_0],...,[R_m] for the underlying F_{2^m} Galois Field.

	When {playerid} is zero {count} random values are generated. When {playerid} > 0, 
	then the {count} parameter is ignored and share for the previous generating 
	invocation for player with id {playerid} are returned.

    \param count - the number of random values to generate.

	\param playerid - the id for which the shares are generated

    \return - Decomposed value shares for player with id {playerid}.
    
   */
   CheetahDVal (*get_decomposed)(uint playerid);

  /*
     Get key box that performs the SubButes(ROT(w)) operation !
     
     We need to do the XOR Rcon[round] manually during the protocol 
     which wlog can be done by palyer 0.

   */
  CheetahKBox (*get_key_box)(uint playerid);

  // Implementation specific stuff
  void * impl;

} * Cfp;


/*!

 Get an instance of {Cfp}.

 \param oe - OperatingEnvironment 
 
 \param combat - All representations are MAC-Compatible meaning their
 alpha values towards each other player are the same. To make this
 instance generate values compatible provide a combatible
 representation. NULL is allowed in which case a fresh alpha value is
 generated per each other player.

 \param nplayers - The number of players to generate for

 \param A Cfp instance.

 */
Cfp Cfp_SimpleNew(OE oe, MiniMacsEnc enc, MiniMacsEnc smenc, Rnd rnd, uint nplayers);

// clean up the pre-processing
void Cfp_SimpleDestroy(Cfp * cfp);
#endif
