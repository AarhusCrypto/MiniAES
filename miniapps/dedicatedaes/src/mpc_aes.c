/*
 *
 * Author: Rasmus Winther Zakarias
 *
 * This file contains two components:
 *
 * 1) The DAesMiniMac which is an implementation of the Dedicated
 *    minimacs on-line phase
 *
 * 2) AesPreprocessing_Cached which is component for loading and
 *    bookeeping preprocessing material for DAesMiniMac.
 *
 * The main attaction in mac_aes(...) further down where 
 * the main-aes loop is implemented.
 *
 */
#include <minimacs/minimacs.h>
#include <cheetah_pre.h>
#include <coov4.h>
#include <hashmap.h>
#include <carena.h>
#include <mpc_aes.h>
#include <assert.h>
#include <datetime.h>

#define KEY_ADR 1
#define PLX_ADR 0
#define KEY_TMP_ADR 2


// ------------------------------------------------------------
// Debugging tools
// ------------------------------------------------------------
MpcPeer debugPeer = 0;


#ifdef DEBUG
static void __lhr(DAesMiniMac mm, MiniMacsRep rep, char * msg, byte * clear_out);
static void _lhl(DAesMiniMac mm, uint src,char * msg,uint round) ;
static void _lhr(DAesMiniMac mm, MiniMacsRep rep, char * msg);
#define _lhr(mm,rep,msg,clear_out) __lhr(mm,rep,msg,clear_out)
#define lhl(mm,src,msg,round) _lhl(mm,src,msg,round)
#define lhr(mm,rep,msg) _lhr(mm,rep,msg)
#else
#define _lhr(mm,rep,msg,clear_out)
#define lhl(mm,src,msg,round) 
#define lhr(mm,rep,msg)
#endif


static void _print_rep(OE oe,MiniMacsRep rep,
		       const char * file, uint line, const char * fun);
static void _print_state(OE oe,DAesMiniMac mm, uint adr, 
			 const char * file, uint line,
			 const char * fun);
#define print_state(OE,MM,ADR)\
  _print_state((OE),(MM),(ADR),__FILE__,__LINE__,__FUNCTION__)

#define print_rep(OE,REP)					\
  _print_rep((OE),(REP),__FILE__,__LINE__,__FUNCTION__);	
// ------------------------------------------------------------
// ------------------------------------------------------------


// -----------------------------------------------------
// MiniMac Dedicated AES protocol (DAesMiniMacs) impl.
// -----------------------------------------------------
typedef struct _aes_minimac_impl_ {
	OE oe;
	Map heap;
	MiniMacsEnc menc, smenc;
	CArena com;
	AesPreprocessing pre;
} * DAesMiniMacImpl;



COO_DEF(DAesMiniMac, MR, rcon, uint dst, uint round) {
  DAesMiniMacImpl impl = (DAesMiniMacImpl)this->impl;
  MR mr = MR_OK;
  MiniMacsRep rep = 0;
  uint i = 0, block=0;
  OE oe = impl->oe;
  byte v[DATA_BYTES] = {0};
  MiniMacsRep result = 0;

  static byte rcon[10] = {
    0x01,0x02,0x04,0x08,
    0x10,0x20,0x40,0x80,
    0x1B,0x36,
  };


  rep = impl->heap->get((void*)(ull)dst);
  if (!rep) {
    ERR(oe,"Address %u not set cannot add round constant.",dst);
    return MR_HEAP_NOT_AVAIL;
  }

  if (round < 1 || round > 10) {
    ERR(oe, "Invalid round %u not in [1;10].",round);
  }
  
  for(block = 0; block < DATA_BYTES/16;++block) {
    for(i = 0; i < 4;++i) {
      v[block*16+4*i] ^= rcon[round-1];
    }
  }

  result = minimacs_rep_add_const_fast(impl->oe,
				       impl->menc,
				       rep,
				       v,DATA_BYTES);
  if (!result) {
    ERR(oe, "MiniMac operations failed for round constant.");
    return MR_REP_OP_FAILED;
  }

  minimacs_rep_clean_up(oe,&rep);
  impl->heap->put( (void*)(ull)dst, result );
  
  
  return mr;
}}

// implemetation of copy 
COO_DEF(DAesMiniMac, MR, cpy, uint dst, uint src) {
  DAesMiniMacImpl impl = (DAesMiniMacImpl)this->impl;
  MiniMacsRep tmp = 0;
  byte zeros[DATA_BYTES] = { 0 };
  MiniMacsRep res = 0;
 tmp = impl->heap->get((void*)(ull)src);
 if (!tmp) {
   ERR(impl->oe, "cannot copy rep from address, %u, it is not set.",src);
   return MR_HEAP_NOT_AVAIL;
 }

 res = minimacs_rep_add_const_fast(impl->oe, impl->menc,tmp,zeros,sizeof(zeros));
 if (!res) {
   ERR(impl->oe,"Unable to add two codewords");
   return MR_REP_OP_FAILED;
 }
 
 impl->heap->put((void*)(ull)dst,res);
 
 impl->oe->p("Copying representation at %u to %u, %p\n", src,dst,res);

return MR_OK;
}}

// implementation of xor 
COO_DEF(DAesMiniMac, MR, xor, uint dst, uint op1, uint op2) {
  DAesMiniMacImpl impl = (DAesMiniMacImpl)this->impl;
  MiniMacsRep o1 = impl->heap->get((void*)(ull)op1);
  MiniMacsRep o2 = impl->heap->get((void*)(ull)op2);
  bool o1const=False, o2const=False;
  MiniMacsRep r = 0;
  
  o1const = minimacs_rep_is_public_const(o1);
  o2const = minimacs_rep_is_public_const(o2);

  if (o1 == 0) { 
    ERR(impl->oe,"operand at address %u was not set.",op1);
    return MR_HEAP_NOT_AVAIL;
  }

  if (o2 == 0) { 
    ERR(impl->oe,"operand at address %u was not set.",op2);
    return MR_HEAP_NOT_AVAIL;
  }

  if (o1const && o2const) {
    uint i = 0;
    byte * ntxt = (byte*)impl->oe->getmem(o1->lval);
    MiniMacsEnc enc = impl->menc;
    for(i = 0;i < o1->lval;++i) {
      ntxt[i] = o1->codeword[i] ^ o2->codeword[i];
    }
    impl->oe->putmem(ntxt);
    r = minimacs_create_rep_public_plaintext_fast(impl->oe, enc, ntxt, o1->lval, o1->lcodeword);
  }

  if (!o1const && o2const) {
    MiniMacsEnc enc = impl->menc;
    r = minimacs_rep_add_const_fast(impl->oe, enc, o1, o2->codeword, o1->lval);
  }

  if (o1const && !o2const) {
    MiniMacsEnc enc = impl->menc;
    r = minimacs_rep_add_const_fast(impl->oe, enc, o2, o1->codeword, o2->lval);
  }

  if (!o1const && !o2const) {
    r = minimacs_rep_xor(impl->oe, o1, o2);
    if (!r) { 
      impl->oe->p("failed to xor rep at @%u with rep @%u",op1,op2);
      return MR_REP_OP_FAILED;
    };
  }

  impl->heap->put((void*)(ull)dst, r);
  return MR_OK;
}}


COO_DEF(DAesMiniMac, byte *, get, uint src)
DAesMiniMacImpl impl = (DAesMiniMacImpl)this->impl;
MiniMacsRep r = impl->heap->get((void*)(ull)src);
byte * res = 0;
if (!r) return 0;
res = impl->oe->getmem(r->lval);
if (!res) return 0;
mcpy(res, r->codeword, r->lval);
return res;
}

COO_DEF(DAesMiniMac, MR, input, uint playerid, uint dst, byte * data) {
  DAesMiniMacImpl impl = (DAesMiniMacImpl)this->impl;
  MiniMacsRep single = impl->pre->get_single();
  uint i = 0,j = 0,  nplayers = impl->pre->get_nplayers();
  uint myid = impl->pre->get_playerid();
  OE oe = impl->oe;
  byte * openedvalue = 0;
  byte * share = 0, * mac = 0;
  uint lmsg = 0, lcode = 0;
  MR rc=  MR_OK;
  MiniMacsRep result = 0;
 
  lmsg = impl->pre->get_lmsg();
  lcode = impl->pre->get_lcode();

  if (impl->com->get_no_peers() < 1) {
    ERR(oe,"No one else connected, aborting protocol.");
    return MR_PEER_DISCON;
  }

  if (!single) { 
    ERR(oe, "No more pre-processing material, need a single.");
    return MR_NO_PREP;
  }

  openedvalue = oe->getmem(lcode);
  if (!openedvalue) {
    ERR(oe, "Out of memory");
    return MR_NOMEM;
  }

  share = oe->getmem(lcode);
  if (!share) {
    ERR(oe,"Ran out of memory");
    rc = MR_NOMEM;
    goto fail;
  }
  mac = oe->getmem(lcode);
  if (!mac) {
    ERR(oe,"Ran out of memory");
    rc = MR_NOMEM;
    goto fail;
  }
  

    // I am inputter
  if (playerid == myid) {
    for (i = 0; i < nplayers; ++i) {
      if (i == myid) continue;
      MpcPeer peer = impl->com->get_peer(0); // TODO(rwz): consider Peer map impl 
      CAR r = {0};

      if (!peer) {
	oe->print("There is no peer %u.\n",i);
	ERR(oe, "Peer %u disconnected.",i);
	rc = MR_PEER_DISCON;
	goto fail;
      }

      r = peer->receive(Data_shallow(share,lcode));
      if (r.rc != OK) {
	ERR(oe, "Failed to receive data from peer %u.",i);
	rc = MR_PEER_DISCON;
	goto fail;
      }

      r = peer->receive(Data_shallow(mac,lcode));
      if (r.rc != OK) {
	ERR(oe, "Failed to receive data from peer %u.",i);
	rc = MR_PEER_DISCON;
	goto fail;
      }

      if (!minimacs_check_othershare_fast(impl->menc,
					  single,
					  i,
					  share, 
					  mac,
					  lcode)) {
	ERR(oe,"Peer %u is reporting a value that does not check out.",i);
	rc = MR_PEER_DISCON;
	goto fail;
      }

      for(j = 0;j < lcode;++j) {
	openedvalue[j] ^= share[j];
      }
    }
    
    for(i = 0;i < lcode;++i) {
      openedvalue[i] = add(openedvalue[i],add(single->codeword[i],single->dx_codeword[i]));
    }

    oe->putmem(share);share=0;
    share = impl->menc->encode(openedvalue,lmsg);
    if (!share) {
      ERR(oe,"Encoding single failed.");
      rc = MR_NOMEM;
      goto fail;
    }

    oe->putmem(openedvalue);openedvalue = 0;
    openedvalue = impl->menc->encode(data,lmsg);
    if (!openedvalue) {
      ERR(oe, "No memory for encoding.");
      rc = MR_NOMEM;
      goto fail;
    }

    for(i = 0; i < lcode;++i) {
      share[i] = share[i] ^ openedvalue[i];
    }

    for(i = 0; i < nplayers;++i) {
      MpcPeer peer = 0;
      CAR r = {0};
      if (i == myid) continue;

      peer = impl->com->get_peer(0); // TODO(rwz): peer map impl 
      if (!peer) {
	ERR(oe, "Peer %u disconnected.");
	rc = MR_PEER_DISCON;
	goto fail;
      }

      r = peer->send(Data_shallow(share,lcode));
      if (r.rc != OK) {
	ERR(oe, "Failed to send to peer %u.");
	rc = MR_PEER_DISCON;
	goto fail;
      }
    }

    result = minimacs_rep_add_const_fast(oe, impl->menc, single, share, lmsg );
    minimacs_rep_clean_up(oe,&single);
    if (!result) {
      ERR(oe,"Failed to add constant to random value for input.");
      rc = MR_REP_OP_FAILED;
      goto fail;
    }

    impl->heap->put((void*)(ull)dst, result);
    oe->p("Input successfully completed.");
  } else {
    MpcPeer peer = impl->com->get_peer(0);
    CAR r = {0};
    Data epsilon = Data_new(oe,lcode);

    if (!peer) {
      ERR(oe, "Peer disconnected.");
      rc = MR_PEER_DISCON;
      goto fail;
    }

    r = peer->send(Data_shallow(single->codeword, lcode));
    if (r.rc != OK) {
      ERR(oe, "Peer disconnected ... ");
      rc = MR_PEER_DISCON;
      goto fail;
    }

    r = peer->send(Data_shallow(single->mac[playerid]->mac, lcode));
    if (r.rc != OK) {
      ERR(oe, "Peer disconnected ... ");
      rc = MR_PEER_DISCON;
      goto fail;
    }

    r = peer->receive(epsilon);
    if (r.rc != OK) {
      ERR(oe, "Peer disconnected ... ");
      rc = MR_PEER_DISCON;
      goto fail;

    }

    if (!impl->menc->validate((polynomial*)epsilon->data, lmsg)) {
      ERR(oe, "Invalid codeword received from peer.");
      rc = MR_BAD_PEER;
      goto fail;
    }
    
    result = minimacs_rep_add_const_fast(oe, impl->menc, single, epsilon->data, lmsg);
    if (!result) {
      ERR(oe, "Failed to complete input.");
      rc = MR_REP_OP_FAILED;
      goto fail;
    }
    impl->heap->put((void*)(ull)dst, result);
  }

    return MR_OK;
  fail:
    return rc;
}}

void DAesMiniMac_Destroy(DAesMiniMac * instance) {


}

static uint hash_uint(void * v) {
	uint val = (uint)(ull)v;
	return 101 * val + 65537;
}

static int compare_uint(void * a, void * b) {
	uint vala = (uint)(ull)a;
	uint valb = (uint)(ull)b;
	return (vala > valb ? 1 : valb == vala ? 0 : -1);
}

// Factory method
DAesMiniMac DAesMiniMac_DefaultNew(OE oe, const char * filename) {
	MiniMacsEnc benc = 0;
	MiniMacsEnc senc = 0;
	Map heap = 0;
	AesPreprocessing prep = 0;
	CArena arena = 0;

	prep = AesPreprocessing_Cached_New(oe,filename, 128, 128, 128, 128, 128, 128);
	
	heap = HashMap_new(oe, hash_uint, compare_uint, 256);

	benc = MiniMacsEnc_MatrixNew(oe, prep->get_lcode(), prep->get_lmsg());

	senc = MiniMacsEnc_MatrixNew(oe, prep->get_lmsg() / 4 + 16, prep->get_lmsg() / 8);

	arena = CArena_new(oe);

	return DAesMiniMac_New(oe, benc, senc, heap, prep,arena);
}

// destroy an instance created with {DAesMiniMac_DefaultNew}.
void DAesMiniMac_DefaultDestroy(DAesMiniMac * instance) {

}

COO_DEF(DAesMiniMac,MR,sboxword,uint dst, uint op) {
  DAesMiniMacImpl impl = (DAesMiniMacImpl)this->impl;
  impl->oe->p("not implemented yet");
  return MR_NOT_IMPL;
}}

COO_DEF(DAesMiniMac,MR,open,uint src) {
  DAesMiniMacImpl impl = (DAesMiniMacImpl)this->impl;
  OE oe = impl->oe;
  MiniMacsRep rep = 0;
  byte * buffer = 0, * share = 0, * mac = 0;
  uint lbuffer = 0, lshare = 0, lmac = 0, i = 0, p = 0;
  
  rep = impl->heap->get((void*)(ull)src);
  if(!rep) {
    ERR(oe,"Opening unset address %u.",src);
    return MR_HEAP_NOT_AVAIL;
  }

  if (minimacs_rep_is_public_const(rep)) {
    return MR_OK;
  }

  lbuffer = impl->pre->get_lcode();
  lmac = lbuffer;
  lshare = lbuffer;

  buffer = oe->getmem(lbuffer);
  if (!buffer) {
    ERR(oe, "Out of memory.");
    return MR_NOMEM;
  }

  mac = oe->getmem(lmac);
  if (!mac) {
    ERR(oe, "Out of memory.");
    return MR_NOMEM;
  }

  share = oe->getmem(lshare);
  if (!lshare) {
    ERR(oe, "Out of memory.");
    return MR_NOMEM;
  }

  {
    const uint myid = impl->pre->get_playerid();
    const uint nplayers = impl->pre->get_nplayers();
    uint p = 0;
    for(;p < nplayers ;++p) {
      MpcPeer peer = 0;
      CAR r = {0};
      if (p == myid) {
	continue;
      }

      // TODO(rwz): We need a peer map to get more than two players
      peer = impl->com->get_peer(0);
      if (!peer) {
	ERR(oe, "Peer has disconnected :-(");
	return MR_PEER_DISCON; // TODO(rwz): goto fail and clean up
      }

      r = peer->send(Data_shallow(rep->codeword,rep->lcodeword));
      if (r.rc != OK) {
	ERR(oe, "An error occurred while communicating with peer:\n%s",r.msg);
	return MR_PEER_DISCON;
      }
      
      r = peer->send(Data_shallow(rep->mac[myid == 0 ? 1 : 0]->mac,
				  rep->mac[myid == 0 ? 1 : 0]->lmac));
      if (r.rc != OK) {
	ERR(oe, "An error occurred while communicating with peer:\n%s",r.msg);
	return MR_PEER_DISCON;
      }
    }


    for(p=0;p < nplayers;++p) {
      MpcPeer peer = 0;
      CAR r = {0};
	    
      if (p == myid) continue;

      peer = impl->com->get_peer(0);
      if (!peer) {
	ERR(oe, "Peer has disconnected :-(");
	return MR_PEER_DISCON; // TODO(rwz): goto fail and clean up
      }

      r = peer->receive(Data_shallow(buffer,lbuffer));
      if (r.rc != OK) {
	ERR(oe, "An error occurred while communicating with peer:\n%s",r.msg);
	return MR_PEER_DISCON;
      }

      
      r = peer->receive(Data_shallow(mac,lmac));
      if (r.rc != OK) {
	ERR(oe, "An error occurred while communicating with peer:\n%s",r.msg);
	return MR_PEER_DISCON;
      }

      if (!minimacs_check_othershare_fast(impl->menc,
					  rep,
					  myid == 0 ? 1 : 0,
					  buffer,
					  mac,
					  lbuffer)) {
	ERR(oe,"Player %u has detected cheating.",impl->pre->get_playerid());
	return MR_WRONG_MAC;
      }

      for(i=0;i<lbuffer;++i) {
	share[i] ^= buffer[i];
      }
    }

    for(i = 0;i < lbuffer;++i) {
      share[i] = share[i] ^ rep->dx_codeword[i] ^ rep->codeword[i];
    }
  }
  
  {
    MiniMacsRep result = 0;
    result = minimacs_create_rep_public_plaintext_fast(impl->oe,
						       impl->menc,
						       share,
						       DATA_BYTES,
						       255);
    if (!result) {
      ERR(oe, "Out of memory."); // TODO(rwz): Goto fail.
      return MR_NOMEM;
    }
    
    impl->heap->put((void*)(ull)src,result);
  }
    return MR_OK;
  fail:
    return MR_NOT_IMPL;

  }}

COO_DEF(DAesMiniMac,MR,rot,uint dst, uint op) {
  DAesMiniMacImpl impl = (DAesMiniMacImpl)this->impl;
  AesPreprocessing pre = impl->pre;


  impl->oe->p("not implemented yet");
  return MR_NOT_IMPL;
}}

static MR compute_box(DAesMiniMac this, uint dst, uint op, CheetahSBox box, 
		       MATRIX * lt) {
  DAesMiniMacImpl impl = (DAesMiniMacImpl)this->impl;
  MiniMacsRep rep = 0;
  MiniMacsRep delta_share = 0;
  uint p = 0;
  byte * buffer = 0, *mac =0;
  uint lbuffer = 0,lmac =0 ;
  uint i = 0, j = 0;
  byte delta[DATA_BYTES] = {0};
  byte newstate[DATA_BYTES] = {0};
  MR rc = MR_OK;

  rep = impl->heap->get((void*)(ull)op);
  if (!rep) {
    impl->oe->p("Heap error asked for unset value at address %u",op);
    return MR_HEAP_NOT_AVAIL;
  }

  delta_share = minimacs_rep_xor(impl->oe, rep, box->R);
  if (!delta_share) {
    impl->oe->p("Minimacs xor operation failed.");
    rc = MR_REP_OP_FAILED;
    goto fail;
  }

  // Open delta_share
  for(p = 0; p < impl->pre->get_nplayers();++p) {
    MpcPeer peer = 0;
    CAR err = {0};

    // TODO(rwz): to support more players than 2 we need to have a
    // player map with ids. 
    if (p == impl->pre->get_playerid()) continue;

    peer = impl->com->get_peer(0);
    if (!peer) {
      impl->oe->p("Aborting computation, peer %u has disconnected.",p);
      return MR_PEER_DISCON;
    }

    err = peer->send(Data_shallow(delta_share->codeword,delta_share->lcodeword));
    if (err.rc != OK) {
      impl->oe->p(err.msg);
      return MR_PEER_DISCON;
    }

    err = peer->send(Data_shallow(delta_share->mac[impl->pre->get_playerid() == 0 ? 1 : 0]->mac,
				  delta_share->mac[impl->pre->get_playerid() == 0 ? 1 : 0]->lmac));
    if (err.rc != OK) {
      impl->oe->p(err.msg);
      return MR_PEER_DISCON;
    }
    
  }

  lbuffer = impl->pre->get_lcode();
  buffer = impl->oe->getmem(lbuffer);
  if (!buffer) {
    impl->oe->p("Out of memory.");
    rc = MR_NOMEM;
    goto fail;
  }

  lmac = lbuffer;
  mac = impl->oe->getmem(lmac);
  if (!buffer) {
    ERR(impl->oe,"Out of memory.");
    rc = MR_NOMEM;
    goto fail;
  }
  

  for(p = 0;p < impl->pre->get_nplayers();++p) {
    MpcPeer peer = 0;
    CAR err = {0};

    // TODO(rwz): supporting more players than 2 we need to have a
    // player map with ids. 
    assert(impl->pre->get_nplayers() == 2);
    if (p == impl->pre->get_playerid()) continue;

    peer = impl->com->get_peer(0);
    
    err = peer->receive(Data_shallow(buffer,lbuffer));
    if (err.rc != OK) {
      impl->oe->p(err.msg);
      return MR_PEER_DISCON;
    }

    err = peer->receive(Data_shallow(mac,lmac));
    if (err.rc != RC_OK) {
      impl->oe->p(err.msg);
      return MR_PEER_DISCON;
    }

    if (!minimacs_check_othershare_fast(impl->menc,
					delta_share,
					impl->pre->get_playerid() == 0 ? 1 : 0,
					buffer,
					mac,
					lbuffer)) {
      impl->oe->p("Player %u has detected cheating.",impl->pre->get_playerid());
      return MR_WRONG_MAC;
    }

    for(i = 0; i < DATA_BYTES;++i) {
      delta[i] ^= buffer[i];
    }
  }

  for(i = 0; i < DATA_BYTES;++i) {
    delta[i] = delta[i] ^ delta_share->dx_codeword[i] ^ delta_share->codeword[i];
  }

  impl->oe->putmem(buffer);buffer=0;
  impl->oe->putmem(mac);mac=0;


  /*
  {
    byte clear_r[DATA_BYTES] = {0};
    MiniMacsRep xored = 0;
    _lhr(this,box->R,"The R in the box",clear_r);
    lhl(this, PLX_ADR,"The plaintext",-1);

    xored = box->table[0][clear_r[0]];
    for(i = 1;i < DATA_BYTES;++i) {
      MiniMacsRep tmp = xored;
      xored = minimacs_rep_xor(impl->oe,xored,box->table[i][clear_r[i]]);
    }
    lhr(this,xored,"Looking up with R shoud gain all 0x63 if the box is proper");
  }
  */

  // Right we got the delta_share now comes the lookup
  // Looking up the appropriate entries in the S-boxSRMC
  {
    MiniMacsRep result = box->table[0][delta[0]];
    for(i = 1;i < (DATA_BYTES/16)*16;++i) {
      MiniMacsRep rep = box->table[i][delta[i]];
      MiniMacsRep tmp = result;
      if (i < 17) {
	lhr(this,box->table[i][delta[i]],"computing the sumes towards the box");
      }
      result = minimacs_rep_xor(impl->oe,rep,result);
      minimacs_rep_clean_up(impl->oe, &tmp);
      if (!result) {
	ERR(impl->oe,"Error xoring box values.");
	return MR_NOMEM;
      }

    }
    lhr(this,result,"After Sbox-SRMC operation");
    impl->heap->put((void*)(ull)dst,result);
  }
  return MR_OK;
 fail:
  return rc;

}

static MATRIX *
load_matrix(OE oe, byte * data, uint h, uint w) {
	MATRIX * res = new_matrix(oe, h, w);
	uint row = 0, col = 0;

	for (row = 0; row < h; ++row) {
		for (col = 0; col < w; ++col) {
			matrix_setentry(res, row, col, data[col + w*row]);
		}
	}
	return res;
}


extern byte mc[16][16];
extern byte sr[16][16];
//xextern byte srmc_2[16][16];
extern byte KS[16][16];

COO_DEF(DAesMiniMac,MR,sbox_srmc,uint dst, uint op) {
  DAesMiniMacImpl impl = (DAesMiniMacImpl)this->impl;
  OE oe = impl->oe;
  CheetahSBox box = 0;
  static MATRIX * srmc_ = 0;
  if (srmc_ == 0) {
    MATRIX * SR = load_matrix(oe, (byte*)sr,16,16);
    MATRIX * MC = load_matrix(oe, (byte*)mc,16,16);
    MATRIX * srmc = matrix_multiplication(MC,SR);
    srmc_ = srmc;
  }
  box = impl->pre->get_sbox_srmc();
  if (!box) {
    ERR(impl->oe,"Box not available, aborting");
    return MR_NO_PREP;
  }

  return compute_box(this,dst,op,box,srmc_);
}}

#define SWAP(A,B) A=(A)^(B);B=(A)^(B);A=(A)^(B);
#define ROT(D) {\
    SWAP((D)[12],(D)[13]);			\
    SWAP((D)[13],(D)[14]);			\
    SWAP((D)[14],(D)[15]);			\
  }

#define IROT(D) {\
    SWAP((D)[15],(D)[14]);			\
    SWAP((D)[14],(D)[13]);			\
    SWAP((D)[13],(D)[12]);			\
  }

COO_DEF(DAesMiniMac,MR,key_box,uint dst, uint src) {
  DAesMiniMacImpl impl = (DAesMiniMacImpl)this->impl;
  OE oe = impl->oe;
  MR mr = MR_OK;
  MiniMacsRep rep = 0, delta = 0;
  uint p = 0, i = 0, block = 0, z=0;
  byte clear_delta[DATA_BYTES] = {0};
  MATRIX * MKS = load_matrix(oe,(byte*)KS,16,16);
  CheetahKBox kbx = impl->pre->get_key_box();

  if (!MKS) {
    ERR(impl->oe, "No memory.");
    return MR_NOMEM;
  }
  
  if (!kbx) {
    ERR(impl->oe,"No more key boxes :-(");
    return MR_NO_PREP;
  }
  
  rep = impl->heap->get( (void*)(ull) src );
  if (!rep) {
    ERR(oe,"Heap address %u not available.");
    return MR_HEAP_NOT_AVAIL;
  }
  //  lhr(this,rep,"The plain key before anything");
  
  delta = minimacs_rep_xor(impl->oe,rep,kbx->R);
  if (!delta) {
    ERR(oe, "Xor operation failed.");
    return MR_REP_OP_FAILED;
  }
  

  // Send shares
  for(p = 0;p < impl->pre->get_nplayers();++p) {
    MpcPeer peer = 0;
    CAR err = {0};

    if (p == impl->pre->get_playerid()) continue;

    peer = impl->com->get_peer(0);
    if (!peer) {
      impl->oe->p("Aborting computation, peer %u has disconnected.",p);
      return MR_PEER_DISCON;
    }

    err = peer->send(Data_shallow(delta->codeword,delta->lcodeword));
    if (err.rc != OK) {
      ERR(oe,"Sending data to peer failed: %s",err.msg);
      return MR_PEER_DISCON;
    }

    err = peer->send(Data_shallow(delta->mac[p]->mac,delta->mac[p]->lmac));
    if (err.rc != OK) {
      ERR(oe,"Sending mac data to peer failed: %s.",err.msg);
      return MR_PEER_DISCON;
    }
  }

  // Receive shares
  {
    Data data_buffer = 0, mac_buffer = 0;

    data_buffer = Data_new(oe,delta->lcodeword);
    if (!data_buffer) {
      ERR(oe, "No memory");
      return MR_NOMEM;
    }

    mac_buffer  = Data_new(oe,delta->lcodeword);
    if (!mac_buffer) {
      ERR(oe, "No memory");
      return MR_NOMEM;
    }

    for(p = 0; p < impl->pre->get_nplayers();++p) {
      MpcPeer peer = 0;
      CAR err = {0};
    

      if (p == impl->pre->get_playerid()) continue;

      peer = impl->com->get_peer(0);

      err = peer->receive(data_buffer);
      if (err.rc != OK) {
	ERR(oe,"Receiving data from peer failed: %s.",err.msg);
	return MR_PEER_DISCON;
      }

      err = peer->receive(mac_buffer);
      if (err.rc != OK) {
	ERR(oe,"Receiving data from peer failed: %s.",err.msg);
	return MR_PEER_DISCON;
      }

      if (!minimacs_check_othershare_fast(impl->menc,
					  delta,
					  p,
					  data_buffer->data,
					  mac_buffer->data,
					  data_buffer->ldata)) {
	oe->print("Player cheating ! Aborting computation, good bye.");
	ERR(oe, "MAC check failed on share from player %u",p);
	return MR_WRONG_MAC;
      }
      
      for(i = 0;i < DATA_BYTES;++i) {
	clear_delta[i] ^= data_buffer->data[i];
      }
    }

    Data_destroy(oe,&data_buffer);
    Data_destroy(oe,&mac_buffer);
    
    for(i = 0;i < DATA_BYTES;++i) {
      clear_delta[i] = clear_delta[i] ^ 
	delta->codeword[i] ^ 
	delta->dx_codeword[i];
    }
  } // end rceives shares

    minimacs_rep_clean_up(oe, &delta);
    
    // perform linear transformation ROT on clear_delta 
    for(block = 0; block < DATA_BYTES/16;++block) {
      ROT(clear_delta + block*16);
    }

    //    lhr(this,kbx->R,"The clear R value");
    {  // s in scope
      MiniMacsRep s = 0, t=0,epsilon=0;
      for(block = 0; block < DATA_BYTES/16;++block) {
	for(i=0;i<4;++i) {
	  // check tmp = (0,...,S_13 ^ R_14, 0...,0) 
	  // in pos 12
	  MiniMacsRep tmp = kbx->table[4*block+i][clear_delta[16*block+12+i]];
	  if (!s) {
	    s = tmp;
	  } else {
	    t = s;
	    s = minimacs_rep_xor(oe,s,tmp);
	    minimacs_rep_clean_up(oe,&t);
	  }
	  //	  lhr(this,s,"Building sum");
	}
      }

      t = s;
      s = minimacs_rep_add_const_fast(oe, impl->menc, s, clear_delta, DATA_BYTES);
      minimacs_rep_clean_up(oe,&t);
      //      lhr(this,s,"Got the state before KS");
      
      zeromem(clear_delta,DATA_BYTES);
      delta = minimacs_rep_xor(oe, s, kbx->T);
      // Send shares
      for(p = 0;p < impl->pre->get_nplayers();++p) {
	MpcPeer peer = 0;
	CAR err = {0};
	
	if (p == impl->pre->get_playerid()) continue;
	
	peer = impl->com->get_peer(0);
	if (!peer) {
	  impl->oe->p("Aborting computation, peer %u has disconnected.",p);
	  return MR_PEER_DISCON;
	}
	
	err = peer->send(Data_shallow(delta->codeword,delta->lcodeword));
	if (err.rc != OK) {
	  ERR(oe,"Sending data to peer failed: %s",err.msg);
	  return MR_PEER_DISCON;
	}
	
	err = peer->send(Data_shallow(delta->mac[p]->mac,delta->mac[p]->lmac));
	if (err.rc != OK) {
	  ERR(oe,"Sending mac data to peer failed: %s.",err.msg);
	  return MR_PEER_DISCON;
	}
      }


      // open S (X) T
      // Receive shares
      { // open delta for T
	Data data_buffer = 0, mac_buffer = 0;
	
	data_buffer = Data_new(oe,delta->lcodeword);
	if (!data_buffer) {
	  ERR(oe, "No memory");
	  return MR_NOMEM;
	}
	
	mac_buffer  = Data_new(oe,delta->lcodeword);
	if (!mac_buffer) {
	  ERR(oe, "No memory");
	  return MR_NOMEM;
	}
	
	for(p = 0; p < impl->pre->get_nplayers();++p) {
	  MpcPeer peer = 0;
	  CAR err = {0};
	  
	  
	  if (p == impl->pre->get_playerid()) continue;
	  
	  peer = impl->com->get_peer(0);
	  
	  err = peer->receive(data_buffer);
	  if (err.rc != OK) {
	    ERR(oe,"Receiving data from peer failed: %s.",err.msg);
	    return MR_PEER_DISCON;
	  }
	  
	  err = peer->receive(mac_buffer);
	  if (err.rc != OK) {
	    ERR(oe,"Receiving data from peer failed: %s.",err.msg);
	    return MR_PEER_DISCON;
	  }
	  
	  if (!minimacs_check_othershare_fast(impl->menc,
					      delta,
					      p,
					      data_buffer->data,
					      mac_buffer->data,
					      data_buffer->ldata)) {
	    oe->print("Player cheating ! Aborting computation, good bye.");
	    ERR(oe, "MAC check failed on share from player %u",p);
	    return MR_WRONG_MAC;
	  }
	  
	  for(i = 0;i < DATA_BYTES;++i) {
	    clear_delta[i] ^= data_buffer->data[i];
	  }
	}
	
	Data_destroy(oe,&data_buffer);
	Data_destroy(oe,&mac_buffer);
	
	for(i = 0;i < DATA_BYTES;++i) {
	  clear_delta[i] = clear_delta[i] ^ 
	    delta->codeword[i] ^ 
	    delta->dx_codeword[i];
	}
      } // end rceives shares

      // compute KSxDelta
      for(block=0;block<DATA_BYTES/16;++block) {
	MATRIX * vec = 0;
	MATRIX * res = 0;
	vec = new_matrix(oe,16,1);

	for(z = 0; z < 16;++z) {
	  matrix_setentry(vec,z,0,clear_delta[16*block+z]);
	}
	
	res = matrix_multiplication(MKS,vec);
	destroy_matrix(vec);
	
	if (!res) {
	  ERR(oe,"Failed to multiply matrices");
	  return MR_NOMEM;
	}
	for(z = 0;z < 16;++z) {
	  clear_delta[16*block+z] = matrix_getentry(res,z,0);
	}
	destroy_matrix(res);
      }

      epsilon = minimacs_rep_xor(oe,s,rep);
      if (!epsilon) {
	ERR(oe, "Failed to compute epsilon :-()");
	return MR_REP_OP_FAILED;
      }
      minimacs_rep_clean_up(oe,&s);
      s=t=0;

      s = minimacs_rep_add_const_fast(oe, impl->menc, epsilon, clear_delta, DATA_BYTES);
      minimacs_rep_clean_up(oe, &epsilon);
      t=s;
      s = minimacs_rep_xor(oe,s,kbx->KSxT);
      minimacs_rep_clean_up(oe,&t);
      impl->heap->put( (void*)(ull)dst, s);
    }
   
  return mr;
}}

COO_DEF(DAesMiniMac,MR,sbox_sr,uint dst, uint op) {
  DAesMiniMacImpl impl = (DAesMiniMacImpl)this->impl;
  CheetahSBox box = 0;
  MATRIX * sr_ = 0;
  if (!sr_) {
    sr_ = load_matrix(impl->oe,(byte*)sr,16,16);
  }
  

  box = impl->pre->get_sbox_sr();
  if (!box) {
    ERR(impl->oe,"Box not available, aborting");
    return MR_NO_PREP;
  }

  return compute_box(this,dst,op,box,sr_);

}}

// Assign only constructor
DAesMiniMac DAesMiniMac_New(OE oe, MiniMacsEnc menc, MiniMacsEnc smenc, Map heap, AesPreprocessing aespre, CArena arena) {
	DAesMiniMac result = (DAesMiniMac)oe->getmem(sizeof(*result));
	if (result == 0) return 0;

	DAesMiniMacImpl impl = (DAesMiniMacImpl)oe->getmem(sizeof(*impl));
	if (impl == 0) goto fail;

	impl->oe = oe;
	impl->heap = heap;
	impl->menc = menc;
	impl->smenc = smenc;
	impl->pre = aespre;
	impl->com = arena;

	result->impl = impl;
	result->cpy = COO_attach(result, DAesMiniMac_cpy);
	result->xor = COO_attach(result, DAesMiniMac_xor);
	result->get = COO_attach(result, DAesMiniMac_get);
	result->input = COO_attach(result, DAesMiniMac_input);
	result->sbox_srmc = COO_attach(result, DAesMiniMac_sbox_srmc);
	result->sbox_sr = COO_attach(result, DAesMiniMac_sbox_sr);
	result->open = COO_attach(result, DAesMiniMac_open);
	result->key_box = COO_attach(result, DAesMiniMac_key_box);
	result->rcon = COO_attach(result, DAesMiniMac_rcon);

	return result;
fail:
	DAesMiniMac_Destroy(&result);
	return 0;
}
// -----------------------------------------------------
// DAesMiniMacs Done
// -----------------------------------------------------


// -------------------- MPC AES Implementation ------------------------
static MR
add_round_key(DAesMiniMac amm, uint round) {
  MR mr = amm->xor(PLX_ADR,PLX_ADR,KEY_ADR);
  return mr;
}

/*
  round goes from 1 to 10 both inclusive;
 */
static MR
key_schedule(OE oe, DAesMiniMac amm, uint round) {
  MR mr = MR_OK;

  if (round < 1 || round > 10) {
    ERR(oe, "Bad round %u",round);
    return MR_BAD_ARGS;
  }


  mr = amm->key_box(KEY_ADR,KEY_ADR);
  if (mr != MR_OK) { 
    ERR(oe, "Key box operationg failed for address %u",KEY_ADR);
    return mr;
  }


  mr = amm->rcon(KEY_ADR,round);
  if (mr != MR_OK) {
    ERR(oe, "Rcon operation failed for address %u and round %u.",KEY_ADR,round);
    return mr;
  }


  return mr;
}

static MR load_key_share(DAesMiniMac mm, byte * key) {
  uint id = 0;
  MR mr = MR_OK;
  DAesMiniMacImpl impl = (DAesMiniMacImpl)mm->impl;
  uint nplayers = impl->pre->get_nplayers();
  impl->oe->print("\n");
  for(id = 0;id < nplayers;++id) {
    impl->oe->print("Loading key share from player %u\n",id);
    mr = mm->input(id,KEY_ADR,key);
    if (mr != MR_OK) return mr;
  }
  return mr;
}

static MR load_plx(DAesMiniMac mm, byte * plx) {
  DAesMiniMacImpl impl = (DAesMiniMacImpl)mm->impl;
  MiniMacsRep vrep = minimacs_create_rep_public_plaintext_fast(impl->oe, 
							       impl->menc,
							       plx,
							       impl->pre->get_lmsg(),
							       impl->pre->get_lcode());
  if (vrep == 0) {
    ERR(impl->oe,"Could not create public representation.");
    return MR_NOMEM;
  }
  impl->heap->put((void*)(ull)PLX_ADR,vrep);
  return MR_OK;
}


static void _print_rep(OE oe,MiniMacsRep rep,
		       const char * file, uint line, const char * fun) {
  uint i = 0; 
 oe->print("\n[%s:%u:<%s>]:\n",file,line,fun);
  oe->print("dx: ");
  for(i = 0; i < 16;++i) 
    if (rep->dx_codeword) {
      oe->print("%02x ",rep->dx_codeword[i]);
    } else {
      oe->print("Public value");
    }
  
  oe->print("\ncw: ");
  for(i = 0; i < 16; ++i) 
    oe->print("%02x ",rep->codeword[i]);
  oe->print("\n");
}

static void _print_state(OE oe,DAesMiniMac mm, uint adr, 
			 const char * file, uint line, const char * fun) {
      MiniMacsRep rep = ((DAesMiniMacImpl)mm->impl)->heap->get((void*)(ull)adr);
      _print_rep(oe,rep,file,line,fun);
} 
#ifdef DEBUG
static void __lhr(DAesMiniMac mm, MiniMacsRep rep, char * msg, byte * clear_out) {
  DAesMiniMacImpl im = mm->impl;
  MpcPeer p = debugPeer;
  uint lmsg = 0;
  byte v[DATA_BYTES] = {0};
  byte c[DATA_BYTES] = {0};
  byte s[3*DATA_BYTES+15+180] = {0};
  uint i = 0, o = 0;
  bool isconst = minimacs_rep_is_public_const(rep);

  if (im->pre->get_playerid() == 0) {
    while(msg[lmsg++]);

    if (isconst) {
      mcpy(c,rep->codeword,DATA_BYTES);
    } else {
      p->receive(Data_shallow(v,DATA_BYTES));
      for(i = 0;i < DATA_BYTES;++i) {
	c [i]= rep->codeword[i] ^ rep->dx_codeword[i] ^ v[i];
      }
      p->send(Data_shallow(rep->codeword,DATA_BYTES));
    }
    
    o += osal_sprintf(s,"%s\n",msg);
    for(i = 0;i < DATA_BYTES;++i) {
      if (i > 0 && i % 16 ==0) o += osal_sprintf(s+o,"\n");
      o += osal_sprintf(s+o,"%2x ",c[i]);
    }
    
    im->oe->p(s);
  } else {
    if (!isconst) {
      p->send(Data_shallow(rep->codeword,DATA_BYTES));
      p->receive(Data_shallow(v,DATA_BYTES));
      for(i = 0;i < DATA_BYTES;++i) {
	c [i]= rep->codeword[i] ^ rep->dx_codeword[i] ^ v[i];
      }
    }
  }

  if (clear_out != 0) {
    mcpy(clear_out,c,DATA_BYTES);
  }
}


static void _lhr(DAesMiniMac mm, MiniMacsRep rep, char * msg) {
  _lhr(mm,rep,msg,0);
}


static void _lhl(DAesMiniMac mm, uint src,char * msg,uint round)  {
  DAesMiniMacImpl im = mm->impl;
  MiniMacsRep rep = im->heap->get( (void*)(ull)src );
  if (im->pre->get_playerid() == 0) {
    im->oe->p("<~~~~~~~~~~ ROUND %d ~~~~~~~~~~>",round);
  }
  lhr(mm,rep,msg);
}
#endif
/*
 So we are running 7 AES instances in parallel in each code word and
 so the {key} and {plx} must have length 7*16 and our codeword are
 going to have that length exactly.

 112 length message is codewords of length 240 !

 Preprocessing parameters are ltext=112 and lcode=240

 Heap address 0 will be the code word containing the current 7 round
 keys,

 and heap address 1 will be the code word containing the current 7
 AES-states.

 */
int mpc_aes(OE oe, DAesMiniMac mm, byte * key, byte * plx, byte ** ctx, bool ks) {
  uint i=0,j=0;
  uint round = 0;
  byte * res = 0;
  DAesMiniMacImpl im = mm->impl;
  DateTime dt = DateTime_New(im->oe);
  ull start = 0;
  CArena debugger = 0;

#ifdef DEBUG
  debugger = CArena_new(oe);
  if (im->pre->get_playerid() == 0) {
    oe->p("Connecting to Heap Debugger");
    debugger->connect("127.0.0.1",8123);
    debugPeer = debugger->get_peer(0);
    if (!debugPeer) {
      ERR(oe,"Oh no debug peer not available.");
      return -1;
    }
  } else {
    oe->p("Heap Debugger Listening on port 8123");
    debugger->listen_wait(1,8123);
    debugPeer = debugger->get_peer(0);
    if (!debugPeer) {
      ERR(oe,"Oh no debug peer not available.");
      return -1;
    }
  }
#endif
  
  if (!mm) { 
    oe->p("Parameter mm (DAesMiniMac instance) was not set. {mm} == 0, aborting.");
    return -1;
  }

  if (!key) { 
    oe->p("Parameter key was not set. {key} == 0, aborting.");
    return -1;
  }

  if (!plx) { 
    oe->p("Parameter plaintext was not set. {plx} == 0, aborting.");
    return -1;
  }

  if (load_key_share(mm,key) != MR_OK) {
    oe->p("Operation load_key failed.");
    return -1;
  }

  if (load_plx(mm, plx) != MR_OK) {
    oe->p("opertaion load plaintext failed.");
    return -1;
  }


  //  lhl(mm,KEY_ADR,"<~~~~ Round Key ~~~~>",0);
  //  lhl(mm,PLX_ADR,"<~~~~ Round Plx ~~~~>",0);
  start = dt->getMilliTime();
  if (add_round_key(mm,round) != MR_OK) { 
    oe->p("Operation add_round_key failed. {add_round_key(mm) == MR_OK}");
    return -1;
  } 

  for(round = 1; round < 11;++round) {

    // update the key schedule
    if (ks == True) {
       if (key_schedule(oe,mm,round) != MR_OK) {
	oe->p("%s:%d key schedule failed.",__FILE__,__LINE__);
	return -1;
      }
    }

    if (round < 10) {
      if (mm->sbox_srmc(PLX_ADR, PLX_ADR) != MR_OK) {
	oe->p("%s:%d iteration %u, sbox_srmc failed",__FILE__,__LINE__,round);
	return -1;
      }
    } else {
      if (mm->sbox_sr(PLX_ADR, PLX_ADR) != MR_OK) {
	oe->p("%s:%d sbox_sr failed",__FILE__,__LINE__);
	return -1;
      }
    }

    if (add_round_key(mm,round) != MR_OK) { 
      oe->p("%s:%d sbox_sr failed",__FILE__,__LINE__);
      return -1;
    }
    
    //    lhl(mm,KEY_ADR,"<~~~~ Round i Key ~~~~>",round);
    //    lhl(mm,PLX_ADR,"<~~~~ Round i Plx ~~~~>",round);
  }

  oe->p("AES Took %lums",dt->getMilliTime()-start);
  if (mm->open(PLX_ADR) != MR_OK) { 
    oe->p("%s:%d open failed",__FILE__,__LINE__);
    return -1;
  }

  if (ctx != 0) {
    *ctx = mm->get(PLX_ADR);
  }

  return 0;
}
//END END-------------- MPC AES Implementation -----------------END END


// -----------------------------------------------------
// DAesMiniMac pre-processing provider
// -----------------------------------------------------


typedef struct _aes_preprocessing_impl_ {
	OE oe;
	DerInputStream in;

	// the cached decomposed reps in memory
	List decomp_cache;
	// number of decomposed read so far
	uint decomp_read;

	// the cached singles in memory
	List single_cache;
	// number of single read so far
	uint single_read;
	
	// the cached srmc Sboxs in memory
	List sbox_srmc_cache;
	// number of srmc sboxs read so far
	uint box_srmc_read;

	// the cached sr sboxes in memory
	List sbox_sr_cache;

  uint lintranses_read;
  List lintranses;

  // --- Key schedule core ---
  List keyboxes;

	// number of sr sboxes read so far
	uint sr_read; 
	uint playerid;
	uint nplayers;
	uint version;
	uint lmsg;
	uint lcode;
	char * purpose;
} *AesPreprocessingImpl;


COO_DEF(AesPreprocessing, CheetahKBox, cache_get_key_box) {
  AesPreprocessingImpl impl = (AesPreprocessingImpl)this->impl;
  CheetahKBox kbx = impl->keyboxes->get_element(0);
  if (kbx) impl->keyboxes->rem_element(0);
  return kbx;
}}

COO_DEF(AesPreprocessing, CheetahDVal, cache_get_decom_val) {
AesPreprocessingImpl impl = (AesPreprocessingImpl)this->impl;
 return 0;
}}

COO_DEF(AesPreprocessing, uint, cache_get_lcode) {
AesPreprocessingImpl impl = (AesPreprocessingImpl)this->impl;
return impl->lcode;
}}

COO_DEF(AesPreprocessing, uint, cache_get_lmsg) {
AesPreprocessingImpl impl = (AesPreprocessingImpl)this->impl;
return impl->lmsg;
}}

COO_DEF(AesPreprocessing, uint , cache_get_nplayers) {
AesPreprocessingImpl impl = (AesPreprocessingImpl)this->impl;
return impl->nplayers;
}}

COO_DEF(AesPreprocessing, uint, cache_get_playerid) {
AesPreprocessingImpl impl = (AesPreprocessingImpl)this->impl;
return impl->playerid;
}}

static void * get_and_load(OE oe, List cache) {
	void * res = 0;
	if (cache->size() == 0) {
		oe->syslog(OSAL_LOGLEVEL_WARN, "[%s:%u] out of material.", __FUNCTION__, __LINE__);
		return  0;
	}

	res = cache->get_element(0);
	cache->rem_element(0);
	oe->p("cache access %u remaining",cache->size());
	return res;
}

COO_DEF(AesPreprocessing, CheetahSBox, cache_get_sbox_sr)
AesPreprocessingImpl impl = (AesPreprocessingImpl)this->impl;
return get_and_load(impl->oe, impl->sbox_sr_cache);
}

COO_DEF(AesPreprocessing, CheetahSBox, cache_get_decomp)
AesPreprocessingImpl impl = (AesPreprocessingImpl)this->impl;
return get_and_load(impl->oe, impl->decomp_cache);
}


COO_DEF(AesPreprocessing, CheetahSBox, cache_get_sbox_srmc)
AesPreprocessingImpl impl = (AesPreprocessingImpl)this->impl;
return get_and_load(impl->oe, impl->sbox_srmc_cache);
}

COO_DEF(AesPreprocessing, MiniMacsRep, cache_get_single)
AesPreprocessingImpl impl = (AesPreprocessingImpl)this->impl;
return get_and_load(impl->oe, impl->single_cache);
}
List SingleLinkedList_new(OE oe);


static RC read_minimacs_rep(OE oe, DerInputStream in, MiniMacsRep * out) {
	RC rc = RC_OK;
	MiniMacsRep rep = oe->getmem(sizeof(*rep));
	uint i = 0;
	ull v = 0;

	rc = in->begin_seq();
	rc = in->read_int(&v);rep->lval = v;
	rc = in->read_str(&rep->dx_codeword, &rep->ldx_codeword);
	rc = in->read_str(&rep->codeword, &rep->lcodeword);

	// -- read the macs --
	rc = in->begin_seq();
	rc = in->read_int(&v);rep->lmac = v;
	rep->mac = oe->getmem(sizeof(bedoza_mac)*rep->lmac);
	if (rep->mac == 0) {
		rc = RC_NOMEM;
		goto fail;
	}

	for (i = 0; i < rep->lmac-1; ++i) {
		bedoza_mac mac = oe->getmem(sizeof(*mac));
		rc = in->begin_seq();
		rc = in->read_int(&v);mac->mid = v;
		rc = in->read_int(&v);mac->toid = v;
		rc = in->read_int(&v);mac->fromid = v;
		rc = in->read_str(&(mac->mac), &(mac->lmac));
		rc = in->leave_seq();
		rep->mac[mac->fromid] = mac;
	}
	rc = in->leave_seq();
	// -- read the macs done ---


	// -- read the keys --
	rc = in->begin_seq();
	rc = in->read_int(&v);rep->lmac_keys_to_others = v;
	rep->mac_keys_to_others = oe->getmem(sizeof(bedoza_mac_key)*rep->lmac_keys_to_others);
	for (i = 0; i < rep->lmac_keys_to_others; ++i) {
		ull v = 0;
		rep->mac_keys_to_others[i] = oe->getmem(sizeof(*rep->mac_keys_to_others[0]));
		rc = in->begin_seq();
		rc = in->read_int(&v);
		(rep->mac_keys_to_others[i]->mid) = v;
		rc = in->read_int(&v);
		(rep->mac_keys_to_others[i]->toid) = v;
		rc = in->read_int(&v);
		(rep->mac_keys_to_others[i]->fromid) = v;
		rc = in->read_str(&rep->mac_keys_to_others[i]->alpha, 
			              &rep->mac_keys_to_others[i]->lalpha);
		rc = in->read_str(&rep->mac_keys_to_others[i]->beta,
						  &rep->mac_keys_to_others[i]->lbeta);
		rc = in->leave_seq();
	}
	rc = in->leave_seq();
	// -- read the keys done --
	rc = in->leave_seq();
	// -- and we are done --

	if (out) *out = rep;
	return rc;
fail:
	return rc;
}

COO_DEF(AesPreprocessing, char *, Cached_get_purpose) {
	AesPreprocessingImpl impl = (AesPreprocessingImpl)this->impl;
	return impl->purpose;
}}

static RC matrix_read(OE oe, DerInputStream in, MATRIX ** mout) {
  ull height = 0, width = 0;
  uint  ldata = 0;
  byte * data = 0;
  RC rc = RC_OK;

  in->begin_seq();
  in->read_int(&height);
  in->read_int(&width);
  data = oe->getmem(height*width);
  in->read_str(&data,&ldata);
  in->leave_seq();
  if (mout) *mout = matrix_from_flatmem(oe,data,height,width);
  oe->putmem(data);
  return RC_OK;
}

// -----------------------------------------------------
// Cache based preprocessing 
//
// AesPreprocessing is a provider of pre-processing material
// to the DAesMiniMac protocol. Cheetah is the actual algo. 
// that builds and stores the preprocessing to disk.
//
// This cache based provider reads more material from disk 
// as needed holder a prepared cache of material in memory.
//
// -----------------------------------------------------
AesPreprocessing AesPreprocessing_Cached_New(OE oe, const char * filename,
	uint cache_no_sbox_srmc,
	uint cache_no_decomp_val,
	uint cache_no_single,
	uint cache_no_srmc,
	uint cache_no_sr,
	uint cache_no_sbox_sr) {
	uint lfilename = osal_strlen(filename);
	byte * openreq = oe->getmem(lfilename + 10);
	FD fd = 0;
	RC rc = RC_OK;
	AesPreprocessing prep = 0;
	AesPreprocessingImpl impl = 0;
	uint k = 0, i = 0, j = 0;
	ull singles_in_file = 0;
	uint notoload = 0;
	ull v = 0;

	osal_sprintf((char*) openreq, "file %s", filename);
	rc = oe->open((char*)openreq, &fd);
	oe->putmem(openreq);
	if (rc != RC_OK) {
		oe->syslog(OSAL_LOGLEVEL_WARN, "file %s not fould.", filename);
		return 0;
	}

	impl = (AesPreprocessingImpl)oe->getmem(sizeof(*impl));
	if (!impl) goto fail;
		
	prep = (AesPreprocessing)oe->getmem(sizeof(*prep));
	if (!prep) goto fail;
	// TODO(rwz): Needs to be done

	prep->impl = impl;
	impl->oe = oe;
	

	impl->decomp_cache = SingleLinkedList_new(oe);
	impl->single_cache = SingleLinkedList_new(oe);
	impl->sbox_srmc_cache = SingleLinkedList_new(oe);
	impl->sbox_sr_cache = SingleLinkedList_new(oe);
	impl->lintranses = SingleLinkedList_new(oe);
	impl->keyboxes = SingleLinkedList_new(oe);

	oe->p("Loading pre-processing");

	// --- load caches ---
	impl->in = DerInputStream_New(oe, fd);
	if (!impl->in) goto fail;
	rc = impl->in->begin_seq();
	if (rc != RC_OK) goto fail;
	// skip INFO
	rc = impl->in->begin_seq();
	if (rc != RC_OK) goto fail;
	{
		ull playerid = 0;
		ull nplayers = 0;
		ull version = 0;
		byte * purpose = 0;
		uint l = 0; ull v = 0;
		rc = impl->in->read_int(&playerid);
		if (rc != RC_OK) goto fail;
		rc = impl->in->read_int(&nplayers);
		if (rc != RC_OK) goto fail;
		rc = impl->in->read_int(&version);
		if (rc != RC_OK) goto fail;
		rc = impl->in->read_str(&purpose, &l);
		if (rc != RC_OK) goto fail;
		rc = impl->in->read_int(&v);impl->lmsg = v;
		if (rc != RC_OK) goto fail;
		rc = impl->in->read_int(&v); impl->lcode =v;
		if (rc != RC_OK) goto fail;
		impl->nplayers = nplayers;
		impl->playerid = playerid;
		impl->version = version;
		impl->purpose = (char*)purpose;
	}
	rc = impl->in->leave_seq();
	if (rc != RC_OK) goto fail;

	oe->p("Loaded preprocessing nplayers: %u, id:%u, version:%u.",impl->nplayers,
	      impl->playerid, impl->version);
	
	// skip Decomp
	rc = impl->in->begin_seq();
	if (rc != RC_OK) goto fail;

	rc = impl->in->read_int(&v);
	if (rc != RC_OK) goto fail;

	notoload = ( v > cache_no_decomp_val ? cache_no_decomp_val : v );
	oe->p("loading %u decomp values.",notoload);
	for(k = 0; k < notoload;++k) {
	  
	}

	rc = impl->in->leave_seq();
	if (rc != RC_OK) goto fail;
	

	// load SBOX SRMC
	rc = impl->in->begin_seq();
	if (rc != RC_OK) goto fail;

	rc = impl->in->read_int(&v);
	if (rc != RC_OK) goto fail;
	
	notoload = (v>cache_no_sbox_srmc ? cache_no_sbox_srmc : v);
	oe->p("loading %u sbox_srmc values.",notoload);
	for( k = 0; k < notoload;++k) {
	  CheetahSBox box = oe->getmem(sizeof(*box));
	  if (!box) {
	    ERR(oe, "Out of memory allocating box");
	    rc = RC_NOMEM;
	    goto fail;
	  }
	  
	  rc = impl->in->begin_seq();
	  if (rc != RC_OK) goto fail;

	  rc = read_minimacs_rep(oe,impl->in,&box->R);
	  if (rc != RC_OK) goto fail;

	  for( i = 0; i < (DATA_BYTES/16)*16; ++i) {
	    for ( j = 0; j < 256; ++j) {
	      rc = read_minimacs_rep(oe, impl->in, &box->table[i][j]);
	      if (rc != RC_OK) goto fail;
	    }
	  }
	  rc = impl->in->leave_seq();
	  if (rc != RC_OK) goto fail;
	  oe->p("done loading box %u/%u",k+1,notoload);
	  impl->sbox_srmc_cache->add_element(box);
	}
	rc = impl->in->leave_seq();
	if (rc != RC_OK) goto fail;

	// load SBOX_SR
	rc = impl->in->begin_seq();
	if (rc != RC_OK) goto fail;
	rc = impl->in->read_int(&v);
	if (rc != RC_OK) goto fail;

	notoload = (v > cache_no_sbox_sr ? cache_no_sbox_sr : v);
	oe->p("loading %u sbox_sr box(es).",notoload);
	for( k = 0; k < notoload; ++k) {
	  
	  CheetahSBox box = oe->getmem(sizeof(*box));
	  if (!box) {
	    ERR(oe, "Out of memory allocating box.");
	    rc = RC_NOMEM;
	    goto fail;
	  }

	  rc = impl->in->begin_seq();
	  if (rc != RC_OK) goto fail;

	  rc = read_minimacs_rep(oe,impl->in,&box->R);
	  if (rc != RC_OK) goto fail;

	  for(i = 0; i < (DATA_BYTES/16)*16;++i) {
	    for(j = 0; j < 256; ++j) {
	      rc = read_minimacs_rep(oe,impl->in,&box->table[i][j]);
	      if (rc != RC_OK) goto fail;
	    }
	  }
	  rc = impl->in->leave_seq();
	  if (rc != RC_OK) goto fail;
	  oe->p("done loading sr-box %u/%u",k+1,notoload);
	  impl->sbox_sr_cache->add_element(box);
	}
	rc = impl->in->leave_seq();
	if (rc != RC_OK) goto fail;

	// Load linear transformations
	rc = impl->in->begin_seq();
	if (rc != RC_OK) goto fail;
	rc = impl->in->read_int(&v);
	if (rc != RC_OK) goto fail;
	notoload = v;
	for( k = 0; k < notoload;++k) {
	  CheetahLVal lval = oe->getmem(sizeof(*lval));
	  if (!lval) {
	    ERR(oe,"No more memory.");
	    return 0;
	  }
	  
	  rc = impl->in->begin_seq();
	  if (rc != RC_OK) goto fail;
	  rc = impl->in->read_int(&v);
	  if (rc != RC_OK) goto fail;
	  rc = read_minimacs_rep(oe,impl->in,&lval->R);
	  if (rc != RC_OK) goto fail;
	  rc = read_minimacs_rep(oe,impl->in,&lval->MxR);
	  if (rc != RC_OK) goto fail;
	  rc = matrix_read(oe,impl->in,&lval->M);
	  if (rc != RC_OK) goto fail;
	  rc = impl->in->leave_seq();
	  if (rc != RC_OK) goto fail;
	  
	  impl->lintranses->add_element(lval);
	}
	rc = impl->in->leave_seq();
	if (rc != RC_OK) goto fail;


	// KEY BOXES
	rc = impl->in->begin_seq();
	rc = impl->in->read_int(&v);
	notoload = v;

	for( k = 0; k < notoload;++k) {
	  CheetahKBox kbx = oe->getmem(sizeof(*kbx));
	  uint x=0,y=0;
	  oe->p("loading keybox %u/%u",k, notoload);
	  rc = impl->in->begin_seq();
	  rc = read_minimacs_rep(oe,impl->in, &kbx->R);
	  rc = read_minimacs_rep(oe,impl->in, &kbx->T);
	  rc = read_minimacs_rep(oe,impl->in, &kbx->KSxT);
	  for(x=0;x < DATA_BYTES/16*4;++x) {
	    for(y = 0; y < 256;++y) {
	      rc = read_minimacs_rep(oe,impl->in,&kbx->table[x][y]);
	    }
	  }
	  rc = impl->in->leave_seq();
	  impl->keyboxes->add_element(kbx);
	}
	rc = impl->in->leave_seq();


	// load singles
	// Now we are at the singles
	rc = impl->in->begin_seq();
	if (rc != RC_OK) goto fail;
	rc = impl->in->read_int(&singles_in_file);
	if (rc != RC_OK) goto fail;
	notoload = singles_in_file > cache_no_single ? cache_no_single : singles_in_file;
	for (k = 0; k < notoload; ++k) {
		MiniMacsRep rep = 0;
		rc = read_minimacs_rep(oe, impl->in, &rep);
		if (rc != RC_OK) return 0;
		impl->single_cache->add_element(rep);
	}

	prep->get_decom_val = COO_attach(prep, AesPreprocessing_cache_get_decom_val);
	if (!prep->get_decom_val) goto fail;
	prep->get_lcode = COO_attach(prep, AesPreprocessing_cache_get_lcode);
	if (!prep->get_lcode) goto fail;
	prep->get_lmsg= COO_attach(prep, AesPreprocessing_cache_get_lmsg);
	if (!prep->get_lcode) goto fail;
	prep->get_nplayers= COO_attach(prep, AesPreprocessing_cache_get_nplayers);
	if (!prep->get_nplayers) goto fail;
	prep->get_playerid = COO_attach(prep, AesPreprocessing_cache_get_playerid);
	if (!prep->get_playerid) goto fail;
	prep->get_sbox_sr = COO_attach(prep, AesPreprocessing_cache_get_sbox_sr);
	if (!prep->get_sbox_sr) goto fail;
	prep->get_sbox_srmc = COO_attach(prep, AesPreprocessing_cache_get_sbox_srmc);
	if (!prep->get_sbox_srmc) goto fail;
	prep->get_single = COO_attach(prep, AesPreprocessing_cache_get_single);
	if (!prep->get_single) goto fail;
	prep->get_key_box = COO_attach(prep,AesPreprocessing_cache_get_key_box);
	if (!prep->get_key_box) goto fail;
	//prep->get_sr= COO_attach(prep, AesPreprocessing_cache_get_sbox_sr);
	//if (!prep->get_sr) goto fail;
	//prep->get_srmc = COO_attach(prep, AesPreprocessing_cache_get_sbox_srmc);
	//if (!prep->get_srmc) goto fail;
	prep->get_purpose = COO_attach(prep, AesPreprocessing_Cached_get_purpose);

	return prep;

fail:
	oe->syslog(OSAL_LOGLEVEL_WARN, "Could not load preprocessing material.");
	DerInputStream_Destroy(&impl->in);
	AesPreprocesing_Cached_Destroy(&prep);
	return 0;
}

void AesPreprocesing_Cached_Destroy(AesPreprocessing * prep) {
}
// -----------------------------------------------------
// DAesMiniMac pre-processing provider END
// -----------------------------------------------------
