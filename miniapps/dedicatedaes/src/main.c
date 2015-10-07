/*

The MIT License(MIT)

Copyright(c) 2015 Aarhus University

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files(the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and / or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions :

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT.IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Author: Rasmus Winther Zakarias, Aarhus Crypto.

*/

#include <osal.h>
#include <map.h>
#include <cheetah_pre.h>
#include <cheetah.h>
#include <mpc_aes.h>
#include <utils/options.h>
#include <rnd.h>
#include <encoding/int.h>
#include <encoding/der.h>
#include <reedsolomon/minimacs_enc_fft.h>
#include <carena.h>
#include <hashmap.h>
#include <minimacs/minimacs_rep.h>
#include <minimacs/minimacs.h>
#include <datetime.h>

List SingleLinkedList_new(OE oe);

typedef enum _operations_ {
	DO_PREP,
	DO_AES_MPC,
	DO_COMPILE
} Operation;


typedef struct _lintrans_param_ {
  uint kind;
  MATRIX * M;
} * LinTransParam;

typedef struct _params_ {
	Operation op;
	union {
	  struct {
	    uint nplayers;
	    uint nsingle;
	    uint nsboxsrmc;
	    uint nsboxsr;
	    uint ndecomp;
	    uint nkeyboxes;
	    List lintranses; // List<LinTransParam>
	    char * fprefix;
	  } prep;
	  struct {
	    char * prep_file;
	    char * ip;
	    uint port;
	    bool ks;
	    uint blocks;
	    uint forks;
	  } mpc;
	  struct  {
	    char * filename;
	    uint offset;
	  } compile;
	} p;
} CfpParams;

static byte srmc[16][16] = 
  {{2,0,0,0 ,3,0,0,0 ,1,0,0,0 ,1,0,0,0},
   {0,2,0,0 ,0,3,0,0 ,0,1,0,0 ,0,1,0,0},    
   {0,0,2,0 ,0,0,3,0 ,0,0,1,0 ,0,0,1,0},    
   {0,0,0,2 ,0,0,0,3 ,0,0,0,1 ,0,0,0,1}, 
   
   {0,1,0,0 ,0,2,0,0 ,0,3,0,0 ,0,1,0,0},    
   {0,0,1,0 ,0,0,2,0 ,0,0,3,0 ,0,0,1,0},    
   {0,0,0,1 ,0,0,0,2 ,0,0,0,3 ,0,0,0,1},    
   {1,0,0,0 ,2,0,0,0 ,3,0,0,0 ,1,0,0,0},    
   
   {0,0,1,0 ,0,0,1,0 ,0,0,2,0 ,0,0,3,0},    
   {0,0,0,1 ,0,0,0,1 ,0,0,0,2 ,0,0,0,3},    
   {1,0,0,0 ,1,0,0,0 ,2,0,0,0 ,3,0,0,0},    
   {0,1,0,0 ,0,1,0,0 ,0,2,0,0 ,0,3,0,0},    
   
   {0,0,0,3 ,0,0,0,1 ,0,0,0,1 ,0,0,0,2},    
   {3,0,0,0 ,1,0,0,0 ,1,0,0,0 ,2,0,0,0},    
   {0,3,0,0 ,0,1,0,0 ,0,1,0,0 ,0,2,0,0},    
   {0,0,3,0 ,0,0,1,0 ,0,0,1,0 ,0,0,2,0}};

static byte sr[16][16] = {
  {1,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0},
  {0,1,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0},
  {0,0,1,0, 0,0,0,0, 0,0,0,0, 0,0,0,0},
  {0,0,0,1, 0,0,0,0, 0,0,0,0, 0,0,0,0},
  //
  {0,0,0,0, 0,1,0,0, 0,0,0,0, 0,0,0,0},
  {0,0,0,0, 0,0,1,0, 0,0,0,0, 0,0,0,0},
  {0,0,0,0, 0,0,0,1, 0,0,0,0, 0,0,0,0},
  {0,0,0,0, 1,0,0,0, 0,0,0,0, 0,0,0,0},
  //
  {0,0,0,0, 0,0,0,0, 0,0,1,0, 0,0,0,0},
  {0,0,0,0, 0,0,0,0, 0,0,0,1, 0,0,0,0},
  {0,0,0,0, 0,0,0,0, 1,0,0,0, 0,0,0,0},
  {0,0,0,0, 0,0,0,0, 0,1,0,0, 0,0,0,0},
  //
  {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1},
  {0,0,0,0, 0,0,0,0, 0,0,0,0, 1,0,0,0},
  {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,1,0,0},
  {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,1,0},
};

int atoi(char * a);

static MATRIX * 
load_matrix(OE oe, byte * data, uint h, uint w) {
  MATRIX * res = new_matrix(oe,h,w);
  uint row = 0, col = 0;
  
  for(row = 0; row < h;++row) {
    for(col = 0; col < w;++col) {
      matrix_setentry(res,row,col,data[col+w*row]);
    }
  }
  return res;
}

typedef enum {
  AES_SRMC = 0x00,
  AES_SR   = 0x01,
  AES_KS_ROT_LAST_WORD = 0x02,
} LinTransKind;


static void print_help(OE oe) {

	oe->print("\nPURPOSE\n-------\n"\
		"Program has two modes of operation. Either generating preprocessing material,\n"\
		"or acting as a MiniTrix-peer to carry out the dedicated AES protocol.\n"\
		"Options:\n"\
		" -mpc\t- this options tells the program to run as peer\n"\
		" -prep\t- this options tells the program to create preprocessing\n"\
		" -perpfile <filename>\t- is used with -mpc indicating file with prep. material\n"\
		" -port <port>\t - is used with -mpc indicating comm. port\n"\
		" -ip   <address>\t- is used with -mpc indicating ip address to connec to.\n"\
		" -nplayers\t- is used with -prep indicating how many players we prepare for\n"\
		" -nsboxsrmc\t- used with -prep the number of s-boxes in normal rounds\n"\
		" -nsboxsr\t- used with -prep the number of s-boxes in last round\n"\
		" -ndecomp\t- used with -prep the number of decomposed singles to create\n"\
		" -nsingles\t- used with -prep the number of singles to create\n"\
  	        " -nkeyboxes\t- used with -prep the number of key schedule boxes to create\n"\
		"\n\nExample:\n- Prepare for 2 parties computing one block of AES:\n"\
		"\tdaes -prep -nplayers 2 -nsboxsrmc 9 -nsboxsr 1 -ndecomp 0 -nsingles 1\n"
		"- Compute AES: on port 2020 with two processes on localhost:\n"\
		"\tdaes -mpc -prepfile aes_prep_4_player_0.rep -port 2020\n"\
		"\tdaes -mpc -prepfile aes_prep_4_player_1.rep -port 2020 -ip 127.0.0.1\n"\
		"\n\nQuestions can be sent to rwl@cs.au.dk\n"
		);

}

static
int check_arguments(OE oe, Map args, CfpParams * params) {


  if (args->contains("compile")) {
	  // check for input file
    if (!args->contains("in")) {
      oe->print("parameter in missing.\n");
      return 0;
    }

    if (!args->contains("offset")) {
    	params->p.compile.offset = 0;
    } else {
      params->p.compile.offset = atoi(args->get("offset"));
    }
    params->p.compile.filename = args->get("in");
    params->op = DO_COMPILE;
    return 1;
  }

	if (args->contains("prep")) {

		if (args->contains("mpc")) {
		  oe->print("Ambigious aguments "\
			    "both mpc and prep argument given.\n");
		  return 0;
		}

		params->op = DO_PREP;

		params->p.prep.lintranses = SingleLinkedList_new(oe);
		if (!args->contains("nlt")) {
		  oe->print("parameter nlt missing, no linear transformations will be generated.\n");
		} else {
		  uint count = atoi(args->get("nlt")) , x=0;
		  LinTransParam param = 0;

		  for ( x = 0; x < count;++x) {
		    param = oe->getmem(sizeof(*param));
		    if (!param) {
		      ERR(oe,"No memory");
		      return 0;
		    }
		    params->p.prep.lintranses->add_element(param);
		    if (!args->contains("ltkind")) {
		      param->kind = 0;
		    } else {
		      param->kind = atoi(args->get("ltkind"));
		    }
		    
		    switch(param->kind) {
		    case AES_SRMC:
		      param->M = load_matrix(oe,(byte*)srmc,16,16);
		      break;
		    case AES_SR:
		      param->M = load_matrix(oe,(byte*)sr,16,16);
		      break;
		    default:
		      oe->print("%u is unrecognized, defaulting to SRMC transformation 0.",param->kind);
		      param->M = load_matrix(oe,(byte*)srmc,16,16);
		    }
		  }
		  // MATRIX * 		  
		}
		
		if (!args->contains("nkeyboxes")) {
		  oe->print("parameter nkeyboxes missing, defaulting to 12.\n");
		  params->p.prep.nkeyboxes = 12;
		} else {
		  atoui(args->get("nkeyboxes"),&params->p.prep.nkeyboxes);
		}
		
		if (!args->contains("nsingle")) {
		  oe->print("parameter nsingle missing, defaulting to 64.\n");
		  params->p.prep.nsingle = 64;
		} else {
		  atoui(args->get("nsingle"), &params->p.prep.nsingle);
		}

		if (!args->contains("nsboxsrmc")) {
		  oe->print("parameter nsboxsrmc missing, defaulting to 10.\n");
		  params->p.prep.nsboxsrmc = 10;
		} else {
		  atoui(args->get("nsboxsrmc"), &params->p.prep.nsboxsrmc);
		}

		if (!args->contains("nsboxsr")) {
		  oe->print("parameter sboxsr is missing, defaulting to 2.\n");
		  params->p.prep.nsboxsr = 2;
		} else {
		  atoui(args->get("nsboxsr"), &params->p.prep.nsboxsr);
		}

		if (!args->contains("ndecomp")) {
		  oe->print("parameter ndecomp is missing.\n");
		} else {
		  atoui(args->get("ndecomp"), &params->p.prep.ndecomp);
		}
		
		if (!args->contains("-out")) {
		  oe->print("parameter out missing using default filenames.\n");
		  params->p.prep.fprefix = "aes_prep_4_player_";
		} else {
		  params->p.prep.fprefix = args->get("out");
		}

		if (!args->contains("nplayers")) {
		  oe->print("parameter nplayers is missing, defaulting to 2.\n");
		  params->p.prep.nplayers = 2;
		} else {
		  atoui(args->get("nplayers"), &params->p.prep.nplayers);
		}

		return 1;
	}

	if (args->contains("mpc")) {

		params->op = DO_AES_MPC;

		if (args->contains("prep")) {
		  oe->print("parameters contains both mpc and prep which is ambigious, aborting computation.");
		  return 0;
		}

		if (!args->contains("forks")) {
		  params->p.mpc.forks = 0;
		} else {
		  params->p.mpc.forks = atoi(args->get("forks"));
		}

		if (!args->contains("prepfile")) {
			oe->print("parameter prepfile missing, aborting.\n");
			return 0;
		}

		if (args->contains("ip")) {
			params->p.mpc.ip = (char*)args->get("ip");
		}
		else { 
		  oe->p("ip address parameters is missing, defaulting to localhost.\n");
		  params->p.mpc.ip = "127.0.0.1"; 
		}

		if (!args->contains("blocks")) {
		  params->p.mpc.blocks = 1;
		} else {
		  params->p.mpc.blocks = atoi(args->get("blocks"));
		}

		if (!args->contains("ks")) {
		  oe->p("Key schedule is omitted as the -ks parameters is not present.");
		  params->p.mpc.ks = 0;
		} else {
		  oe->p("Key schedule is present and will be carried out.");
		  params->p.mpc.ks = 1;
		}

		if (!args->contains("port")) {
		  oe->p("parameter port is missing, defaulting to 2020.\n");
		  params->p.mpc.port = 2020;
		} else {
		  atoui((byte*)args->get("port"), &params->p.mpc.port);		  
		}
		
		params->p.mpc.prep_file = (char*)args->get("prepfile");

		return 1;
	}

	
	print_help(oe);
	if (!args->contains("help")) {
	  oe->p("No valid operation selected. Do -prep for preprocessing"
		" or -mpc for multiparty computation.");
	}

	return 0;
}

static int perform_mpc(OE oe, Map options, CfpParams params) {
  DateTime dt = DateTime_New(oe);
	AesPreprocessing prep = 
	  AesPreprocessing_Cached_New(oe, 
				      params.p.mpc.prep_file, 
				      20, 0, 64, 1, 1, 4);
	MiniMacsEnc menc = 0, smenc = 0;
	Map heap = 0;
	DAesMiniMac mm = 0;
	CArena arena = CArena_new(oe);
	uint mycount = 0;

	if (!prep) {
		oe->print("[%s:%u] Loading preprocessing material fail.\n",__FUNCTION__,__LINE__);
		goto fail;
	}

	init_polynomial();
	init_matrix();

	oe->print("Running MPC loaded preprocessing:\n\t%s\n", prep->get_purpose());

	menc = MiniMacsEnc_FFTNew(oe);
	if (menc == 0) goto fail;

	smenc = MiniMacsEnc_MatrixNew(oe, 44, 14);
	if (smenc == 0) goto fail;

	heap = HashMap_IntKey_New(oe,64);
	if (!heap) goto fail;

	if (params.p.mpc.forks > 0) {
	  int i = 0;
	  List pids = SingleLinkedList_new(oe);
	  ull start = 0;
	  for ( i = 0; i < params.p.mpc.forks;++i) {
	    int pid = 0;
	    mycount = i;
	    pid = fork();
	    if (pid) break;
	    if (i == 0) start = dt->getMilliTime();
	    pids->add_element((void*)(ull)pid);
	  }
	  
	  if (pids->size() >= params.p.mpc.forks) {

	    
	    for(i = 0; i < pids->size();++i) {
	      int pid = (int)(ull)pids->get_element(i);
	      waitpid(pid,0,0);
	    }

	    oe->print("\n\n");
	    oe->usleep(10000);
	    oe->print("Completed %u AES in parallel in %lu ms",params.p.mpc.forks,
		      dt->getMilliTime()-start);
	  SingleLinkedList_destroy(&pids);
	  DateTime_Destroy(&dt);

	    return 0;
	  }
	  SingleLinkedList_destroy(&pids);
	}

	if (prep->get_playerid() == 0) {
	  CAR r = {0};
	  uint port = params.p.mpc.port + mycount;
	  oe->print("Waiting for player to connect on port %u... ",port);
	  r = arena->listen_wait(1, port);
	  if (r.rc != OK) {
	    oe->print("Unable to listen for incoming connections: %s\n",r.msg);
	    goto fail;
	  }
	}
	else {
	  uint port = params.p.mpc.port + mycount;
	  arena->connect(params.p.mpc.ip, port);
	}

	mm = DAesMiniMac_New(oe, menc, smenc, heap, prep,arena);
	if (!mm) goto fail;

	{
	  int r = 0;
	  byte keyshare[DATA_BYTES] = { 0 };
	  byte txt[DATA_BYTES] = { 0 };
	  byte ciphertext[16] = { 0 };
	  MiniMacsRep result = 0;
	  uint blk = 0;
	  ull duration = 0, start =0;

	  for(blk = 0; blk < params.p.mpc.blocks;++blk) {
	    oe->p("Multiparty AES computing block %u/%u\n",blk,params.p.mpc.blocks);
	    start = dt->getMilliTime();
	    r = mpc_aes(oe,mm, keyshare, txt, 
			(byte **)&ciphertext, params.p.mpc.ks);
	    duration += (dt->getMilliTime()-start);
	  if (r < 0) {
	    oe->print("AES computation failed, consult the log file.\n");
	    goto fail;
	  } 

	  result = heap->get((void*)0);
	  if (!result) {
	    oe->print("No result in heap");
	    goto fail;
	  }

	  for(r = 0;r < DATA_BYTES;++r) {
	    if (r > 0 && r % 16 ==0) oe->print("\n");
	    oe->print("%02x ",result->codeword[r]);
	  }
	  oe->print("\n");

	  }
	  oe->print("\n\nAll %u blocks took %lums %lu",params.p.mpc.blocks,duration,duration/params.p.mpc.blocks);
	}
	DateTime_Destroy(&dt);
	return 0;
fail:
	DateTime_Destroy(&dt);
	return -1;
}

static RC minimacs_rep_write(DerCtx * c, MiniMacsRep rep) {
	RC rc = RC_OK;
	uint i = 0;

	if (!c) return RC_BAD_ARGS;

	if (!rep) return RC_BAD_ARGS;

	rc = der_begin_seq(&c);
	if (rc != RC_OK) goto fail;

	rc = der_insert_uint(c, rep->lval);
	if (rc != RC_OK) goto fail;
	rc = der_insert_octetstring(c, rep->dx_codeword, rep->ldx_codeword); 
	if (rc != RC_OK) goto fail;
	rc = der_insert_octetstring(c, rep->codeword, rep->lcodeword);
	if (rc != RC_OK) goto fail;

	// macs
	rc = der_begin_seq(&c);
	if (rc != RC_OK) goto fail;
	rc = der_insert_uint(c, rep->lmac);
	if (rc != RC_OK) goto fail;
	for (i = 0; i < rep->lmac; ++i) {
		if (rep->mac[i] == 0) continue;
		rc = der_begin_seq(&c);
		if (rc != RC_OK) goto fail;
		rc = der_insert_uint(c, rep->mac[i]->mid); 
		if (rc != RC_OK) goto fail;
		rc = der_insert_uint(c, rep->mac[i]->toid);
		if (rc != RC_OK) goto fail;
		rc = der_insert_uint(c, rep->mac[i]->fromid);
		if (rc != RC_OK) goto fail;
		rc = der_insert_octetstring(c, rep->mac[i]->mac, rep->mac[i]->lmac);
		if (rc != RC_OK) goto fail;
		rc = der_end_seq(&c);
		if (rc != RC_OK) goto fail;
	}
	rc = der_end_seq(&c);
	if (rc != RC_OK) goto fail;

	rc = der_begin_seq(&c);
	if (rc != RC_OK) goto fail;
	rc = der_insert_uint(c, rep->lmac_keys_to_others);
	if (rc != RC_OK) goto fail;
	for (i = 0; i < rep->lmac_keys_to_others; ++i) {
		rc = der_begin_seq(&c);
		if (rc != RC_OK) goto fail;
		rc = der_insert_uint(c, rep->mac_keys_to_others[i]->mid);
		if (rc != RC_OK) goto fail;
		rc = der_insert_uint(c, rep->mac_keys_to_others[i]->toid);
		if (rc != RC_OK) goto fail;
		rc = der_insert_uint(c, rep->mac_keys_to_others[i]->fromid);
		if (rc != RC_OK) goto fail;
		rc = der_insert_octetstring(c, rep->mac_keys_to_others[i]->alpha, rep->mac_keys_to_others[i]->lalpha);
		if (rc != RC_OK) goto fail;
		rc = der_insert_octetstring(c, rep->mac_keys_to_others[i]->beta, rep->mac_keys_to_others[i]->lbeta);
		if (rc != RC_OK) goto fail;
		rc = der_end_seq(&c);
		if (rc != RC_OK) goto fail;
	}
	rc = der_end_seq(&c);
	if (rc != RC_OK) goto fail;

	/* { */
	/*   uint box_len = 0; */
	/*   der_final(&c, 0, &box_len); */
	/*   printf("\nRep size %lu, lmacs=%u, lmkto=%u\n",box_len,rep->lmac,rep->lmac_keys_to_others); */
	/* } */

	rc = der_end_seq(&c);
	if (rc != RC_OK) goto fail;

	return rc;
fail:
	return rc;
}

static RC matrix_write(DerCtx * c, MATRIX * m) {
  RC rc = RC_OK;
  byte * mem = matrix_to_flatmem(m);
  uint h = matrix_getheight(m);
  uint w = matrix_getwidth(m);
  uint lmem = h*w;
  DerRC drc = DER_OK;

  drc = der_begin_seq(&c);
  if (drc != DER_OK) return RC_FAIL;
  
  drc = der_insert_uint(c,h);
  if (drc != DER_OK) return RC_FAIL;
  
  drc = der_insert_uint(c,w); 
  if (drc != DER_OK) return RC_FAIL;

  drc = der_insert_octetstring(c,mem,lmem);
  if (drc != DER_OK) return RC_FAIL;
  
  drc = der_end_seq(&c);
  if (drc != DER_OK) return RC_FAIL;

  return rc;
}

static int perform_prep(OE oe, Map options, CfpParams params) {
	Rnd rnd = LibcWeakRandomSource_New(oe);
	MiniMacsEnc enc = 0, smenc = 0;
	Cfp cfp = 0;
	MiniMacsRep single = 0;
	uint i = 0, player = 0;
	DerCtx * c = { 0 };
	const uint version = 20150630;
	init_polynomial();
	init_matrix();

	// DATA_BYTES Force to 85
	enc = MiniMacsEnc_FFTNew(oe);
	if (enc == 0) goto fail;

	smenc = MiniMacsEnc_MatrixNew(oe, 44, 14);
	if (smenc == 0) goto fail;

	cfp = Cfp_SimpleNew(oe, enc, smenc, rnd,params.p.prep.nplayers);
	if (cfp == 0) return 0;

	oe->print("Generating material for %d players.\n", params.p.prep.nplayers);
	for (player = 0; player < params.p.prep.nplayers; ++player) {
		oe->print("\n-----\nMaterial for player %d\n-----\n",player);
		der_begin(&c);
		// INFO
		der_begin_seq(&c);
		der_begin_seq(&c);
		der_insert_uint(c, player);
		der_insert_uint(c, params.p.prep.nplayers);
		der_insert_uint(c, version);
		der_insert_cstr(c, 
				"\nCheetah preprocessing for fast AES. We have " \
				"Singles, SBoxSRMC and SBoxSR preprocessing for "\
				"single opening AES rounds.");
		der_insert_uint(c, DATA_BYTES);
		der_insert_uint(c, 255);
		der_end_seq(&c);

		der_begin_seq(&c);
		der_insert_uint(c, params.p.prep.ndecomp);
		oe->print("Bit decomposed singles: [   0/%4d]", params.p.prep.ndecomp);
		for (i = 0; i < params.p.prep.ndecomp; ++i) {
			oe->print("\b\b\b\b\b\b\b\b\b\b");
			oe->print("%4d/%4d]", i+1,params.p.prep.ndecomp);
			{
				CheetahDVal dval = (CheetahDVal)cfp->get_decomposed(player);
				uint k = 0;
				der_begin_seq(&c);
				minimacs_rep_write(c, dval->R);
				for (k = 0; k < 8; ++k) {
					minimacs_rep_write(c, dval->Ri[k]);
				}
				der_end_seq(&c);
				CheetahDVal_Destroy(oe, &dval);
			}
		}
		der_end_seq(&c);

		oe->print("\nSBoxes with ShiftRows and MixColumns: [    0/%5d]", params.p.prep.nsboxsrmc);
		der_begin_seq(&c);
		der_insert_uint(c, params.p.prep.nsboxsrmc);
		for (i = 0; i < params.p.prep.nsboxsrmc; ++i) {
			oe->print("\b\b\b\b\b\b\b\b\b\b\b\b");
			oe->print("%5d/%5d]", i + 1, params.p.prep.nsboxsrmc);
			{
				CheetahSBox srmc = cfp->get_sbox_srmc(player);
				uint k = 0, l = 0;
				der_begin_seq(&c);
				minimacs_rep_write(c, srmc->R);
				oe->print(" [%5d/%5d]", 0, DATA_BYTES * 256);
				for (l = 0; l < DATA_BYTES; ++l) {
				  oe->print("\b\b\b\b\b\b\b\b\b\b\b\b");
				  oe->print("%5d/%5d]", l*256+k+1, DATA_BYTES * 256);
				  for (k = 0; k < 256; ++k) {
				    minimacs_rep_write(c, srmc->table[l][k]);
				  }

				}
				oe->print("\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
				der_end_seq(&c);
 				CheetahSBox_Destroy(oe, &srmc);
			}
		}
		der_end_seq(&c);

		oe->print("\nSBoxes with ShiftRows: [    0/%5d]",params.p.prep.nsboxsr);
		der_begin_seq(&c);
		der_insert_uint(c, params.p.prep.nsboxsr);
		for (i = 0; i < params.p.prep.nsboxsr; ++i) {
			oe->print("\b\b\b\b\b\b\b\b\b\b\b\b");
			oe->print("%5d/%5d]", i + 1, params.p.prep.nsboxsr);
			{
				CheetahSBox sr = cfp->get_sbox_sr(player);
				uint k = 0, l = 0;
				der_begin_seq(&c);
				minimacs_rep_write(c, sr->R);
				oe->print(" [%5d/%5d]", 0, DATA_BYTES * 256);
				for (l = 0; l < DATA_BYTES; ++l) {
					for (k = 0; k < 256; ++k) {
						oe->print("\b\b\b\b\b\b\b\b\b\b\b\b");
						oe->print("%5d/%5d]", l * 256 + k + 1, DATA_BYTES * 256);
						minimacs_rep_write(c, sr->table[l][k]);
					}
				}
				oe->print("\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
				{
				  uint box_len = 0;
				  der_final(&c, 0, &box_len);
				  oe->print("Box size %lu\n",box_len);
				}

				der_end_seq(&c);
				CheetahSBox_Destroy(oe,&sr);
			}
		}
		der_end_seq(&c);


		oe->print("\nLinear Transformations: [   0/%03u]",params.p.prep.lintranses->size());
		der_begin_seq(&c);
		der_insert_uint(c, params.p.prep.lintranses->size());
		{
		  uint lintrans = 0;
		  for(lintrans = 0; lintrans < params.p.prep.lintranses->size();++lintrans) {
		    LinTransParam param = params.p.prep.lintranses->get_element(0);
		    CheetahLVal lval = 0;
		    uint k = 0, l = 0;

		    oe->print("\b\b\b\b\b\b\b\b");
		    oe->print("%03u/%03u]",lintrans,params.p.prep.lintranses->size());
		    if (!param) {
		      ERR(oe, "Software inconsistency error, param is not set :-(");
		      return RC_FAIL;
		    }

		    lval = cfp->get_lintrans(player,param->M);
		    if (!lval) {
		      ERR(oe,"Somehow linear transformation generation failed."\
			  " For player %u.",player);
		      return RC_FAIL;
		    }
		    
		    der_begin_seq(&c);
		    der_insert_uint(c,param->kind);
		    minimacs_rep_write(c, lval->R);
		    minimacs_rep_write(c, lval->MxR);
		    matrix_write(c,lval->M);
		    CheetahLVal_Destroy(oe, &lval);
		    der_end_seq(&c);
		  }
		}
		der_end_seq(&c);

		oe->print("\nKey Boxes: [  0/%3d]",params.p.prep.nkeyboxes);
		der_begin_seq(&c);
		der_insert_uint(c,params.p.prep.nkeyboxes);
		for(i = 0; i < params.p.prep.nkeyboxes;++i) {
		  oe->print("\b\b\b\b\b\b\b\b");
		  oe->print("%3d/%3d]", i + 1, params.p.prep.nkeyboxes);
		  der_begin_seq(&c);
		  {
		    uint k = 0, l = 0;
		    CheetahKBox kbx = cfp->get_key_box(player);
		    minimacs_rep_write(c,kbx->R); 
		    minimacs_rep_write(c,kbx->T);
		    minimacs_rep_write(c,kbx->KSxT);
		    oe->print(" [%5d/%5d]", 0, DATA_BYTES/16*4*256);
		    for(k=0;k < DATA_BYTES/16*4;++k) {
		      for( l = 0; l < 256;++l) {
			oe->print("\b\b\b\b\b\b\b\b\b\b\b\b");
			oe->print("%5d/%5d]", k * 256 + l + 1, DATA_BYTES/16*4* 256);
			minimacs_rep_write(c, kbx->table[k][l]);
		      }
		    }
		    oe->print("\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
		  }
		  der_end_seq(&c);
		}
		der_end_seq(&c);


		oe->print("\nSingles: [  0/%3d]",params.p.prep.nsingle);
		der_begin_seq(&c);
		der_insert_uint(c, params.p.prep.nsingle);
		for (i = 0; i < params.p.prep.nsingle; ++i) {
			oe->print("\b\b\b\b\b\b\b\b");
			oe->print("%3d/%3d]", i + 1, params.p.prep.nsingle);
			{
				MiniMacsRep s = cfp->get_single(player);
				minimacs_rep_write(c, s);
				minimacs_rep_clean_up(oe, &s);
			}
		}
		der_end_seq(&c);
		der_end_seq(&c);

		oe->print("\nWritting material to file");
		{
			uint ldata = 0;
			byte * data;
			FD file = 0;
			RC rc = 0;
			char filename[512] = { 0 };
			der_final(&c, 0, &ldata);
			oe->print("\nWritting %lu bytes (%lu Mb) of material to file\n",ldata,ldata / (1024*1024));
			data = oe->getmem(ldata);
			der_final(&c, data, &ldata);
			osal_sprintf(filename, "file %s%d.rep",params.p.prep.fprefix, player);
			rc = oe->open(filename, &file);
			oe->write(file, data, &ldata);
			oe->close(file);
			oe->putmem(data);
		}
	}


	return 0;
fail: 
	return -2;
}


RC compile_circuit(OE oe, const char * filename,uint offset);

static int runner(OE oe, Map args, CfpParams params) {
  int r = 0;
  switch (params.op) {
  case DO_AES_MPC:
    oe->p("Performing mpc");
    r = perform_mpc(oe, args, params);
    goto end;
  case DO_PREP:
    oe->p("Performing preprocessing");
    r = perform_prep(oe, args, params);
    goto end;
  case DO_COMPILE: {
    oe->p("Performing circuit compiler");
    compile_circuit(oe, params.p.compile.filename,params.p.compile.offset);
    goto end;
  }
  default:
    goto end;
  }
 end:
  return r;
}

int main(int c, char **a) {
  OE oe = OperatingEnvironment_New();
  Map args = Options_New(oe, c, a);
  Rnd rnd = LibcWeakRandomSource_New(oe);
  MiniMacsEnc enc = 0, smenc = 0;
  Cfp cfp = Cfp_SimpleNew(oe, enc,smenc, rnd, 2);
  CfpParams params = { 0 };
  uint instances = 0;
  int r = 0;
  oe->set_log_file("cheetah.log");

  oe->p("Cheetah starting");
	
  oe->print("Aarhus Crypto - Multiparty Computation - Arithmetic Black Box\n");
  oe->print("Online MiniTrix - Dedicated to AES. Written by Rasmus Zakarias.\n");
  oe->print("This software is licensed under the MIT license, see main.c.\n");

  if (!check_arguments(oe, args, &params)) {
    r = -1;
    goto end;
  }

  r = runner(oe,args,params);

 end:
  Cfp_SimpleDestroy(&cfp);
  OperatingEnvironment_Destroy(&oe);
  return r;
}

