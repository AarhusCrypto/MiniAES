#include <cheetah_pre.h>
#include <osal.h>
#include <singlelinkedlist.h>
#include <coov4.h>
#include <reedsolomon/reedsolomon.h>
#include <datetime.h>
#include <math/matrix.h>

byte mc[16][16] = {
  {2, 3, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
  {1, 2, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
  {1, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
  {3, 1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
  {0, 0, 0, 0, 2, 3, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0},
  {0, 0, 0, 0, 1, 2, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0},
  {0, 0, 0, 0, 1, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0},
  {0, 0, 0, 0, 3, 1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0},
  {0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 1, 1, 0, 0, 0, 0}, 
  {0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 1, 0, 0, 0, 0},
  {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 3, 0, 0, 0, 0},
  {0, 0, 0, 0, 0, 0, 0, 0, 3, 1, 1, 2, 0, 0, 0, 0},
  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 1, 1}, 
  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 1}, 
  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 3}, 
  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 1, 1, 2} 
};

byte sr[16][16] = {
  {1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0}, 
  {0, 0, 0, 0,  0, 1, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0}, 
  {0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 1, 0,  0, 0, 0, 0}, 
  {0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 1},
  //
  {0, 0, 0, 0,  1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0}, 
  {0, 0, 0, 0,  0, 0, 0, 0,  0, 1, 0, 0,  0, 0, 0, 0}, 
  {0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 1, 0}, 
  {0, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0},
  //
  {0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 0,  0, 0, 0, 0}, 
  {0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 1, 0, 0}, 
  {0, 0, 1, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0}, 
  {0, 0, 0, 0,  0, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0},
  //
  {0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 0}, 
  {0, 1, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0}, 
  {0, 0, 0, 0,  0, 0, 1, 0,  0, 0, 0, 0,  0, 0, 0, 0}, 
  {0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 1,  0, 0, 0, 0},
};

static byte sbox[256] = { 
0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

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

typedef struct _cheetah_preprocessing_implementation_ {

  // number of players
  uint nplayers;
  
  // random source
  Rnd rndsrc;
  
  // The first single, a value that all other MiniMacsReps will be
  // consistent with. E.g. in the BeDoZa mac key auth. player B's share to A 
  // the Aplha-key part must be the same. We use compat[i]'s alpha key parts
  // for all representations prepared to player i.
  MiniMacsRep * compat;
  MiniMacsRep * smallcompat;
  
  // we need oe to mem and stuff
  OE oe;

  // the current single
  List singles; // List<MiniMacsRep *>
  
  // Current SBox 
  List Rs; // List<MiniMacsRep *>
  
  List tables; // List<MiniMacsRep *[112][256]>
  
  // Current Bit Decomposition state
  List decompR; // List<MiniMacsRep * decompR>;
  List decompTable; // 	List<MiniMacsRep *[8]>
  
  
  // List <CheetahSBox> but the table is less
  List key_boxes;
  
  // The linear transformation
  List cheetahLVals;
  
  // MiniMac encoders
  MiniMacsEnc menc;
  MiniMacsEnc smenc;

} * CfpImpl;


void Cfp_SimpleDestroy(Cfp * cfp) { 
	Cfp c = 0;
	CfpImpl ci = 0;
	OE oe = 0;

	if (!cfp) return;

	if (!*cfp) return;

	c = *cfp;
	ci = (CfpImpl)c->impl;

	if (!ci) return;
	oe = ci->oe;

	SingleLinkedList_destroy(&ci->singles);
	SingleLinkedList_destroy(&ci->Rs);
	SingleLinkedList_destroy(&ci->tables);
	SingleLinkedList_destroy(&ci->decompR);
	SingleLinkedList_destroy(&ci->decompTable);

	COO_detach(c->get_decomposed);
	COO_detach(c->get_sbox_sr);
	COO_detach(c->get_sbox_srmc);
	COO_detach(c->get_single);
	COO_detach(c->get_lintrans);

	oe->putmem(ci);
	oe->putmem(c);

	*cfp = 0;
}

COO_DEF(Cfp, CheetahDVal, get_decomposed,  uint playerid) {
	CfpImpl impl = (CfpImpl)this->impl;
	OE oe = impl->oe;
	byte R[DATA_BYTES] = { 0 };
	uint i = 0;
        MiniMacsRep * decompR = 0;
        MiniMacsRep **decompTable = oe->getmem(8*sizeof(*decompTable));

	if (impl->compat == 0 || impl->smallcompat == 0) return 0;

	CheetahDVal res = (CheetahDVal)oe->getmem(sizeof(*res));
	if (!res) return 0;

	if (playerid == 0) {
		impl->rndsrc->rand(R, sizeof(R));
		decompR = minimacs_create_rep_from_plaintext_f(oe, impl->menc, R, DATA_BYTES, impl->nplayers, 255, impl->compat);
		if (decompR == 0) goto fail;
		for (i = 0; i < 8; ++i) {
			byte R_i[14] = { 0 };
			uint j = 0;
			for (j = 0; j < DATA_BYTES; ++j) {
				uint byteidx = j;
				uint bitindx = i;
				byte Rv = ((R[byteidx] & (0x01 << bitindx)) >> bitindx); // read bit {i} from byte {j}
				byteidx = j >> 8;
				bitindx = j - (byteidx << 3);
				R_i[byteidx] |= (Rv << bitindx); // write the {Rv} as the {j}th bit
			}
			decompTable[i] =
			  minimacs_create_rep_from_plaintext_f(oe, impl->smenc, R_i, 14, impl->nplayers, 44, impl->smallcompat);
			if (decompTable[i] == 0) {
				goto fail;
			}
		}
		
		impl->decompR->add_element(decompR);
		impl->decompTable->add_element(decompTable);
	} else {
	  decompR = impl->decompR->get_element(0);
	  decompTable = impl->decompTable->get_element(0);
	}
	  

	if (decompR && decompTable && playerid < impl->nplayers) {
		res->R = decompR[playerid]; decompR[playerid] = 0;
		for (i = 0; i < 8; ++i) {
			res->Ri[i] = decompTable[i][playerid];
			decompTable[i][playerid] = 0;
		}

		if (playerid == impl->nplayers-1) {
		  impl->decompR->rem_element(0);
		  impl->decompTable->rem_element(0);
		}
	} else {
	  goto fail;
	}

	return res;
fail:
{
  if (decompR) {
	for (i = 0; i < impl->nplayers; ++i) {
		MiniMacsRep rep = decompR[i];
		minimacs_rep_clean_up(oe, &rep);
	}
  }
}

 if (decompTable) {
		int j = 0;
		for (j = 0; j < 8; ++j) {
			if (decompTable[j] == 0) continue;
			for (i = 0; i < impl->nplayers; ++i) {
			  MiniMacsRep rep = decompTable[j][i];
				minimacs_rep_clean_up(oe, &rep);
			}
		}
		oe->putmem(impl->decompR);

	}
	return 0;
}}

#define SWAP(A,B) A=(A)^(B);B=(A)^(B);A=(A)^(B);
#define ROT(D) {\
    SWAP((D)[12],(D)[13]);			\
    SWAP((D)[13],(D)[14]);			\
    SWAP((D)[14],(D)[15]);			\
  }


byte KS[16][16] = {
  {1,0,0,0, 0,0,0,0, 0,0,0,0, 1,0,0,0},
  {0,1,0,0, 0,0,0,0, 0,0,0,0, 0,1,0,0},
  {0,0,1,0, 0,0,0,0, 0,0,0,0, 0,0,1,0},
  {0,0,0,1, 0,0,0,0, 0,0,0,0, 0,0,0,1},
  //
  {1,0,0,0, 1,0,0,0, 0,0,0,0, 1,0,0,0},
  {0,1,0,0, 0,1,0,0, 0,0,0,0, 0,1,0,0},
  {0,0,1,0, 0,0,1,0, 0,0,0,0, 0,0,1,0},
  {0,0,0,1, 0,0,0,1, 0,0,0,0, 0,0,0,1},
  //
  {1,0,0,0, 1,0,0,0, 1,0,0,0, 1,0,0,0},
  {0,1,0,0, 0,1,0,0, 0,1,0,0, 0,1,0,0},
  {0,0,1,0, 0,0,1,0, 0,0,1,0, 0,0,1,0},
  {0,0,0,1, 0,0,0,1, 0,0,0,1, 0,0,0,1},
  //
  {1,0,0,0, 1,0,0,0, 1,0,0,0, 0,0,0,0},
  {0,1,0,0, 0,1,0,0, 0,1,0,0, 0,0,0,0},
  {0,0,1,0, 0,0,1,0, 0,0,1,0, 0,0,0,0},
  {0,0,0,1, 0,0,0,1, 0,0,0,1, 0,0,0,0},
};

static CheetahKBox compute_key_box(CfpImpl cfpi, OE oe, uint playerid) {
  CheetahKBox * boxes = 0;
  byte R[DATA_BYTES] = { 0 }, T[DATA_BYTES] = {0};
  MiniMacsRep * Rs = 0, * Ts = 0;
  MiniMacsRep * TKses = 0;
  MiniMacsRep *** table = 0;
  uint i=0,j=0,block=0,player=0,z=0 ;
  int s = 0;
  MATRIX * MKS = 0;

  if (playerid==0) {
    byte ROTR[DATA_BYTES] = {0};
    byte TKs[DATA_BYTES] = {0};
    
    MKS = load_matrix(oe,(byte*)KS,16,16);
    
    cfpi->rndsrc->rand(R, DATA_BYTES);
    cfpi->rndsrc->rand(T, DATA_BYTES);

    Rs = minimacs_create_rep_from_plaintext_f(oe, cfpi->menc, 
					      R, DATA_BYTES, cfpi->nplayers, 
					      255, cfpi->compat);

    Ts = minimacs_create_rep_from_plaintext_f(oe, cfpi->menc,
					    T, DATA_BYTES, cfpi->nplayers,
					    255, cfpi->compat);

    table = cfpi->oe->getmem(DATA_BYTES/16*4*sizeof(*table));

    mcpy(ROTR,R,DATA_BYTES);

    for(block=0;block<DATA_BYTES/16;++block) {
      ROT(ROTR+block*16);
    }

    for(block=0;block<DATA_BYTES/16;++block) {
      MATRIX * vec = 0;
      MATRIX * res = 0;
      uint j = 0;
      
      vec = load_matrix(oe,T+16*block,16,1);
      res = matrix_multiplication(MKS,vec);
      for(j = 0;j < 16;++j) {
	TKs[16*block+j] = matrix_getentry(res,j,0);
      }
      
      destroy_matrix(vec);
      destroy_matrix(res);
    }
    destroy_matrix(MKS);

    TKses = minimacs_create_rep_from_plaintext_f(oe,
						 cfpi->menc,
						 TKs,DATA_BYTES,
						 cfpi->nplayers,
						 255,cfpi->compat);
    
    
    for(block = 0; block < DATA_BYTES/16;++block) {
      for ( i = 0; i < 4;++i) {
	table[4*block+i] = oe->getmem(256*sizeof(**table));
	for(s = 0;s < 256;++s) {
	  byte v[DATA_BYTES] = {0};

	  if (i == 0) {
	    for(z=0;z < 12;++z) {
	      v[16*block+z] = ROTR[16*block+z];
	    }
	  }
	  

	  v[16*block+12+i] = sbox[s]^ROTR[16*block+12+i]^s;

	  table[4*block+i][s^ROTR[16*block+12+i]] = 
	    minimacs_create_rep_from_plaintext_f(oe,
						 cfpi->menc,
						 v,DATA_BYTES,
						 cfpi->nplayers,
						 255,cfpi->compat);
	} // for s = 0 < 256
      }// for i = 0 < 4
    } // for block = 0 < DATA_BYTES/16    

    boxes = oe->getmem(cfpi->nplayers*sizeof(*boxes));
    for(player = 0;player < cfpi->nplayers;++player) {
      CheetahKBox box = 0;
      box = oe->getmem(sizeof(*box));
      box->R = Rs[player];
      box->T = Ts[player];
      box->KSxT = TKses[player];
      for(block = 0;block < DATA_BYTES/16;++block) {
	for(i = 0; i < 4;++i) {
	  for( s = 0; s < 256;++s) {
	    box->table[4*block+i][s] = table[4*block+i][s][player];
	  }// s = 0 < 256
	}// i = 0 < 4
      } // block = 0 < DATA_BYTES/16
      boxes[player] = box;
    } //i = 0 < nplayers

    cfpi->key_boxes->add_element(boxes);
    for(block=0;block<DATA_BYTES/16;++block) {
      for(i = 0;i < 4;++i) {
	oe->putmem(table[4*block+i]);
      }
    }
    oe->putmem(table);
  } // if playerid == 0
  else {
    boxes = cfpi->key_boxes->get_element(0);
  }

  if (boxes && playerid < cfpi->nplayers) {
    CheetahKBox result = 0;
    result = boxes[playerid];
    boxes[playerid] = 0; // disown
    if (playerid == cfpi->nplayers-1) {
      cfpi->key_boxes->rem_element(0);
      oe->putmem(boxes);
    }
    return result;
  }

  return 0;
}

static CheetahSBox compute_box(CfpImpl cfpi, OE oe, MATRIX * lintrans, uint playerid) {
	CheetahSBox box = 0;
	byte R[DATA_BYTES] = { 0 };
	uint i = 0, j = 0, s = 0;
	DateTime dt = DateTime_New(oe);
	ull start = 0;
	MiniMacsRep ***table = 0;
	MiniMacsRep * Rs = 0;
	MATRIX * zeros = new_matrix(oe,16,1);
	MATRIX * m = 0;
	


	if (playerid == 0) {
		cfpi->rndsrc->rand(R, DATA_BYTES);
		Rs = minimacs_create_rep_from_plaintext_f(oe, cfpi->menc, R, DATA_BYTES, cfpi->nplayers, 255, cfpi->compat);

		cfpi->Rs->add_element(Rs);

		table = oe->getmem((DATA_BYTES)*sizeof(*table));
		for (i = 0; i < (DATA_BYTES/16)*16; ++i) {
		  table[i] = oe->getmem(256*sizeof(**table));
			for (s = 0; s < 256; ++s){
				MATRIX * vector = 0;
				MATRIX * r = 0;
				byte v[DATA_BYTES] = { 0 };
				byte * data = 0;
				uint idx = s;
				uint vidx = i%16;
				uint z=0;

				vector = new_matrix(oe, 16, 1);
				matrix_setentry(vector, vidx, 0, sbox[idx]);
				r = matrix_multiplication(lintrans, vector);
				data = matrix_to_flatmem(r);
				destroy_matrix(r);
				for (j = 0; j < 16; ++j) {
				  uint idx = (i/16)*16+j;
				  if (idx > DATA_BYTES) {
				    oe->print("Fatal: j=%u, i=%u idx=%u\n",i,j,idx);
				    exit(-1);
				  }
				    v[idx] = data[j];
				}

				table[i][s^R[i]] = 
				  minimacs_create_rep_from_plaintext_f(oe, 
								       cfpi->menc, 
								       v, DATA_BYTES, 
								       cfpi->nplayers, 
								       255, cfpi->compat);
				oe->putmem(data);
				destroy_matrix(vector);
			}
		}
		cfpi->tables->add_element(table);
	} else {
	  table = cfpi->tables->get_element(0);
	  Rs = cfpi->Rs->get_element(0);
	  if (playerid == cfpi->nplayers-1) {
	    cfpi->tables->rem_element(0);
	    cfpi->Rs->rem_element(0);
	  }
	}

	if (table != 0 && Rs != 0 && playerid < cfpi->nplayers) {
		box = cfpi->oe->getmem(sizeof(*box));
		if (!box) return 0;
		box->R = Rs[playerid];
		for (i = 0; i < (DATA_BYTES/16)*16; ++i) {
		  for (j = 0; j < 256; ++j) {
		    box->table[i][j] = table[i][j][playerid];
		  }
		}
		return box;
	}
	return 0;
}

COO_DEF(Cfp, CheetahSBox, get_sbox_srmc, uint playerid)
CfpImpl impl = (CfpImpl)this->impl;
OE oe = impl->oe;
MATRIX *SR = load_matrix(oe, (byte*)sr,16,16);
MATRIX *MC = load_matrix(oe, (byte*)mc,16,16);
MATRIX *srmc = matrix_multiplication(MC,SR);
return compute_box(impl, oe, srmc, playerid);
}

COO_DEF(Cfp, CheetahSBox, get_sbox_sr, uint playerid)
CfpImpl impl = (CfpImpl)this->impl;
OE oe = impl->oe;
MATRIX * SR = load_matrix(oe, (byte*)sr, 16, 16);
return compute_box(impl, oe, SR, playerid);
}


COO_DEF(Cfp, CheetahKBox, get_key_box, uint playerid) {
  CfpImpl impl = (CfpImpl)this->impl;
  OE oe = impl->oe;
  return compute_key_box(impl,oe,playerid);

}}


COO_DEF(Cfp, MiniMacsRep, get_singles, uint playerid) {
  CfpImpl impl = (CfpImpl)this->impl;
  uint i = 0;
  byte share[DATA_BYTES] = { 0 };
  MiniMacsRep * singles = 0;

  impl->rndsrc->rand(share, DATA_BYTES);
  
  if (playerid == 0) {
    singles = minimacs_create_rep_from_plaintext_f(impl->oe, impl->menc, share, DATA_BYTES, impl->nplayers, 255, impl->compat);
    impl->singles->add_element(singles);
  } else {
    singles = impl->singles->get_element(0);
  }
  
  if (singles && playerid < impl->nplayers) {
    MiniMacsRep result = 0;
    if (playerid == impl->nplayers-1) {
      impl->singles->rem_element(0);
    }
    result = singles[playerid];
    singles[playerid] = 0; // disown 
    return result;
  }

  return 0;
}}


COO_DEF(Cfp, CheetahLVal, get_lintrans, uint playerid, MATRIX * M) {
  CfpImpl impl = (CfpImpl)this->impl;
  OE oe = impl->oe;
  uint i = 0;
  byte rand[DATA_BYTES] = {0};
  byte * mxr_data = 0;
  MiniMacsRep * R = 0;
  MiniMacsRep * MxR = 0;
  MATRIX * mxr = 0, * vector = 0;
  uint mwidth = 0;
  CheetahLVal * reps = 0;
  uint iter = 0;

  if (!M) return 0;


  mwidth = matrix_getwidth(M);

  impl->rndsrc->rand(rand,DATA_BYTES);



  if (playerid == 0) {
    if (mwidth > DATA_BYTES) {
      ERR(oe, "Wrong dimension ! Transformation has width %u and data vector are of height %u.",mwidth,DATA_BYTES);
      return 0;
    }

    
    R = minimacs_create_rep_from_plaintext_f(impl->oe, impl->menc, rand, 
					     DATA_BYTES, impl->nplayers, 255, impl->compat);
    if (!R) {
      ERR(oe, "No more memory, sorry !");
      return 0;
    }

    mxr_data = oe->getmem(DATA_BYTES);
    if (!mxr_data) {
      ERR(oe, "Error this is not working out, no more memory good bye!");
      return 0;
    }

    for (iter = 0; iter < DATA_BYTES/mwidth;++iter) {
      byte * frag = 0;
      vector = new_matrix(oe,mwidth,1);
      for (i = 0; i < mwidth;++i) {
	matrix_setentry(vector,i,0,rand[i]);
      }
    
      mxr = matrix_multiplication(M,vector);
      destroy_matrix(vector);
      if (!mxr) {
	ERR(oe,"Matrix multiplication failed... ");
	return 0;
      }

      frag = matrix_to_flatmem(mxr);
      destroy_matrix(mxr);
      if (!mxr_data) {
	ERR(oe, "Matrix to flat mem conversion failed :(");
	return 0;
      }

      mcpy(mxr_data+mwidth*iter,frag,mwidth);
    }
    
    MxR = minimacs_create_rep_from_plaintext_f(impl->oe, impl->menc, mxr_data, 
					       DATA_BYTES, impl->nplayers, 255, impl->compat);
    oe->putmem(mxr_data);
    if (!MxR) {
      ERR(oe, "Failed to create representation for MxR.");
      return 0;
    }


    {
      reps = oe->getmem(sizeof(*reps)*impl->nplayers);
      for(i = 0; i < impl->nplayers;++i) {
	CheetahLVal val = oe->getmem(sizeof(*val));
	if (!val) {
	  ERR(oe,"No memory");
	  return 0;
	}
	val->R = R[i];
	val->MxR = MxR[i];
	val->M = M;
	reps[i] = val;
      }
      impl->cheetahLVals->add_element(reps);
    }

  } else {
    reps = impl->cheetahLVals->get_element(0);
    if (!reps) return 0;
  }
  

  if (reps && playerid < impl->nplayers) {
    CheetahLVal result = 0;
    if (playerid == impl->nplayers-1) {
      impl->singles->rem_element(0);
    }
    result = reps[playerid];
    reps[playerid] = 0; // disown 
    return result;
  }

  return 0;
}}


Cfp Cfp_SimpleNew(OE oe, MiniMacsEnc enc, MiniMacsEnc smenc, Rnd rnd, uint nplayers) {
	Cfp cfp = 0;  

	if (!oe) goto error;

	cfp = (Cfp)oe->getmem(sizeof(*cfp));
	if (!cfp) return 0;

	if (!rnd) goto error;

	if (nplayers < 2) goto error;

	if (rnd == 0) goto error;

	if (enc == 0) goto error;

	// guranteed: oe != 0, cfp != 0, rnd != 0 and nplayers >= 2

	CfpImpl cfpimpl = (CfpImpl)oe->getmem(sizeof(*cfpimpl));
	if (!cfpimpl) goto error;
	
	cfp->impl = cfpimpl;

	cfpimpl->nplayers = nplayers;
	cfpimpl->oe = oe;
	cfpimpl->rndsrc = rnd;
	cfpimpl->menc = enc;
	cfpimpl->smenc = smenc;

	cfpimpl->singles = SingleLinkedList_new(oe);
	cfpimpl->Rs = SingleLinkedList_new(oe);
	cfpimpl->tables = SingleLinkedList_new(oe);
	cfpimpl->decompR = SingleLinkedList_new(oe);
	cfpimpl->decompTable = SingleLinkedList_new(oe);
	cfpimpl->cheetahLVals = SingleLinkedList_new(oe);
	cfpimpl->key_boxes = SingleLinkedList_new(oe);

	cfp->get_decomposed = COO_attach(cfp, Cfp_get_decomposed);
	cfp->get_sbox_sr = COO_attach(cfp, Cfp_get_sbox_sr);
	cfp->get_sbox_srmc = COO_attach(cfp, Cfp_get_sbox_srmc);
	cfp->get_single = COO_attach(cfp, Cfp_get_singles);
	cfp->get_lintrans = COO_attach(cfp,Cfp_get_lintrans);
	cfp->get_key_box = COO_attach(cfp, Cfp_get_key_box);

	// makesure compat is set
	{
		byte share[DATA_BYTES] = { 0 };
		cfpimpl->rndsrc->rand(share, DATA_BYTES);
		cfpimpl->compat = 
		  minimacs_create_rep_from_plaintext_f(cfpimpl->oe, 
						       cfpimpl->menc, 
						       share, DATA_BYTES, 
						       cfpimpl->nplayers, 255, 
						       0);

		cfpimpl->smallcompat = minimacs_create_rep_from_plaintext_f(cfpimpl->oe, cfpimpl->smenc, share, 14, cfpimpl->nplayers, 44, 0);
	}

	return cfp;
error:
	Cfp_SimpleDestroy(&cfp);
	return 0;
}


void CheetahSBox_Destroy(OE oe, CheetahSBox * val) {
	CheetahSBox box = 0;
	uint i = 0;

	if (!val) return;

	box = *val;
	if (!box) return;

	for (i = 0; i < DATA_BYTES; ++i) {
		MiniMacsRep * r = box->table[i];
		uint j = 0;
		for (j = 0; j < 256; ++j) {
			MiniMacsRep rep = r[j];
			minimacs_rep_clean_up(oe, &rep);
		}
	}

	minimacs_rep_clean_up(oe, &box->R);
}

void CheetahLVal_Destroy(OE oe, CheetahLVal * val) {
	CheetahLVal v = 0;
	if (!val) return;

	v = *val;
	if (!v) return;

	minimacs_rep_clean_up(oe,&v->MxR);
	minimacs_rep_clean_up(oe,&v->R);

}

void CheetahDVal_Destroy(OE oe,CheetahDVal * val) {
	CheetahDVal v = 0;
	if (!val) return;

	v = *val;
	if (!v) return;

	minimacs_rep_clean_up(oe, &v->R);
	minimacs_rep_clean_up(oe, &v->Ri[0]);
	minimacs_rep_clean_up(oe, &v->Ri[1]);
	minimacs_rep_clean_up(oe, &v->Ri[2]);
	minimacs_rep_clean_up(oe, &v->Ri[3]);
	minimacs_rep_clean_up(oe, &v->Ri[4]);
	minimacs_rep_clean_up(oe, &v->Ri[5]);
	minimacs_rep_clean_up(oe, &v->Ri[6]);
	minimacs_rep_clean_up(oe, &v->Ri[7]);
}
