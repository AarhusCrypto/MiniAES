#include <cheetah.h>
#include <osal.h>
#include <math/matrix.h>


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

static byte tbl_shift_rows[16][16] = {
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

byte test[4][4] = {

  {0,0,0,1},
  {0,1,0,0},
  {0,0,1,0},
  {1,0,0,0}

};

byte tbl_mix_columns[16][16] = {
  {2,0,0,0, 3,0,0,0, 1,0,0,0 ,1,0,0,0},
  {0,2,0,0, 0,3,0,0, 0,1,0,0 ,0,1,0,0},
  {0,0,2,0, 0,0,3,0, 0,0,1,0 ,0,0,1,0},
  {0,0,0,2, 0,0,0,3, 0,0,0,1 ,0,0,0,1},
  //
  {1,0,0,0, 2,0,0,0, 3,0,0,0, 1,0,0,0},
  {0,1,0,0, 0,2,0,0, 0,3,0,0, 0,1,0,0},
  {0,0,1,0, 0,0,2,0, 0,0,3,0, 0,0,1,0},
  {0,0,0,1, 0,0,0,2, 0,0,0,3, 0,0,0,1},
  //
  {1,0,0,0, 1,0,0,0, 2,0,0,0, 3,0,0,0},
  {0,1,0,0, 0,1,0,0, 0,2,0,0, 0,3,0,0},
  {0,0,1,0, 0,0,1,0, 0,0,2,0, 0,0,3,0},
  {0,0,0,1, 0,0,0,1, 0,0,0,2, 0,0,0,3},
  //
  {3,0,0,0, 1,0,0,0, 1,0,0,0, 2,0,0,0},
  {0,3,0,0, 0,1,0,0, 0,1,0,0, 0,2,0,0},
  {0,0,3,0, 0,0,1,0, 0,0,1,0, 0,0,2,0},
  {0,0,0,3, 0,0,0,1, 0,0,0,1, 0,0,0,2},
};

byte sbox[256] = {
		  0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
		  0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
		  0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
		  0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
		  0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
		  0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
		  0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
		  0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
		  0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
		  0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
		  0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
		  0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
		  0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
		  0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
		  0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
		  0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};


#define MM(M1,M2) matrix_multiplication(M1,M2)

MATRIX * pow3(MATRIX * SR) {
  MATRIX * T = 0, * T1 = 0;
  
  T = MM(SR,SR);
 
  T1 = MM(T,SR);

  destroy_matrix(T);

  return T1;
  
}


typedef struct _aes_state_ {
  byte state[16];
} * Aes;

Aes Aes_new(OE oe) {
  Aes res = (Aes)oe->getmem(sizeof(*res));
  return res;
}

void Aes_destroy(OE oe, Aes * aes) {
  if (!aes) return;
  if (!*aes) return;

  oe->putmem(*aes);
  *aes = 0;
}

// load h by w data set into a freshly allocated matrix
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

static Aes 
key_schedule(OE oe, Aes key, uint round) {
  Aes res = Aes_new(oe);
  polynomial rcon = 1;
  byte tmp[4] = {0};
  uint i = 0;

  // Invalid round 
  if (round < 1 || round > 11) return 0;

  // round constant (TODO(rwl): Make constant)
  for(i = 0; i < round-1; ++i) {
    rcon = multiply(rcon,2);
  }
  
  // key schedule core
  tmp[0] = sbox[key->state[7]] ^ rcon;
  tmp[1] = sbox[key->state[11]];
  tmp[2] = sbox[key->state[15]];
  tmp[3] = sbox[key->state[3]];
  
  // key schedule word 0
  res->state[ 0] = tmp[0] ^ key->state[ 0];
  res->state[ 4] = tmp[1] ^ key->state[ 4];
  res->state[ 8] = tmp[2] ^ key->state[ 8];
  res->state[12] = tmp[3] ^ key->state[12];

  res->state[ 1] = res->state[ 0] ^ key->state[ 1];
  res->state[ 5] = res->state[ 4] ^ key->state[ 5];
  res->state[ 9] = res->state[ 8] ^ key->state[ 9];
  res->state[13] = res->state[12] ^ key->state[13];

  res->state[ 2] = res->state[ 1] ^ key->state[ 2];
  res->state[ 6] = res->state[ 5] ^ key->state[ 6];
  res->state[10] = res->state[ 9] ^ key->state[10];
  res->state[14] = res->state[13] ^ key->state[14];

  res->state[ 3] = res->state[ 2] ^ key->state[ 3];
  res->state[ 7] = res->state[ 6] ^ key->state[ 7];
  res->state[11] = res->state[10] ^ key->state[11];
  res->state[15] = res->state[14] ^ key->state[15];

  return res;
}

static Aes 
subbytes(OE oe, Aes aes) {
  Aes res = Aes_new(oe);
  uint i = 0;

  for(i = 0;i < 16;++i) {
    res->state[i] = sbox[aes->state[i]];
  }

  return res;
}

static Aes 
mix_columns(OE oe, Aes aes) {
  Aes res = Aes_new(oe);

  MATRIX * MC = load_matrix(oe,(byte*)tbl_mix_columns,16,16);
  MATRIX * V  = load_matrix(oe,aes->state,16,1);
  MATRIX * R  = matrix_multiplication(MC,V);

  uint i = 0;

  destroy_matrix(MC);
  destroy_matrix(V);

  for(i = 0;i < 16;++i) {
    res->state[i] = matrix_getentry(R,i,0);
  }

  destroy_matrix(R);

  return res;
}

static Aes 
shift_rows(OE oe, Aes aes) {
  Aes res = Aes_new(oe);

  MATRIX * SR = load_matrix(oe,(byte*)tbl_shift_rows,16,16);
  MATRIX * V  = load_matrix(oe,aes->state,16,1);
  MATRIX * R  = matrix_multiplication(SR,V);

  uint i = 0;

  destroy_matrix(SR);
  destroy_matrix(V);
  
  for(i = 0;i < 16;++i) {
    res->state[i] = matrix_getentry(R,i,0);
  }

  destroy_matrix(R);
  
  return res;
}

static Aes 
shift_row_mix_cols(OE oe, Aes aes) {
  MATRIX * state = load_matrix(oe,aes->state,16,1);
  //MATRIX * SRMC = load_matrix(oe, (byte*)srmc, 16, 16 );
  MATRIX * SR = load_matrix(oe, (byte*)tbl_shift_rows, 16, 16);
  MATRIX * MC = load_matrix(oe, (byte*)tbl_mix_columns, 16, 16);
  MATRIX * SRMC = matrix_multiplication(MC, SR);
  MATRIX * res = matrix_multiplication(SRMC,state);
  uint i = 0;
  Aes aesres = 0;

  destroy_matrix(SR);
  destroy_matrix(MC);
  destroy_matrix(SRMC);
  destroy_matrix(state);

  aesres = Aes_new(oe);
  for(i = 0;i < 16;++i) {
    aesres->state[i] = matrix_getentry(res,i,0);
  }
  destroy_matrix(res);
  return aesres;
}

static Aes
add_round_key(OE oe, Aes state, Aes rkey) {
  uint i = 0;
  Aes newstate = Aes_new(oe);

  for(i = 0;i < 16;++i) {
    newstate->state[i] = rkey->state[i] ^ state->state[i];
  }
  
  return newstate;
}

static void
print_aes(OE oe, Aes aes) {
  uint i = 0, j = 0;
  byte b[5*16+2] = {0};

  b[0] = '\n';
  b[5*16+1] = '\n';
  for(i = 0;i < 4;++i) {
    for(j = 0; j < 4;++j) {
      if (j == 3)
	osal_sprintf(b+16*i+j*4+1," %2x\n",aes->state[j+4*i]);
      else
	osal_sprintf(b+16*i+j*4+1," %2x ",aes->state[j+4*i]);
    }
  }
  oe->p(b);
}


static Aes aes_encrypt(OE oe, Aes key, Aes in) {
  Aes plx = Aes_new(oe);
  uint round = 0;
  Aes tmp = 0;
  *plx = *in;

  /*
    Add the round key to the state to obtain the final state in
    {plx} of this round.
  */
  plx=add_round_key(oe,tmp=plx,key);
  //oe->p("Final state from this round:");
  //print_aes(oe,plx);
  Aes_destroy(oe,&tmp);


  for(round = 1;round < 11;++round) {
    byte b[32] = {0};
    /*
      Run the key schedule getting the new key in {key1} from the
      round number and the old key previously (e.g. before this line)
      stored in {key1}.
    */
    key = key_schedule(oe,tmp=key,round);
    Aes_destroy(oe,&tmp);

    /*
      Print what round we are at
    */
    //osal_sprintf(b,"Round %u:",round);
    //oe->p(b);

    /*
      Perform the S-Box on the state i {plx} which is out AES state.
    */
    plx=subbytes(oe,tmp=plx);
    //oe->p("After SubBytes:");
    //print_aes(oe,plx);
    Aes_destroy(oe,&tmp);

    /*
      Perform the shift rows step from {plx} assigning the new state
      to {plx}.

    plx = shift_rows(oe,plx);
    oe->p("After Shift rows:");
    print_aes(oe,plx);
    */

    /*
      Perform the mix columns step from {plx} assignment the new state
      to {plx} again.
     */
    if (round < 10)  {
      //plx = mix_columns(oe,plx);
      plx = shift_row_mix_cols(oe,tmp=plx);
      Aes_destroy(oe,&tmp);
    } else {
      plx = shift_rows(oe, tmp=plx);
      Aes_destroy(oe,&tmp);
    }
    //oe->p("After linear transform: ");
    //print_aes(oe,plx);

    /*
      Add the round key to the state to obtain the final state in
      {plx} of this round.
     */
    plx=add_round_key(oe,tmp=plx,key);
    //oe->p("Final state from this round:");
    //print_aes(oe,plx);
    Aes_destroy(oe,&tmp);

    /*
      Print the round key.
     */
    //oe->p("Key");
    //print_aes(oe,key);
  }

  return plx;
}

/*
int main(int c, char **a) {
  OE oe = OperatingEnvironment_New();

  Aes key = Aes_new(oe);
  Aes plx = Aes_new(oe);
  Aes cip = 0;

  init_polynomial();

  oe->p("Cheetah Multiparty Computation AES Implementation");
  oe->p("All rights reserved, Aarhus University 2014");
  
  cip = aes_encrypt(oe,plx,key);
  
  print_aes(oe,cip);

  teardown_polynomial();
  OperatingEnvironment_Destroy(&oe);
  return 0;
}
*/
