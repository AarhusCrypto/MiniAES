#include <testcase.h>
#include <cheetah_pre.h>
#include <math/polynomial.h>
#include <mpc_aes.h>
#include <coov4.h>

#define AssertTrue(BExp) if ((BExp) != True) goto fail;

// ----- pre-processing tests ------
static int test_decomp_pre_processing(OE oe) {
	Rnd rnd = 0;
	MiniMacsEnc enc = 0, smenc=0;
	Cfp cfp = 0;
	CheetahDVal dval = 0;
	init_polynomial();
	init_matrix();

	enc = MiniMacsEnc_MatrixNew(oe, 255, 119);
	if (enc == 0) goto fail;

	smenc = MiniMacsEnc_MatrixNew(oe, 44, 14);
	if (smenc == 0) goto fail;

	rnd = LibcWeakRandomSource_New(oe);
	if (rnd == 0) goto fail;

	cfp = Cfp_SimpleNew(oe, enc, smenc, rnd, 2);
	if (cfp == 0) goto fail;

	dval = cfp->get_decomposed(0);
	if (dval == 0) goto fail;

	dval = cfp->get_decomposed(1);
	if (dval == 0) goto fail;

	Cfp_SimpleDestroy(&cfp);
	LibcWeakRandomSource_Destroy(&rnd);
	MiniMacsEnc_MatrixDestroy(&enc);

	return 1;
fail:
	Cfp_SimpleDestroy(&cfp);
	LibcWeakRandomSource_Destroy(&rnd);
	MiniMacsEnc_MatrixDestroy(&enc);
	return 0;
}

static int test_sbox_sr_pre_processing(OE oe) {
	Rnd rnd = 0;
	MiniMacsEnc enc = 0, smenc = 0;
	Cfp cfp = 0;
	CheetahSBox box = 0;
	init_polynomial();
	init_matrix();

	enc = MiniMacsEnc_MatrixNew(oe, 255, 119);
	if (enc == 0) goto fail;

	smenc = MiniMacsEnc_MatrixNew(oe, 44, 14);
	if (smenc == 0) goto fail;

	rnd = LibcWeakRandomSource_New(oe);
	if (rnd == 0) goto fail;

	cfp = Cfp_SimpleNew(oe, enc, smenc, rnd, 2);
	if (cfp == 0) goto fail;

	box = cfp->get_sbox_sr(0); // leaked
	if (box == 0) goto fail;

	box = cfp->get_sbox_sr(1); // leaked
	if (box == 0) goto fail;

	Cfp_SimpleDestroy(&cfp);
	LibcWeakRandomSource_Destroy(&rnd);
	MiniMacsEnc_MatrixDestroy(&enc);

	return 1;
fail:
	Cfp_SimpleDestroy(&cfp);
	LibcWeakRandomSource_Destroy(&rnd);
	MiniMacsEnc_MatrixDestroy(&enc);
	return 0;
}

static int test_sbox_srmc_pre_processing(OE oe) {
	Rnd rnd = LibcWeakRandomSource_New(oe);
	MiniMacsEnc enc = 0, smenc = 0;
	Cfp cfp = 0;
	CheetahSBox box = 0;
	init_polynomial();
	init_matrix();

	enc = MiniMacsEnc_MatrixNew(oe, 255, 119);
	if (enc == 0) goto fail;

	smenc = MiniMacsEnc_MatrixNew(oe, 44, 14);
	if (smenc == 0) goto fail;

	cfp = Cfp_SimpleNew(oe, enc, smenc, rnd, 2);
	if (cfp == 0) return 0;

	box = cfp->get_sbox_srmc(0);
	if (box == 0) goto fail;

	box = cfp->get_sbox_srmc(1);
	if (box == 0) goto fail;

	box = cfp->get_sbox_srmc(2);
	if (box != 0) goto fail;

	return 1;
fail:
	return 0;
}
static int test_single_pre_processing(OE oe) {
	Rnd rnd = LibcWeakRandomSource_New(oe);
	MiniMacsEnc enc = 0, smenc = 0; 
	Cfp cfp = 0;
	MiniMacsRep single = 0;
	init_polynomial();
	init_matrix();

	enc = MiniMacsEnc_MatrixNew(oe, 255, 119);
	if (enc == 0) goto fail;

	smenc = MiniMacsEnc_MatrixNew(oe, 44, 14);
	if (smenc == 0) goto fail;
	
	cfp = Cfp_SimpleNew(oe, enc, smenc, rnd, 2);
	if (cfp == 0) return 0;
	
	single = cfp->get_single(0);
	if (single == 0) goto fail;

	minimacs_rep_clean_up(oe, &single);

	single = cfp->get_single(1);
	if (single == 0) goto fail;

	minimacs_rep_clean_up(oe, &single);

	single = cfp->get_single(2);
	if (single != 0) goto fail;

	Cfp_SimpleDestroy(&cfp);
	if (cfp != 0) return 0;

	MiniMacsEnc_MatrixDestroy(&enc);
	LibcWeakRandomSource_Destroy(&rnd);

	return 1;
fail:
	Cfp_SimpleDestroy(&cfp);
	MiniMacsEnc_MatrixDestroy(&enc);
	LibcWeakRandomSource_Destroy(&rnd);
	minimacs_rep_clean_up(oe, &single);
	return 0;
}



static int test_serialise_preprocessing(OE oe) {
	Rnd rnd = LibcWeakRandomSource_New(oe);
	MiniMacsEnc enc = 0, smenc = 0;
	Cfp cfp = 0;
	MiniMacsRep single = 0;
	const uint nplayers = 2;
	init_polynomial();
	init_matrix();

	enc = MiniMacsEnc_MatrixNew(oe, 255, 119);
	if (enc == 0) goto fail;

	smenc = MiniMacsEnc_MatrixNew(oe, 44, 14);
	if (smenc == 0) goto fail;

	cfp = Cfp_SimpleNew(oe, enc, smenc, rnd, nplayers);
	if (cfp == 0) return 0;


	return 1;
fail:
	return 0;
}

static int test_aes_cached_preprocessing_create_file_does_not_exists(OE oe) {
	AesPreprocessing prep = AesPreprocessing_Cached_New(oe, "doesnotexists.rep", 1, 1, 1, 1, 1, 1);

	prep->get_playerid();

	AssertTrue(prep == 0);
	return 1;
fail:
	return 0;
}

static int test_aes_cached_preprocessing_create(OE oe) {
	AesPreprocessing prep = AesPreprocessing_Cached_New(oe, "aes.rep", 1, 2, 3, 4, 5, 6, 7);



	AssertTrue(prep != 0)
		return 1;
	fail:
	return 0;
}

// ------ cheetah protocol tests ------
static int test_cheetah_protocol(OE oe) {
	return 0;
}

Test tests[] = { 
//	{ "Invoking get_single pre-processing and check output", test_single_pre_processing },
//	{ "Invoking get_sbox_srmc pre-processing and check output", test_sbox_srmc_pre_processing },
//	{ "Invoking get_sbox_sr pre-processing and check output", test_sbox_sr_pre_processing },
//	{ "Invoking get_decomposed pre-processing and check output", test_decomp_pre_processing },
	{ "Check that we fail to create cached preprocessing if file is missing", test_aes_cached_preprocessing_create_file_does_not_exists },
	{ "Check that we can instantiate Cache preprocessing",test_aes_cached_preprocessing_create }
};

TestSuit daessuit = { "Cheetah pre-processing - dedicated for AES",
0,0,
tests,sizeof(tests)/sizeof(Test)
};

TEST_MAIN(daessuit)