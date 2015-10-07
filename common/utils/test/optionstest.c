#include <osal.h>
#include <utils/options.h>
#include <testcase.h>

static int test_options(OE oe) {
  bool ok = True;
  Map a = 0;
  List keys = 0; 
  int i = 0;
  uint argc = 5;
  char *argv[] = {"-rasmus","zakarias","-sarah","zakarias","-switch"};
  
  a = Options_New(oe,argc,argv);
  AssertTrue( a != 0 );

  keys = a->get_keys();
  AssertTrue( keys != 0 );

  AssertTrue(keys->size() == 5);
  AssertTrue(a->contains("rasmus") == True);
  AssertTrue(a->contains("sarah") == True);
  AssertTrue(a->contains("switch") == True);

  

  Options_Destroy(&a);
  OperatingEnvironment_Destroy(&oe);

 test_end:
  return ok;
}

static Test tests[] = {
  {"Check that we can parse and create arguments", test_options},
};

static TestSuit optionssuit = {
  "Command line options parser",
  0,0,
  tests,sizeof(tests)/sizeof(Test)
};

TestSuit * options_test_suit(OE oe) {
  return &optionssuit;
}
