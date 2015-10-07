#include <testcase.h>

extern TestSuit * options_test_suit(OE oe);
extern TestSuit * future_test_suit(OE oe);
extern TestSuit * futureexecutor_test_suit(OE oe);

GetTestSuit subsuits[] = { 
  (GetTestSuit)options_test_suit,
  (GetTestSuit)future_test_suit,
  (GetTestSuit)futureexecutor_test_suit
};

TestSuit top = {
  "Utility tests",
  (__get_suit__ *)subsuits,
  sizeof(subsuits)/sizeof(GetTestSuit),
  0,
  0
};


TEST_MAIN(top);
