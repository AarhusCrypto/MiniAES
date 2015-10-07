#include <testcase.h>

#include <utils/concurrency.h>

static void * test_fn(void * args) {
  OE oe = (OE)args;

  return (void*)0xBEEF;
}

static int test_create_future(OE oe) {
  bool ok = True;
  Future fut = Future_New(oe,test_fn,oe);
  AssertTrue(fut != 0);
  Future_Destroy(&fut);
 test_end:
  return 1;
}

static Test futuretests[] = {
  {"Test Future create",test_create_future},
};


static TestSuit future_suit = {
  "Future Concurrency test suit",
  0,0,
  futuretests,sizeof(futuretests)/sizeof(Test)
};

TestSuit * future_test_suit(OE oe) {
  return &future_suit;
}
