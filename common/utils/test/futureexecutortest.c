#include <testcase.h>
#include <utils/concurrency.h>
#include <singlelinkedlist.h>

static int test_create_futureexecutor(OE oe) {
  FutureExecutor fe = FutureExecutor_New(oe);
  bool ok = True;
  AssertTrue( fe != 0);
  FutureExecutor_Destroy(&fe);
 test_end:
  return ok;
}

static void * future_fn(OE oe, ...) {
  uint  i = 0, prev = i;
  oe->usleep(8000);
  return (void*)(ull)0xBEEF;
}

static int test_run_future(OE oe) {
  FutureExecutor fe = FutureExecutor_New(oe);
  bool ok = True;
  Future f = 0;
  ull v = 0;

  AssertTrue(fe != 0);
  
  f = Future_New(oe,future_fn,oe);
  AssertTrue(f != 0);
  
  fe->submit(f);
  
  v = (ull)f->waitfor();
  AssertTrue(v == 0xBEEF);

  FutureExecutor_Destroy(&fe);

 test_end:
  return ok;
}

static int test_perf_run_future(OE oe) {
  FutureExecutor fe = FutureExecutor_New(oe);
  bool ok = True;
  Future f = 0;
  ull v = 0;
  uint i = 0;
  List futures = SingleLinkedList_new(oe);

  AssertTrue(fe != 0);
  for (i = 0;i < 1000;++i) {
  
    f = Future_New(oe,future_fn,oe);
    AssertTrue(f != 0);
  
    fe->submit(f); 
    futures->add_element(f);
  }

  AssertTrue(futures->size() == 1000);
  for(i = 0; i < futures->size();++i) {
    Future fut = (Future)futures->get_element(i);
    v = (ull)fut->waitfor();
    AssertTrue(v == 0xBEEF);
    Future_Destroy(&fut);
  }

 test_end:
  SingleLinkedList_destroy(&futures);
  FutureExecutor_Destroy(&fe);
  return ok;
}


static Test futureexecutortests[] = {
  {"Test FutureExecutor create",test_create_futureexecutor},
  {"Test FutureExecutor run Future", test_run_future},
  {"Test perf run Future", test_perf_run_future},
};


static TestSuit futureexecutor_suit = {
  "Future Executor Concurrency test suit",
  0,0,
  futureexecutortests,sizeof(futureexecutortests)/sizeof(Test)
};

TestSuit * futureexecutor_test_suit(OE oe) {
  return &futureexecutor_suit;
}
