#include "utils/concurrency.h"
#include <coov4.h>
#include <blockingqueue.h>
#include <datetime.h>
#include <singlelinkedlist.h>

typedef struct _future_impl_ {
  FutureFunction fn;
  OE oe;
  MUTEX lock;
  void * args;
  void * result;
} *FutureImpl;

COO_DEF(Future, void *, waitfor) {
  FutureImpl impl = (FutureImpl)this->impl;
  impl->oe->lock(impl->lock);
  return impl->result;
}}

Future Future_New(OE oe, FutureFunction fn,void * arg) {
  Future future = oe->getmem(sizeof(*future));
  FutureImpl impl = 0;

  if (!future) return 0;

  impl = oe->getmem(sizeof(*impl));
  if (!impl) goto error;

  future->impl = impl;
  impl->oe = oe;
  impl->fn = fn;
  oe->newmutex(&impl->lock);
  oe->lock(impl->lock);

  future->waitfor = COO_attach(future,Future_waitfor);

  return future;
 error:
  oe->putmem(future);
  oe->putmem(impl);
  return 0;
}

void Future_Destroy(Future * fn) {
  Future f = 0;
  FutureImpl impl = 0;
  OE oe = 0;

  if (!fn) return;
  f = *fn;

  if (!f) return;

  impl = (FutureImpl)f->impl;
  if (!impl) return;

  oe = impl->oe;

  COO_detach(f->waitfor);
  
  oe->destroymutex(&impl->lock);
  oe->putmem(impl);
  oe->putmem(f);
}


typedef struct _future_executor_impl {
  BlkQueue work;
  OE oe;
  List runners; // List<ThreadID>.
  bool running;
} * FutureExecutorImpl;

COO_DEF(FutureExecutor, void, submit, Future f) {
  FutureExecutorImpl fe = (FutureExecutorImpl)this->impl;
  
  if (!f) return;

  BlkQueue_push(fe->work, f);
}}

COO_DEF(FutureExecutor,void,cancel,Future f) {
  FutureExecutorImpl fe = (FutureExecutorImpl)this->impl;
  fe->oe->p("FutureExecutor cancel is not implemented.");
}}

static void * future_executor_runner(void * args) {
  FutureExecutorImpl impl = (FutureExecutorImpl)args;
  OE oe = impl->oe;
  DateTime dt = 0;

  dt = DateTime_New(oe);
  if (!dt) {
    ERR(oe,"Cannot create datetime instance");
    return 0;
  }

  oe->p("Future Executor Running in the air");
  while(impl->running) {
    Future f = BlkQueue_take(impl->work);
    FutureImpl fi = 0;
    ull start = 0;
    oe->p("Got task from queue");

    if (!f) continue;
    fi = (FutureImpl)f->impl;
    start = dt->getMilliTime();
    fi->result = fi->fn(oe,fi->args);
    oe->p("Complete task %p in %lu ms",fi,dt->getMilliTime()-start);
    oe->unlock(fi->lock);
  }
  return 0;
}

#define NO_RUNNERS 8
FutureExecutor FutureExecutor_New(OE oe) {
  FutureExecutor fe = (FutureExecutor)oe->getmem(sizeof(*fe));
  FutureExecutorImpl fei = 0;
  uint i = 0;
  if (!fe) return 0;

  fei = (FutureExecutorImpl)oe->getmem(sizeof(*fei));
  if (!fei) goto error;

  fe->submit = COO_attach(fe, FutureExecutor_submit);
  fe->cancel = COO_attach(fe, FutureExecutor_cancel);

  fei->work = BlkQueue_new(oe,1000);
  if (!fei->work) goto error;


  fei->oe = oe;
  fei->running = True;
  fe->impl = fei;

  fei->runners = SingleLinkedList_new(oe);
  for(i = 0; i < NO_RUNNERS;++i) {
    ThreadID runner = 0;
    oe->newthread(&runner,future_executor_runner,fei);
    fei->runners->add_element((void*)(ull)runner);
  }
  
  return fe;
 error:
  oe->putmem(fe);
  BlkQueue_destroy(&fei->work);
  return 0;
}

void FutureExecutor_Destroy(FutureExecutor * fe) {
  FutureExecutor f = 0;
  FutureExecutorImpl fi = 0;
  OE oe = 0;
  uint i = 0;

  if (!fe) return;

  f = *fe;

  fi = f->impl;
  if (!fi) return;

  // kindly ask thread to stop
  fi->running = False;
  oe = fi->oe;
  for(i = 0; i < fi->runners->size();++i) {
    BlkQueue_push(fi->work,0);
  }

  // wait for runner to complete.
  oe->yieldthread();
  for(i = 0; i < fi->runners->size();++i) {
    ThreadID runner = 0;
    runner = (ThreadID)(ull)fi->runners->get_element(i);
    oe->jointhread(runner);
  }

  // release interface
  COO_detach(f->submit);
  COO_detach(f->cancel);

  // destroy state
  BlkQueue_destroy(&fi->work);
  oe->putmem(fi);
  oe->putmem(f);
}

