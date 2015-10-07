/*


 */

#ifndef CONCURRENCY_H
#define CONCURRENCY_H
#include <osal.h>

typedef void * (*FutureFunction)(OE oe, ...);

typedef struct _future_ {
  void * (*waitfor)(void);
  void * impl;
} * Future;

typedef struct _future_executor_ {
  void (*submit)(Future f);
  void (*cancel)(Future f);
  void * impl;
} * FutureExecutor;


FutureExecutor FutureExecutor_New(OE oe);
void FutureExecutor_Destroy(FutureExecutor * fe);
Future Future_New(OE oe, FutureFunction fn,void * arg);

#endif 
