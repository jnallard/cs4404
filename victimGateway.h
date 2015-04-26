#ifndef VICTIM_GATEWAY_H
#define VICTIM_GATEWAY_H

pthread_t startHandleFlowThread(Flow* flow);
void* handleFlow(void* flowPtr);
void requestFlowBlocked(Flow* flow);
void escalateFlow(Flow* flow);
#endif