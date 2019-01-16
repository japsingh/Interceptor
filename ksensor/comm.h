#pragma once

#include "events.h"

NTSTATUS InitComm();
VOID UninitComm();

NTSTATUS Publish(EVENT *evt);