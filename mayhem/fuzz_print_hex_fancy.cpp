#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
extern "C"
{
#include "util.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    if (size < 1) {
        return 0;
    }
    std::vector<uint8_t> vec = provider.ConsumeBytes<uint8_t>(1000);
    print_hex_fancy(&vec[0], 1000);
    return 0;
}
