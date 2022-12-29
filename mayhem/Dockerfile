FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libssl-dev clang

COPY . /repo
WORKDIR /repo
RUN make -j8
RUN rm /repo/hash_extender*.o
RUN clang++ /repo/mayhem/fuzz_print_hex_fancy.cpp -fsanitize=fuzzer,address -I /repo/ /repo/*.o -o /fuzz

FROM ubuntu:20.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libssl-dev
COPY --from=builder /repo/hash_extender /hash_extender
COPY --from=builder /fuzz /fuzz_print_hex_fancy
