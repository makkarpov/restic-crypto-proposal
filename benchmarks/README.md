# benchmarks

This directory contains AI-generated Go benchmark files for measuring the performance of the core cryptographic algorithms.

Folks with deeper knowledge of Go benchmarking internals or performance wizardry are encouraged to call out any mistakes or inaccuracies.

Run these benchmarks with:

```shell
go test -bench=. -benchmem -benchtime=10s -cpu 1
```

A `src.tar` file is required as representative input data for the compression benchmark. The file used for the benchmark in the document was created from the restic codebase with the following command:

```shell
find . -type f -name '*.go' -print0 | tar --null -T - -cvf src.tar
```
