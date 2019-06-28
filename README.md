![travis](https://travis-ci.org/waxosuit/waxosuit.svg?branch=master)&nbsp;
![license](https://img.shields.io/github/license/waxosuit/waxosuit.svg)

# Waxosuit

Waxosuit is an _exosuit_ designed to securely bind cloud native capabilities to **WebAssembly** modules.

Waxosuit is designed around the following core tenets:

* Productivity - Developer and Operations
* Enterprise-grade Security
* Cost Savings
* Portability
* Performance

# Building
Run `make release` to produce a release version of the `waxosuit` binary and the accompanying first-party capability plugins. 

Then, run `make docker` to trigger the build of the docker image using the newly created release binaries.

# Running

To run Waxosuit, you can either use the Docker image or run it directly. Running it directly, you must specify the directory where the capability provider plugins are and the path to the guest module (.wasm file):

```
$ waxosuit myservice.wasm -c ./capabilities
```

For information on how to use it, documentation, and tutorials, take a look at the [Waxosuit site](https://waxosuit.io).
