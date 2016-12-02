# Considerations when writing tests

## "Namespacing"

When running most tests, we (in general) want the tests to be contained to,
themselves, which is tricky when our tests by their nature must modify the 
global state of the cluster. Because Swarmkit lacks native namespacing 
capabilities, in the tests we instead hack a sort of poor man's namespacing 
using UUIDs, name mangling, and labels. This usually doesn't affect the 
behavior of the tests, but test writers should be aware of this so that their 
tests don't become victim of a leaky abstraction.

On test run start, a UUID is generated in `main_test.go`. This UUID is returned
by the `UUID` function, and is used whenever some object needs to be 
identified. Only objects (services etc.) that belong to this test will have 
this UUID, so it can reliably be used to differentiate this test's objects from
those that may have been generatd by another test.

The functions in `utils.go` do most of the heavy lifting. When you create a 
service spec with `CannedServiceSpec`, the name of the function is mangled to 
add the UUID to the end. The original unmangled name is stored unadorned as a
label. In addition, a `uuid` label is added, with the value set to the UUID. As
as consequence of the name mangling, the name should not be used as an 
identifier for the service; its final form is human readable for debugging 
purposes but otherwise should be considered an implementation detail. If you 
cannot or do not wish to use the service ID returned on creation, you should 
filter service by name and uuid labels.
