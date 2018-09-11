[![Go Report Card](https://goreportcard.com/badge/github.com/tink-ab/tempfile)](https://goreportcard.com/report/github.com/tink-ab/tempfile)
[![go-doc](https://godoc.org/github.com/tink-ab/tempfile?status.svg)](https://godoc.org/github.com/tink-ab/tempfile)

tempfile
========
An implementation of
[`ioutil.TempFile`](https://golang.org/pkg/io/ioutil/#TempFile), but also with
an additional parameter for a deterministic suffix.

This is a workaround for https://github.com/golang/go/issues/4896.

Example
-------
```go
import "github.com/tink-ab/tempfile"

myFile, err := tempfile.TempFile("", "my-prefix", "my-suffix")
if err != nil {
    handleError(err)
}
defer myFile.Close()
defer func() {
    if err := os.Remove(myFile.Name()); err != nil {
        handleRemovalError(err)
    }
}()

doSomethingWith(myFile)
```
