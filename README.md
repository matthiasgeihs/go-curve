# `go-curve`: Efficient and safe elliptic curve cryptography

`go-curve` is an **experimental** library of cryptographic primitives based on elliptic curves. It is written in Go and makes use of generics for providing some amount of type safety.

The primitives are typically parametrized by a curve type parameter specifying the used curve.
Higher-order primitives are additionally parametrized by the lower-order primitives they are constructed from.

## Examples

### ECDSA digital signature

The ECDSA digital signature scheme is represented by a struct type that is parametrized by an elliptic curve type.
```go
type ECDSA[C curve.Curve] struct {...}
```
The implementation is generic and can be instantiated with any chosen elliptic curve implementation.
```go
instance := ecdsa.NewECDSA[secp256k1.Curve](...)
```
Keys and signatures produced by the scheme will also be parametrized by the selected curve type. This means that the outputs can be identified with the respective curve and the compiler will be able to check this. 

```go
func (dsa *ECDSA[C]) Sign(sk SecretKey[C], m []byte) (Sig[C], error) {...}
```

### Camenisch-Damgard verifiable encryption

The Camenisch-Damgard verifiable encryption consists of a prover, a verifier, and a decrypter.
As an example, the prover is represented by a struct type that is parametrized by an elliptic curve type, a sigma protocol type, a probabilistic encryption scheme type, and a commitment scheme type.
```go
type Prover[G curve.Curve, P sigma.Protocol, E probenc.Scheme, C commit.Scheme] struct {...}
```
Again, the implementation is generic and can be instantiated with any chosen elliptic curve, sigma protocol, probabilistic encryption, and commitment scheme. At the same time, the outputs are identified with the chosen types and the compiler is able to check that only elements of the same types are combined with each other.

```go
func (p Prover[G, P, E, C]) Commit(
	x sigma.Word[G, P],
	w sigma.Witness[G, P],
) (
	Commitment[C],
	Decommitment[G, P, E, C],
	error,
) {...}
```

## Development

Install [Go](https://go.dev).

Run the tests using `go test`.

```
go test ./...
```

## License
The code is licensed under the MIT License and provided without warranty of any kind.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Copyright Matthias Geihs, 2023.
