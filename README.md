## covenants-examples
Some examples of covenants


### Caboose: a data carrying output





### Transaction flow

```
// structure:
//
// input:
//   this program
//   another paying input
//
// output:
//   this program (copy)
//   new state: OP_RETURN (4 bytes for the counter value) (4 bytes for randomness)
```

```mermaid
graph TD
    A[Input]
    B[This Program] --> A[This Program]
    C[Another Paying Input] --> A[Input]
    D[Output]
    D --> E[Copy of This Program]
    D --> F[New State: OP_RETURN]
    F --> G[Counter Value 4 bytes]
    F --> H[Randomness 4 bytes]
```