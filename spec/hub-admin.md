# Sparrow Hub Administration (sparrow.hub.admin v1)

> Companion to the core specification (`core.md`, section 10.9). Snapshot of the live draft, revision 36, exported for this repository. The live document is the source of truth.

A hub that implements this interface can be configured entirely at run time by a controlling application, such as an orchestrator that runs the hub in a container. The controller pushes one desired-state document; the hub validates it, applies it as a whole, and rolls it back by itself unless the controller confirms it in time. A bootstrap administrator can always reach the interface, so no document can lock the hub out of administration.

## 1. The facet

- The hub publishes a facet named `sparrow.hub.admin`, version `1.0.0`, that implements the interface of section 5. Its facet ID is the hub's choice and stays stable (Hub Profile, section 10.3).
- Every method is authorized like any other call (Hub Profile, section 10.4); every method carries the hint annotation `"sparrow.level": "manage"`.
- **Bootstrap administrator:** the hub's static configuration names at least one principal that is always allowed every method of this facet. No configuration document can take that away.
- Authorization policy (who may call what) is hub-specific. It lives in the document's `extensions`, so confirmation and rollback cover it like everything else.

## 2. Configuration model

The hub's configuration is one document with a **revision** number.

- **Revisions** are unsigned integers, persisted with the document, that go up by one each time the applied document changes, rollbacks included. Revision 0 is a hub that has never been configured, with the document `{nodes: {}}`.
- **Commits replace the whole document.** There is no patch format; a controller reads the document, changes it and commits the result against the revision it read.
- **Optimistic concurrency:** a commit names the revision it is based on, and fails with `Error(aborted)` if that is no longer current. When no commit is pending, a commit whose document is byte-for-byte equal to the applied one in canonical encoding changes nothing and returns the current revision, whatever its base, so retrying a commit whose reply was lost is safe.
- **Validation first:** a commit is validated as a whole before anything changes (section 3). If any problem is found, it fails with `Error(failed_precondition)`, and nothing changes.
- **Secrets by reference:** secrets are stored separately, cannot be changed once stored, and are referenced from the document by name. The document stays small, and every credential change goes through a commit, so confirmation and rollback cover it.

### 2.1 Stored secrets

- `setSecret` stores a secret under a new name. A name that already exists fails with `Error(already_exists)`: to rotate a secret, store it under a new name and commit a document that refers to it. No method ever returns a secret's value.
- `deleteSecret` succeeds when the secret does not exist, and fails with `Error(failed_precondition)` while the applied document or the rollback target of a pending commit refers to it.
- Secret names follow the node-ID grammar (Hub Profile, section 10.2).

### 2.2 Applying a commit

When a commit passes validation, the hub switches to the new document at once and then **reconciles** in the background. `commit` returns after the switch, not after reconciliation; progress is visible in `watch`. The hub registers nodes and never runs them (Hub Profile, section 10.10).

- A node added to the document is dialed, or accepted when it dials in, as its `link` says.
- A node that a revision removes or disables, or whose `link` or `peer` it changes, has its session ended at once, as the Hub Profile, section 10.2, describes: a dialed node is dialed anew under the new configuration, and a dial-in node must dial in again. Until a new session is ready the node is offline, and calls wait or fail as in section 10.7 of the Hub Profile. A node is therefore never served under a configuration that was replaced.

### 2.3 Confirmation and rollback

A commit with `confirmWithinMs` greater than 0 is **pending** until it is confirmed:

- At most one commit is pending. While one is, every commit fails with `Error(aborted)`, even one identical to the pending document; the controller reads the outcome with `get` or `watch` and retries later.
- The **rollback target** is the pending commit's base document. Because nothing else can commit meanwhile, it is always the last confirmed document.
- `confirm(N)` succeeds if N is the current revision and is pending or confirmed; otherwise it fails with `Error(not_found)`, which means only that N is no longer current; the controller reads what happened with `get` or `watch`. The hub decides atomically at the deadline, so a confirmation processed after it fails.
- `rollback(N)` rolls a pending revision N back at once.
- **A rollback**, whether from the deadline, from `rollback` or from a restart while a commit is pending, applies the rollback target as revision N+1, already confirmed. `watch` reports `rolledBack` for N, then `confirmed` for N+1.
- A commit with `confirmWithinMs` of 0 is confirmed at once.

A controller SHOULD confirm over a new session, which shows that new connections still work after the change.

### 2.4 Persistence and bootstrap

The hub persists the last confirmed document with its revision, the highest revision number it has handed out, the stored secrets, its facet-ID table and the last known facets of every node (Hub Profile, sections 10.3 and 10.7). It records the high-water mark before `commit` returns, so a revision number is never handed out twice. A pending commit is never persisted as confirmed. The static configuration (listen addresses, TLS settings and the bootstrap administrator) is up to the implementation.

## 3. The document

```
Config = {
  nodes:         { * node-id => NodeConfig },
  ? defaults:    { * bstr => facet-name },   ; interface hash => preferred facet
  ? extensions:  { * tstr => bstr }          ; hub-specific settings, each a CBOR document
}

NodeConfig = {
  link:          Link,
  ? peer:        bool,           ; the node is another hub (Hub Profile, section 10.8)
  ? enabled:     bool,           ; default true
  ? extensions:  { * tstr => bstr }
}

Link     = [0, Dial]             ; the hub dials the node
         / [1, secret-name]      ; the node dials in and presents this credential

Dial     = { url: tstr, pin: bstr, credential: secret-name }
           ; pin: SHA-256 of the node's SubjectPublicKeyInfo
           ; credential: what the hub presents as ["link", credential]
```

A document is valid when:

- every node ID follows the node-ID grammar and is not reserved (Hub Profile, section 10.2);
- every referenced secret exists, every secret named by a link is named once in the document, and the values of all those secrets are pairwise distinct, so no credential presented to one party can be replayed to another;
- every `Dial.url` is an `https` (WebTransport) or `wss` (WebSocket) URL, and every `pin` is 32 bytes;
- every `defaults` key is a 33-byte interface hash and every value a syntactically valid facet name;
- every `extensions` key is one the hub supports, with valid contents.

Defaults are preferences, not checked against live facets: where the named facet is not visible to a session or does not implement the interface, the hub uses its own choice (Hub Profile, section 10.3).

## 4. Watching

`watch` streams the hub's state:

1. The first event is a full `Snapshot`, followed by one `NodeEvent` for each configured node with its current state.
2. Then every `RevisionEvent` and `NodeEvent`, in the order they happen. A `NodeEvent`'s `revision` is the latest revision whose configuration of that node the reported state reflects, so a controller can tell whether a node is up under the configuration it just committed. After each applied revision R the hub sends a `NodeEvent` for every configured node; a node whose configuration R did not change is reported with R.
3. A node that R removes gets one `NodeEvent` with state `removed` and is not reported again. An `offline` event's `message` gives the last connection failure, such as a pin mismatch or a refused facet.
4. A hub MAY end a watch that falls too far behind with `Error(resource_exhausted)`; the controller starts a new one, which begins with a snapshot again.

## 5. The interface

The types and methods below make up the interface `sparrow.hub.admin` v1. The interface document is named `sparrow.hub.admin` with version `1.0.0` and carries no annotations, and its methods list no errors, since every error they use is a core code. An `optional` field has flag 0x1 and its plain type; `list<T>` is `[0, T]` and `map<K, V>` is `[1, K, V]`. Test vectors published with the spec give its canonical encoding and interface hash.

### 5.1 Types

| TypeId | Name | Kind | Fields or values (tag: name type) |
| --- | --- | --- | --- |
| 64 | `Config` | struct | 0: nodes `map<string, NodeConfig>`; 1: defaults `optional map<bytes, string>`; 2: extensions `optional map<string, bytes>` |
| 65 | `NodeConfig` | struct | 0: link `Link`; 1: peer `optional bool`; 2: enabled `optional bool`; 3: extensions `optional map<string, bytes>` |
| 66 | `Link` | union | 0: dial `Dial`; 1: credential `string` |
| 67 | `Dial` | struct | 0: url `string`; 1: pin `bytes`; 2: credential `string` |
| 68 | `Snapshot` | struct | 0: revision `uint`; 1: config `Config`; 2: state `RevisionState`; 3: confirmInMs `optional uint` |
| 69 | `CommitRequest` | struct | 0: base `uint`; 1: config `Config`; 2: confirmWithinMs `uint` |
| 70 | `ValidateRequest` | struct | 0: base `uint`; 1: config `Config` |
| 71 | `Problem` | struct | 0: path `list<string>`; 1: message `string` |
| 72 | `Problems` | alias | `list<Problem>` |
| 73 | `Secret` | struct | 0: name `string`; 1: value `bytes` |
| 74 | `Names` | alias | `list<string>` |
| 75 | `Event` | union | 0: snapshot `Snapshot`; 1: revision `RevisionEvent`; 2: node `NodeEvent` |
| 76 | `RevisionEvent` | struct | 0: revision `uint`; 1: state `RevisionState`; 2: confirmInMs `optional uint` |
| 77 | `RevisionState` | enum | sigils 64 `pending`, 65 `confirmed`, 66 `rolledBack` |
| 78 | `NodeEvent` | struct | 0: node `string`; 1: revision `uint`; 2: state `NodeState`; 3: message `optional string` |
| 79 | `NodeState` | enum | sigils 67 `connected`, 68 `offline`, 69 `disabled`, 70 `removed` |

Sigils 64–70 are kind 0 (enum values). `confirmInMs` is the time left before the deadline, measured by the hub when it sent the message, so clocks need not agree. A `Problem.path` lists the keys from the document root to the problem, using the field names of section 3 and a union's variant name as one more key, with byte-string map keys as lowercase hex, such as `["nodes", "acme.charts", "link", "dial", "pin"]`.

### 5.2 Methods

One service, 0 `Admin`:

| MethodId | Name | Input | Output | Flags | Behaviour |
| --- | --- | --- | --- | --- | --- |
| 0 | `get` | `unit` | `Snapshot` | idempotent | The applied revision and document, and its state. |
| 1 | `validate` | `ValidateRequest` | `Problems` | idempotent | Validates without changing anything; an empty list means valid. A stale `base` fails with `aborted`. |
| 2 | `commit` | `CommitRequest` | `uint` |  | Validates and applies (sections 2.2, 2.3); returns the new revision. Errors: `aborted` (stale base, or a commit is pending), `failed_precondition` (invalid; `details` is the `dynamic` value `[72, problems]`). |
| 3 | `confirm` | `uint` | `unit` | idempotent | Errors: `not_found`. |
| 4 | `rollback` | `uint` | `uint` |  | Rolls a pending revision back at once and returns the new revision. Errors: `not_found`. |
| 5 | `setSecret` | `Secret` | `unit` |  | Errors: `already_exists`, `invalid_argument` (bad name). |
| 6 | `deleteSecret` | `string` | `unit` | idempotent | Errors: `failed_precondition` (still referenced). |
| 7 | `listSecrets` | `unit` | `Names` | idempotent | Secret names only. |
| 8 | `watch` | `unit` | `[3, Event]` | output ends with `End` | Section 4. |

`watch`'s output is a stream, so it sets flag 0x10; no other half is a stream or reaches `[4]`. `watch` does not set the hint flag 0x4, because its first event holds the whole document.
