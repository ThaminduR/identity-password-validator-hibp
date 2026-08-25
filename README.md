# WSO2 Identity Server - Have I Been Pwned Breach Source

A breach-intelligence source for WSO2 Identity Server that checks candidate passwords against the
[Have I Been Pwned](https://haveibeenpwned.com/) Pwned Passwords corpus.

It implements the `BreachSource` contract published by Identity Server's breached credential detection, and
registers itself as an OSGi service. Enforcement, ordering, failure policy, telemetry and user-facing
messaging all belong to the product; this connector's only job is to answer whether a password is in the
corpus, or to say clearly that it could not tell.

## Requirements

- WSO2 Identity Server with breached credential detection (the `org.wso2.carbon.identity.breach.detection`
  bundles) present.
- Maven 3.x, JDK 11 or higher.
- No API key. The Pwned Passwords range endpoint requires no authentication. A key is supported for
  subscribers, and a missing one is never treated as a reason to stop checking.

## Installation

```bash
mvn clean install
cp components/org.wso2.identity.password.validator.hibp/target/org.wso2.identity.password.validator.hibp.component-*.jar \
   <IS-HOME>/repository/components/dropins/
```

Restart the server. The connector registers itself; there is no configuration file to edit for it to appear.
The server log records the bound sources and their priorities on startup:

```
Breach source bound: id=hibp, priority=500, capabilities=[REMOTE, PASSWORD_ONLY]
```

## Configuration

Operator settings go under this source's namespace in `deployment.toml`. Every key is optional.

```toml
[breach_detection.sources.hibp]
api_key = "$secret{hibp_api_key}"   # optional; vault-resolved, never returned by any API
base_url = "https://api.pwnedpasswords.com/range/"
read_timeout_ms = 1500
connect_timeout_ms = 1000
cache_ttl_seconds = 3600
cache_max_entries = 5000
retries = 1
circuit_breaker_failures = 5
circuit_breaker_open_seconds = 60
```

Whether the source is consulted is this connector's own per-organization setting, published as a governance
connector under **Password Security**. Because the connector publishes it, the setting appears in the Console
when this bundle is installed and disappears when it is removed - no product change is involved either way.

| Setting | Default | Meaning |
|---|---|---|
| `hibp.enable` | `false` | Consult this source for the organization. |
| `__secret__hibp.apiKey` | empty | The key to present for this organization. Optional - see below. |
| `hibp.refuseWhenUnreachable` | `false` | Refuse the password when this service cannot answer, rather than letting it through. |

```http
PATCH /api/server/v1/identity-governance/{category}/connectors/{connector}
{"operation":"UPDATE","properties":[{"name":"hibp.enable","value":"true"}]}
```

The two switches are booleans on purpose. The Console's generic connector form picks a toggle when a
property's value is `true` or `false` and a text box otherwise, so a setting modelled as an enumeration would
make an administrator type `allow` or `deny` by hand.

The API key carries the platform's `__secret__` prefix, the same convention the shipped Sift and ELK
connectors use. That is what makes the Console render it as a password field rather than a plain text box.

**A key is optional, and leaving it empty is a supported configuration** - the range endpoint this connector
calls is free and unauthenticated. An organization's own key wins; the deployment-wide `api_key` above is the
fallback; and with neither set the source still checks every password. A blank key silently disabling the
check is the 1.x failure this connector exists to avoid.

**Know where the key is readable.** A governance property marked confidential is still returned in full by
`GET /identity-governance/{category}/connectors` - we confirmed this against a running server. Marking it
confidential keeps it out of the unauthenticated preferences endpoint, and nothing more. Anyone holding
`internal_idp_view` can read the key back. That is a property of the platform's connector API, not of this
connector, and it applies equally to the shipped connectors that store keys the same way. If that is not
acceptable in your deployment, put the key in `deployment.toml` behind the secret store and leave the
per-organization field empty.

The Console renders these in the order above, and that is why the connector is named `have-i-been-pwned`
rather than `hibp`. When a connector's name is a prefix of its property names, `getConnectorListWithConfigs`
matches every same-prefixed property on the first pass and emits them in the order the platform's property
map happens to yield - a `HashMap` keyed by property name, so the order is arbitrary and shifts as other
connectors are installed. Keeping the connector name outside the property namespace means each property is
matched on its own pass and `getPropertyNames()` decides the order.

## How it works

The candidate password is hashed with SHA-1 in process. The first five characters of the digest are sent to
the range endpoint; the remaining thirty-five never leave the deployment. The endpoint returns every suffix in
that bucket — roughly eight hundred of them — and the match is made locally, so the service never learns the
answer to its own query. `Add-Padding` is sent on every request so the response size does not reveal how many
entries a bucket holds.

Range responses are cached by prefix, which is the only thing worth caching: a bucket is stable for hours and
is shared by every password in it. The candidate password and its full digest are never cache keys and never
cache values.

The call is bounded by an explicit timeout and a retry count, and repeated failure opens a circuit breaker so
an outage costs the deployment one timeout rather than one per registration. Every one of those outcomes is
reported as *unavailable* with a cause — timeout, transport, quota, parse — and never as *not found*. What
that means for the password is the deployment's decision, not this connector's.

## Upgrading from 1.x

1.x was not a breach source. It registered a governance connector and an HTTP servlet, and hooked no
credential-write path, so it could not refuse a password being set. 2.0 replaces that entirely.

| 1.x | 2.0 |
|---|---|
| `/hibp` servlet taking a plaintext password | Removed. Nothing here accepts a password from a caller. |
| `[[resource.access_control]]` with `secure = false` | No longer required, and should be removed. |
| `hibp.password.validator.*` governance connector | Replaced by `breachDetection.*`, which covers every source. |
| Blank API key reported every password as clean, while presenting as enabled | The range endpoint needs no key; a missing key changes nothing. |
| No enforcement | Enforced by the product's listener on every password-setting path. |

**If you are running 1.x, remove the `(.*)/hibp(.*)` access-control entry from `deployment.toml`.** While it is
present, the 1.x servlet accepts a plaintext password from an unauthenticated caller.

The live "check as you type" behaviour the 1.x servlet existed for is deliberately not reintroduced. A browser
that wants it can query the range endpoint directly with a hash prefix, so Identity Server never sees the
password at all.

## Building a source of your own

`BreachSource` is a published contract. Implement it and register the service:

```java
bundleContext.registerService(BreachSource.class, new MySource(), null);
```

The contract is versioned on its own compatibility rather than on the product's release number, so a connector
importing `[1.0,2.0)` keeps resolving across product minors and majors. Everything but `getId`,
`getDescriptor` and `evaluate` has a default, and the contract gains default methods rather than abstract
ones, so an existing connector keeps compiling across additive revisions.
