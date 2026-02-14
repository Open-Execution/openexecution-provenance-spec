# Embedding Provenance Badges

Provenance badges are the public-facing proof that a piece of work has been independently verified through the OpenExecution cryptographic provenance system. Unlike status indicators from internal observability tools, a provenance badge links to an Ed25519-signed certificate that any third party can verify -- court-ready evidence, not a debug dashboard.

Embed badges in your project documentation, README files, or web pages to link directly to the verification result.

## Badge URL Format

```
https://openexecution.dev/badge/{certificateId}
```

This URL returns a dynamically generated badge image (SVG) that displays the verification status of the certificate.

## Verification Link Format

```
https://openexecution.dev/verify/{certificateId}
```

This URL opens the interactive verification page where users can inspect the full certificate details, chain events, and integrity checks.

## Markdown

Use the following Markdown to embed a clickable provenance badge:

```markdown
[![OpenExecution Verified](https://openexecution.dev/badge/{certificateId})](https://openexecution.dev/verify/{certificateId})
```

**Example:**

```markdown
[![OpenExecution Verified](https://openexecution.dev/badge/a1b2c3d4-e5f6-7890-abcd-ef1234567890)](https://openexecution.dev/verify/a1b2c3d4-e5f6-7890-abcd-ef1234567890)
```

## HTML

Use the following HTML to embed a clickable provenance badge on a web page:

```html
<a href="https://openexecution.dev/verify/{certificateId}">
  <img
    src="https://openexecution.dev/badge/{certificateId}"
    alt="OpenExecution Verified"
  />
</a>
```

**Example:**

```html
<a href="https://openexecution.dev/verify/a1b2c3d4-e5f6-7890-abcd-ef1234567890">
  <img
    src="https://openexecution.dev/badge/a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    alt="OpenExecution Verified"
  />
</a>
```

## Badge Styles

The badge displays one of the following states:

| State | Color | Label |
|-------|-------|-------|
| Verified | Green | `OpenExecution | verified` |
| Revoked | Red | `OpenExecution | revoked` |
| Invalid | Gray | `OpenExecution | invalid` |

## Multiple Badges

If your project has multiple provenance certificates (e.g., one per major contribution or release), you can embed multiple badges:

```markdown
### Provenance

[![Answer Verified](https://openexecution.dev/badge/{certId1})](https://openexecution.dev/verify/{certId1})
[![PR Verified](https://openexecution.dev/badge/{certId2})](https://openexecution.dev/verify/{certId2})
```

## Programmatic Access

For programmatic verification (CI/CD pipelines, automated checks), use the verification API directly:

```bash
curl https://api.openexecution.dev/api/v1/provenance/verify/{certificateId}
```

Or use the SDKs:

- **Node.js:** `npm install @openexecution/verify`
- **Python:** `pip install openexecution-verify`

See the [JavaScript SDK](../sdk/js/README.md) and [Python SDK](../sdk/python/README.md) for details.
