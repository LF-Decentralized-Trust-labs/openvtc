# Multiple WebVH DIDs with Same Domain

To create different WebVH DIDs for the same domain name, set the URL during setup to:

```bash
✔ Enter the URL that will host your DID document (e.g., https://<your-domain>.com): https://mydomain.com/profile1
```

The setup wizard creates a WebVH DID with the following value:

```bash
did:webvh:QmeQawCuEQFF28UNKxGcue4tKx3Vyc2bgknCPKKY61gCgh:mydomain.com:profile1
```

The `did:webvh` will resolve into `https://mydomain.com/profile1/did.jsonl` to parse the DID document.

This is helpful when you want to setup multiple profiles with different WebVH DIDs for the same domain hosting the DID documents or when doing testing.
