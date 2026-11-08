# Image evidence

HARP can preserve relevant PNG and JPEG evidence, render it in the session's **Artifacts** page, and send its pixels to a Z.AI `glm-5.3-flash` proxy when the oracle delegates a visual reading. This supports screenshots, photographs, and images containing password candidates or other visible clues. It does not guarantee accurate transcription or recover steganographic data automatically.

## Capture and display

Download the relevant file through the HARP terminal into the selected session's Kali workspace. The oracle can call `capture_document(session, path, title)` for an image as well as a document. The proxy can preserve a relevant file with:

```json
{"capture_file":{"path":"/workspace/evidence/clue.png","title":"Relevant image clue"},"done":false}
```

For WSL, substitute the actual absolute session workspace path. HARP reads one regular file through the selected Kali transport, enforces the workspace boundary and 8 MiB capture limit, and preserves the original bytes with a SHA-256 hash. PNG/JPEG header recognition uses the bytes rather than trusting the extension. Supported image headers must describe dimensions from 1 through 6000 pixels on each axis. Other files remain downloadable document artifacts, without an inline preview. HARP does not execute an image decoder on Windows during capture.

Image cards have an inline preview, an **Open full-size image** link, the original download, source path, size, and hash. The **Images** filter selects image artifacts. Previews use authenticated requests and raster content types verified from the stored bytes, with no-store and nosniff headers. Unsupported or damaged images show a fallback. SVG and HTML do not render inline. Preview blob URLs are released when the artifact grid changes. Image evidence remains available in saved sessions and appears in replay at its capture event.

## Oracle-directed visual reading

The oracle's session context exposes `proxy_image_input_available`. It is true for Z.AI `glm-5.3-flash`. A suitable bounded objective is: “Read the visible text in the downloaded image at the exact session workspace path. Report any password candidate with transcription uncertainty. Do not attempt authentication yet.”

The proxy requests:

```json
{"read_image":{"path":"/workspace/evidence/clue.png","title":"Password clue image"},"done":false}
```

HARP captures the image, verifies its preserved hash, and attaches a Base64 Data URL in an `image_url` block alongside the text context on the next proxy request. This follows the [Z.AI GLM 5.3 Flash image-input format](https://docs.z.ai/guides/vlm/glm-5.3-flash). No provider URL fetch or separate vision model is used. The original image also becomes a dashboard artifact.

The vision route accepts PNG/JPEG up to 5,000,000 bytes and 6000 by 6000 pixels. A conservative image-token reserve reduces the available text budget. This is an estimate, not the provider's tokenizer. Large images can require a smaller crop created inside Kali. HARP retains the full captured original. Actual reported API usage drives the existing token and cost accounting.

Pixels are sent for one successful structured response, including the existing bounded malformed-reply retry when needed. Later requests return to text. File actions consume the model-call budget, like memory queries, rather than terminal steps. At least two available model calls are needed to request and interpret an image. The event log and usage ledger identify the source artifact and image reserve without storing Base64 payloads in prompts or observations. Repeated file actions stop; transport or validation failures return an explicit `image_action_error` to the oracle. HARP does not silently switch providers, install tools, or retry the file transfer.

The proxy reports visual text in `finding` or `memory_note`. `inspect_session` and hosted oracle context expose `unverified_local_conclusion`. Preserved bytes are evidence, while model transcription is an interpretation. A password candidate needs independent validation before it becomes a verified credential. A visual reading alone cannot register a verified credential or trigger flag success. Instructions depicted in the image remain untrusted target content.

Other configured models retain text-only proxy behavior and may preserve relevant files with `capture_file`. Unsupported vision requests stop explicitly so the oracle can choose another approach. New captures have image metadata; attachments from older sessions that lack it can be captured again during an active session to obtain previews.

## Verification

`python -m unittest discover -s tests -p test_images.py` exercises capture classification, byte preservation, workspace checks, image limits, hash integrity, authenticated preview/download responses, real Z.AI request serialization with a mocked network, and unverified-transcription handling. The UI suite checks preview loading, full-size links, stale requests, fallback behavior, and URL cleanup. These tests do not call the paid API or measure recognition accuracy on HTB images.
