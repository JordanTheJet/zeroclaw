# ML Kit Gemini Nano migration plan

Status: planned. The default sideload remains Lite until this plan is implemented and validated.

## Why this migration exists

The optional Full flavor currently depends on the experimental Google AI Edge AICore client:

```text
com.google.ai.edge.aicore:aicore:0.0.1-exp02
```

Google's current Android path for custom Gemini Nano prompts is the ML Kit GenAI Prompt API. It
still uses the device's AICore system service, but gives applications an availability contract,
model download lifecycle, typed errors, and maintained generation APIs. Google currently documents
the Android dependency as:

```text
com.google.mlkit:genai-prompt:1.0.0-beta2
```

The migration must not be treated as a dependency rename. ML Kit enforces device, foreground,
quota, and model-availability constraints that affect zerodroid's background-agent architecture.

Official references, checked 2026-08-22:

- [ML Kit GenAI overview](https://developers.google.com/ml-kit/genai)
- [Prompt API setup and availability lifecycle](https://developers.google.com/ml-kit/genai/prompt/android/get-started)
- [Prompt API model selection](https://developers.google.com/ml-kit/genai/prompt/android/select-model)
- [GenerativeModel reference](https://developers.google.com/android/reference/kotlin/com/google/mlkit/genai/prompt/GenerativeModel)
- [GenAI error codes](https://developers.google.com/android/reference/kotlin/com/google/mlkit/genai/common/GenAiException.ErrorCode)
- [Gemini Nano and AICore architecture](https://developer.android.com/ai/gemini-nano)

## What Full does today

The Full source set owns `NanoAi`; the Lite source set provides an API-compatible unavailable
stub. `ApiServer` exposes both implementations through `/ai/status` and
`/ai/generate?prompt=...`.

The current Full implementation:

1. Checks only whether the `com.google.android.aicore` package is installed.
2. Constructs an AI Edge `GenerativeModel` for each request.
3. Sets temperature `0.2`, top-K `16`, and maximum output tokens `256`.
4. Runs a text-only generation synchronously from the bridge request.
5. Returns JSON with `model`, `on_device`, and `text`, or an exception class and message.
6. Closes the model after a successful generation attempt.

This endpoint is an optional Android-native API. It is not the provider used by normal ZeroClaw
cloud turns, and none of the Accessibility, screenshot, overlay, or `android_*` tools depend on it.

The package-presence check is not a sufficient capability check. AICore can be installed while the
required model is unavailable, downloading, incompatible, or blocked by device policy.

## Concrete API mapping

| Existing AI Edge operation | ML Kit Prompt API replacement |
|---|---|
| `getPackageInfo("com.google.android.aicore")` | Create `Generation.getClient()` and call `checkStatus()` |
| Boolean installed status | Return `AVAILABLE`, `DOWNLOADABLE`, `DOWNLOADING`, or `UNAVAILABLE` |
| No model preparation API | For `DOWNLOADABLE`, expose an explicit `download()` flow and progress |
| `GenerativeModel(generationConfig { context = ... })` | `Generation.getClient()`; AICore context is managed by ML Kit |
| Model-level `temperature`, `topK`, and `maxOutputTokens` | Set the same values on `GenerateContentRequest` |
| `model.generateContent(prompt)` | `model.generateContent(generateContentRequest(...))` |
| `response.text` | Preserve the existing JSON `text` field from `GenerateContentResponse.text` |
| Generic `Throwable` response | Map `GenAiException.errorCode` to stable machine-readable JSON |
| Hard-coded `gemini-nano` label | Add `getBaseModelName()` to status diagnostics |
| Best-effort close after success | Close in `finally` on every path |

The first implementation should preserve the two endpoint response shapes. New fields such as
`feature_status`, `base_model`, `downloaded_bytes`, and `error_code` must be additive so existing
callers keep working.

## Required adapter boundary

Do not call ML Kit directly from `ApiServer`. Keep the flavor-owned `NanoAi` facade and place a
small internal interface behind it with these operations:

```text
status() -> feature status + base model
download(progress callback) -> terminal download result
generate(prompt, generation options) -> text or typed error
close()
```

Production Full binds that interface to ML Kit. JVM tests bind it to a fake. Lite continues to
bind an unavailable implementation without resolving any GenAI dependency. This keeps the API
route stable and makes every availability and error branch testable without pretending an emulator
contains AICore.

## Foreground-use constraint

This is the migration's main semantic blocker. Google's current ML Kit GenAI contract permits
inference only while the application is the top foreground application. A foreground service does
not qualify. A normal zerodroid agent turn often runs while another application is foreground, so
blindly replacing the client would convert apparently valid requests into
`BACKGROUND_USE_BLOCKED` failures.

The safe initial scope is therefore:

- Keep cloud providers as the background-capable agent path.
- Expose Gemini Nano only while a visible zerodroid activity is foreground.
- Report `BACKGROUND_USE_BLOCKED` honestly; do not retry it.
- Do not keep an invisible activity open, steal foreground focus, or treat the overlay as proof
  that zerodroid is the top activity.
- Reconsider background agent integration only if Android publishes an API and policy that permits
  it.

If product requirements demand background local inference, this migration cannot claim feature
parity. That requirement needs a different local model runtime or a later platform capability.

## Device and OEM gates

The Prompt API library supports an Android API level below zerodroid's existing minimum, but the
library being installable does not mean the model is usable. Runtime status is the source of truth.

1. Call `checkStatus()` before download or generation.
2. Treat `UNAVAILABLE` as unsupported, not as a transient network failure.
3. Treat `DOWNLOADABLE` as requiring an explicit user-started model download.
4. Surface `DOWNLOADING` and progress instead of starting competing downloads.
5. Generate only after `AVAILABLE`.
6. Record `getBaseModelName()` because Nano versions can produce different results.
7. Use Google's published device list only for release planning, never as a hard-coded allowlist.

Google's current Prompt API list includes OnePlus 15 under the Nano v3 group. That does not replace
the runtime gate: OS build, Google system components, account rollout, storage, and model state can
still make the feature unavailable on an individual phone.

Stable model selection should remain the default. Preview selection must be a developer-only
explicit option because it requires separate AICore Developer Preview eligibility and has a
different support matrix.

## Error and retry policy

Map ML Kit errors into stable endpoint categories:

| Error | Handling |
|---|---|
| `BUSY` | Bounded exponential backoff, then return retryable failure |
| `PER_APP_BATTERY_USE_QUOTA_EXCEEDED` | Do not retry in the same turn; explain the long-duration quota |
| `BACKGROUND_USE_BLOCKED` | Do not retry; require the visible app foreground |
| `AICORE_INCOMPATIBLE`, `NEEDS_SYSTEM_UPDATE` | Non-retryable device remediation |
| `NOT_AVAILABLE`, `NOT_SUPPORTED` | Non-retryable capability result |
| `NOT_ENOUGH_DISK_SPACE` | Stop download/generation and request user remediation |
| `REQUEST_TOO_LARGE`, `REQUEST_TOO_SMALL` | Validate or resize the request before another attempt |
| Policy or response-processing errors | Return a safe refusal without exposing model internals |
| `CANCELLED` | Preserve cancellation, do not convert it into a generic failure |

Do not retry every exception. In particular, background, compatibility, storage, policy, and
battery-quota failures cannot be fixed by an immediate loop.

## Implementation sequence

1. Add the ML Kit Prompt dependency to Full only and regenerate strict Gradle verification
   metadata. Keep Lite's resolved dependency graph unchanged.
2. Introduce the testable adapter and status model without changing the HTTP contract.
3. Replace package inspection with `checkStatus()` and add explicit download progress.
4. Port generation options and close the model in `finally`.
5. Add stable error mapping and bounded retry for `BUSY` only.
6. Add foreground lifecycle tracking from the visible activity and fail closed when it is absent.
7. Remove `com.google.ai.edge.aicore:aicore:0.0.1-exp02` and its Guava override after parity tests
   pass.
8. Reassess whether a separate Full flavor is still valuable. If ML Kit remains optional and
   device-gated, keep the flavor; do not move the dependency into default Lite by accident.

## Validation required before the swap is safe

### Automated gates

- Lite no-argument Gradle build succeeds without resolving any GenAI Prompt artifact.
- Full opt-in Debug and Release unit tests, lint, and assembly succeed.
- Strict Gradle dependency verification contains checksums for every new artifact.
- The Android OSV scan covers Lite and Full Debug and Release runtime classpaths.
- Facade tests cover every feature status, download terminal state, and mapped error category.
- Route tests prove old JSON fields remain present and new fields are additive.
- A resource-lifecycle test proves `close()` runs after success, failure, and cancellation.
- A mutation test proves removing the foreground gate makes a regression test fail.

### Physical-device matrix

Run these checks on the connected OnePlus 15 and at least one unsupported emulator or device:

- Confirm the actual OnePlus reports its base model and one of the documented feature statuses.
- Exercise `DOWNLOADABLE` through progress and completion if the model is not already present.
- Generate a short deterministic prompt while zerodroid is visibly foreground.
- Put another app in front and prove generation returns `BACKGROUND_USE_BLOCKED` without focus
  theft or retries.
- After model download, enable airplane mode and prove a foreground prompt remains on-device.
- Verify `BUSY` uses bounded backoff and battery quota does not spin.
- Verify process stop/restart does not leak a model client or leave a stuck download state.
- Compare temperature, top-K, and output-token behavior to the existing endpoint contract.
- Confirm cloud providers and every Android UI tool behave identically in Lite and Full.

### Release acceptance

The swap is ready only when:

1. Lite remains the default and has no new Google GenAI runtime dependency.
2. Full installs on a supported device and degrades honestly on an unsupported one.
3. Foreground-only behavior is visible in the UI and release notes.
4. Endpoint compatibility, cancellation, cleanup, and typed failures are proven.
5. APK size, first-token latency, peak memory, and battery impact are recorded against the old
   Full build.
6. No provider credential, screen content, prompt, or generated text is added to logs or test
   artifacts.

## Rollback

The migration is isolated to the Full flavor's `NanoAi` implementation and dependency set. If a
release candidate fails the device matrix, restore the experimental Full adapter or omit Full from
the release. Lite, cloud providers, Accessibility, screenshot/vision, overlay, and Android-native
tools remain unaffected.
