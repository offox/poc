# Opus Stereo Encoder Test

This sample demonstrates a minimal C++ server that:

1. Reads a stereo PCM16 file at 48 kHz.
2. Encodes the data with libopus and pushes it over RTP/UDP.
3. Exposes a lightweight HTTP control API and static HTML page to start the stream and play a WAV preview of the PCM source.

The browser playback is performed without WebRTC — the server simply renders the PCM source into a WAV container for the HTML page to fetch while Opus packets are delivered via RTP to the configured destination.

## Building

```bash
mkdir -p build
cd build
cmake ..
make
```

> **Note:** You must have `libopus` and `pkg-config` installed on your system.

## Running

```bash
./opus_streamer --file path/to/input.pcm --dest 127.0.0.1 --port 5004 --http-port 8080
```

* `--file` (required) points to a stereo PCM16 little-endian file sampled at 48 kHz.
* `--dest`/`--port` configure the RTP destination address and UDP port.
* `--http-port` configures the port used by the embedded HTTP server.
* `--web-root` optionally sets a custom directory that contains `index.html`.

Open a browser to `http://localhost:8080/` and click **Start Streaming**. The server begins emitting Opus over RTP and the page plays back the WAV rendering so you can hear the source locally.

## RTP Details

* Payload type: 111 (dynamic).
* Frame duration: 20 ms (960 samples per channel at 48 kHz).
* Marker bit is set only on the first packet of a session.
* A randomly generated SSRC, initial sequence number, and timestamp are used for each run.

## Limitations

* The PCM file is streamed once per activation of the **Start Streaming** button.
* Error handling is intentionally minimal for clarity.
* Browser playback is sourced from a WAV representation instead of receiving RTP directly.
