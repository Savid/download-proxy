# Download Proxy

A reverse proxy that intercepts download links and provides options to save files to the server or download locally.

## Docker

```bash
docker run -d \
  -p 5050:5050 \
  -v /path/to/downloads:/watched \
  -e AUTH_TOKEN=your_token_here \
  -e UPSTREAM_DOMAIN=example.com \
  -e DOWNLOAD_URL_PATTERN="%s/download.php/%s/%s.zip" \
  -e DETAILS_URL_PATTERN="%s/details.php?id=%s" \
  -e DOWNLOAD_FILE_EXTENSION=".zip" \
  -e DOWNLOAD_LINK_PATTERNS="download.php,get.php" \
  --name download-proxy \
  ghcr.io/your-username/download-proxy:latest
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AUTH_TOKEN` | ✅ | Authentication token |
| `UPSTREAM_DOMAIN` | ✅ | Domain to proxy |
| `DOWNLOAD_URL_PATTERN` | ✅ | Download URL pattern |
| `DETAILS_URL_PATTERN` | ✅ | Details page URL pattern |
| `DOWNLOAD_FILE_EXTENSION` | ✅ | File extension |
| `DOWNLOAD_LINK_PATTERNS` | ✅ | Link patterns to match |

## License

MIT