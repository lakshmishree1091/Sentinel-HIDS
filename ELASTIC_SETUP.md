# Sending Findings to Elastic Cloud - Setup

The script `elastic_send.sh` uploads findings to Elastic Cloud (for the Kibana
dashboard). It reads credentials from a `.env` file that is NOT in this repo
(it's gitignored, because it holds a secret key). Each person creates their own.

## Steps (each user does this on their own machine)

1. Get your Elasticsearch endpoint URL:
   - In Elastic Cloud, open your project's "Get started" / connection page.
   - Copy the "Elasticsearch endpoint" URL (looks like
     https://xxxxx.es.<region>.gcp.elastic.cloud:443).

2. Create an API key (the ENCODED version):
   - In Kibana: Admin/Settings > API keys > Create API key.
   - Name it (e.g. "sentinel-sender"), click Create.
   - On the result screen, make sure the dropdown says "Encoded",
     then click the COPY button next to the key.
   - IMPORTANT: copy it immediately - it is shown only once.

3. Create a file named `.env` in the sentinel-hids folder with this content
   (use YOUR url and YOUR encoded key, keep the quotes, all on one line each):

   ELASTIC_URL="https://YOUR-ENDPOINT.es.REGION.gcp.elastic.cloud:443"
   ELASTIC_API_KEY="YOUR_ENCODED_API_KEY"

4. Lock the file so only you can read it:
   chmod 600 .env

5. Make sure curl and jq are installed:
   sudo apt install -y curl jq

6. Test the send (after a scan has produced findings):
   ./elastic_send.sh logs/findings.jsonl sentinel-hids

   Success looks like:  Sent ... to Elastic index: sentinel-hids (HTTP 200)

## Notes
- NEVER commit your .env to git - it contains your secret key.
  It is already listed in .gitignore, so git will ignore it.
- If Kibana shows "no results", widen the time range (top-right) to
  "Last 30 days" and refresh.
