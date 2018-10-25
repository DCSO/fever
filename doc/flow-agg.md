## Aggregated flow metadata JSON example

```json
{
  "sensor-id": "foobar",
  "time-start": "2017-03-13T17:36:53.205850748+01:00",
  "time-end": "2017-03-13T17:36:58.205967348+01:00",
  "tuples": {
    "172.22.0.214_172.18.8.116_993": {
      "count": 1,
      "total_bytes_toclient": 86895,
      "total_bytes_toserver": 17880
    },
    "172.22.0.214_172.18.8.145_2222": {
      "count": 2,
      "total_bytes_toclient": 36326,
      "total_bytes_toserver": 4332
    },
    "172.22.0.214_198.232.125.113_80": {
      "count": 3,
      "total_bytes_toclient": 23242,
      "total_bytes_toserver": 1223
    },
    "172.22.0.214_198.232.125.123_80": {
      "count": 1,
      "total_bytes_toclient": 1026322,
      "total_bytes_toserver": 51232
    }
  },
  "proxy-map": {
    "23.37.43.27": {
      "ss.symcd.com": 1
    }
  }
}
```
The `tuples` keys represent routes in which sourceIP/destIP/destPort (concatenated using `_`) map to the number of flow events observed in the reported time period. In the `proxy-map` dict, the keys are destination IP addresses which have had observed HTTP requests on ports 8000-8999, 80 or 3128 (i.e. typical proxy ports). The associated values are the number of times that these requests were made with certain HTTP Host headers.

Using the `-n` parameter, the reporting frequency can be tuned. Longer intervals (e.g. hours) will reduce load on the consuming endpoint, but may also lead to larger payloads in the JSON outlined above.