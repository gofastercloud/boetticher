# Reading platform journals

Use the bounded CLI command:

```text
boetticher logs HOST --since 1h --limit 100
boetticher logs HOST --unit blocky --priority warning
```

Hosts are resolved against the managed platform model. Unit names, durations,
priorities, and result counts are validated; arbitrary journal paths and follow
mode are not supported. The collector's own local journal is distinct from
remote collected journals.
