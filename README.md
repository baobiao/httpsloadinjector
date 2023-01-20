# HTTP Load Injector for Testing

This code is not for use in Production because we explicitly ignore the TLS verification.

## Basic Usage
```
./httpsloadinjector -p <JSON-FILE> -s <HTTPS-URL> [options]
```

## Required and Optional Inputs.
```
 -d,--duration <arg>   Optional maximum Duration in Hours for testing. Default is 1.
 -h,--headers <arg>    Optional Key-Value file name of HTTP Headers to use on every Request.
 -p,--payload <arg>    Required Path of JSON File to be sent as payload.
 -s,--service <arg>    Required Service endpoint to be targeted.
 -t,--threads <arg>    Optional number of threads to fire. Default is 1.
 -w,--waittime <arg>   Optional wait time in Seconds per thread between payload injection.
                         Default is 5 seconds.
```

- `--duration` - Default is **One Hour**.  Specify fraction of an hour for shorter tests.  All running threads will yield at the end of the test duration.
- `--headers` - Additional HTTP Headers that can be added into each HTTP Request. E.g. Basic Authentication, User Agent.
- `--payload` - Relative path to the JSON file that will be used by each HTTP Request.
- `--service` - HTTPS service endpoint to be targeted for load injection.
- `--threads` - Default is **One Thread**.  Specify a different number of threads for parallel loads.
- `--waittime` - Default is **5 seconds**. Specify a different integer value for each Thread to pause before continuing with the next request.  A random fraction of 1 second is added to the specified wait time.

## Example
The following example will spawn **17 threads**, each with a wait time of about **1 second between requests**.  The test will **run for one minute**.  Each request will send `payload.json` with additional Request Headers in `headers.txt` contents to the specified endpoint.
```
./httpsloadinjector -t 17 -w 1 -d 0.0167 -p ./payload.json -h headers.txt -s https://localhost:8443/hello-world
```

## Packaging
Packaged with:
- GraalVM 22.3.0 Java 17 CE
- Ubuntu 22.04 on WSL 2

### Compile Uber Jar
```
mvn package
```

### Compile Native Binary
```
mvn -Pnative native:compile
```