# IPK - Computer communications and networks
## 1 project
### Author: Alina Vinogradova, 2BIT
### [xvinog00@stud.fit.vutbr.cz](mailto:xvinog00@stud.fit.vutbr.cz)

## Application: HTTP server in C language
The HTTP server provides information about the client system: **hostname**, **cpu-name** a **current cpu load**.<br>
<br>Requests available for use:
1. ```GET http://servername:12345/hostname```
2. ```GET http://servername:12345/cpu-name```
3. ```GET http://servername:12345/load```

Communication with the server is possible with the following tools: Web browser, [wget](https://www.gnu.org/software/wget/), [curl](https://curl.se/).

## File compilation
`make` in the root directory of the project.
```
    $ ls
    
    hinfosvc.c Makefile Readme.md
    
    $ make
    
    gcc -Wall -Werror hinfosvc.c -o hinfosvc
    
    $ ls
     
    hinfosvc  hinfosvc.c  Makefile  README.md
```

## Execution syntax
`./hinfosvc [-p port]`

where `[-p port]` is the local port on which the server will listen for requests.

The server can be shut down using `CTRL+C`. It can process the following three types of requests that are sent to the server by the GET command:

`./hinfosvc 12345 &` - server startup on port 12345 in the background.

1. Obtaining a domain name:
```
    $ GET http://localhost:12345/hostname
    
    alja
```

```
    $ curl -i http://localhost:12345/hostname
    
    HTTP/1.1 200 OK
    Content-Length: 4
    Content-Type: text/plain;

    alja
```
2. Getting CPU information:
```
    $ GET http://localhost:12345/cpu-name

    Ryzen 7 3700U with Radeon Vega Mobile Gfx
```

```
    $ curl -i http://localhost:12345/cpu-name
    
    HTTP/1.1 200 OK
    Content-Length: 41
    Content-Type: text/plain;

    Ryzen 7 3700U with Radeon Vega Mobile Gfx
```
3. Current load. (Calculation from the values given in the file `/proc/stat`):


    
```
    $ GET http://localhost:12345/load
    
    17%
```

```
    $ curl -i http://localhost:12345/load
    
    HTTP/1.1 200 OK
    Content-Length: 3
    Content-Type: text/plain;

    18%
```

### Error prevention
1. `404 Not Found`
```
    $ curl -i http://localhost:12345/wrong
    
    HTTP/1.1 404 Not Found
    Content-Length: 0
    Content-Type: text/plain;

```
2. `405 Method Not Allowed`
```
    $ curl -i -X POST http://localhost:12345/cpu-name
    
    HTTP/1.1 405 Method Not Allowed
    Content-Length: 0
    Content-Type: text/plain;

```
