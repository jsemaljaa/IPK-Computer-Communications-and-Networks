# IPK - Počítačové komunikace a sítě
## 1. projekt
### Author: Alina Vinogradova, 2BIT
### [xvinog00@stud.fit.vutbr.cz](mailto:xvinog00@stud.fit.vutbr.cz)

## Aplikace: HTTP server v jazyce C
Server komunikující prostřednictvím protokolu HTTP poskytuje informace o systému klienta: **hostname**, **cpu-name** a **current cpu load**.<br>
<br>Dostupné k použití dotazy:
1. ```GET http://servername:12345/hostname```
2. ```GET http://servername:12345/cpu-name```
3. ```GET http://servername:12345/load```

Komunikace se serverem je možná s pomocí následujících nástrojů: webový prohlížeč, [wget](https://www.gnu.org/software/wget/), [curl](https://curl.se/).

## Překlad souboru 
`make` v kořenovém adresáři projektu.
```
    $ ls
    
    hinfosvc.c Makefile Readme.md
    
    $ make
    
    gcc -Wall -Werror hinfosvc.c -o hinfosvc
    
    $ ls
     
    hinfosvc  hinfosvc.c  Makefile  README.md
```

## Syntax spuštění
`./hinfosvc [-p port]`

kde `[-p port]` je lokální port na kterém server bude naslouchat požadavkům.

Server je možné ukončit pomocí `CTRL+C`. Umí zpracovat následující tři typy dotazů, které jsou na server zaslané příkazem GET:

`./hinfosvc 12345 &` - spuštění serveru na portu 12345 v pozadí.

1. Získání doménového jména:
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
2. Získání informací o CPU:
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
3. Aktuální zátěž. (Výpočet z hodnot uvedených v souboru `/proc/stat`):


    
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

### Prevence chyb
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