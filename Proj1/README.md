
# IPK - Computer Communications and Networks - Project 1
## HTTP server v C
### ZADÁNÍ:
Úkolem je vytvoření serveru v jazyce C/C++ komunikujícího prostřednictvím protokolu HTTP, který bude poskytovat různé informace o systému. Server bude naslouchat na zadaném portu a podle url bude vracet požadované informace. Server musí správně zpracovávat hlavičky HTTP a vytvářet správné HTTP odpovědi. 
Typ odpovědi bude text/plain. Komunikace se serverem by měla být možná jak pomocí webového prohlížeče, tak nástroji typu wget a curl. Server musí být spustitelný v prostředí Linux Ubuntu 20.04 LTS.

Server bude přeložitelný pomocí Makefile, který vytvoří spustitelný soubor hinfosvc.

## Syntax spuštění
`./hinfosvc [-p port]`

kde `[-p port]` je argumentem označující lokální port na kterém bude naslouchat požadavkům.

Server bude možné ukončit pomocí CTRL+C. Server bude umět zpracovat následující tři typy dotazů, které jsou na server zaslané příkazem GET:

- Získání doménového jména
    
    Vrací síťové jméno počítače včetně domény, například:
    ```
    GET http://servername:12345/hostname
    
    merlin.fit.vutbr.cz
    ```
- Získání informací o CPU

    Vrací informaci o procesoru, například:
    ```
    GET http://servername:12345/cpu-name

    Intel(R) Xeon(R) CPU E5-2640 0 @ 2.50GHz
    ```
- Aktuální zátěž 

    Vrací aktuální informace o zátěži. (Výpočet z hodnot uvedených v souboru /proc/stat). Výsledek je například:
    ```
    GET http://servername:12345/load

    65%
    ```