# IPK - Computer Communications and Networks - Project 2
## Sniffer paketů

### ZADÁNÍ:
Navrhněte a implementujte síťový analyzátor v C/C++/C#, který bude schopný na
určitém síťovém rozhraním zachytávat a filtrovat pakety.

## Syntax spuštění
`./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}`
| Příkaz | Popis |
| --- | --- |
| `-i [rozhraní]` nebo `--interface [rozhraní]` | `-i eth0` Právě jedno rozhraní, na kterém se bude poslouchat. Nebude-li tento parametr uveden, či bude-li uvedené jen -i bez hodnoty, vypíše se seznam aktivních rozhraní. |
| `-p [port]` | `-p 23`Bude filtrování paketů na daném rozhraní podle portu; nebude-li tento parametr uveden, uvažují se všechny porty; pokud je parametr uveden, může se daný port vyskytnout jak v source, tak v destination části. |
| `-t` nebo `--tcp` | Bude zobrazovat pouze TCP pakety. |
| `-u` nebo `--udp` | Bude zobrazovat pouze UDP pakety. |
| `--icmp` | Bude zobrazovat pouze ICMPv4 a ICMPv6 pakety. |
| `--arp` | Bude zobrazovat pouze ARP rámce. |
| `-n` | `-n 10` Určuje počet paketů, které se mají zobrazit, tj. i "dobu" běhu programu; pokud není uvedeno, uvažujte zobrazení pouze jednoho paketu, tedy jakoby `-n 1`.|

- Pokud nebudou konkrétní protokoly specifikovány, uvažují se k tisknutí všechny (tj. veškerý obsah, nehledě na protokol)
- Argumenty mohou být v libovolném pořadí.

## Formát výstupu:
| Příkaz | Výstup |
| --- | --- |
| `timestamp` | Čas (ve formátu dle RFC3339) |
| `src MAC` a `dst MAC` | MAC adresa s : jako oddělovačem |
| `frame length` | Délka (v bytech) |
| `src IP` a `dst IP`| Pokud je tak IP adresa (podpora v4 ale i v6 dle RFC5952) |
| `src port` a `dst port` | Pokud je tak portové číslo |
| `offset_vypsaných_bajtů` | Výpis_bajtů_hexa výpis_bajtů_ASCII |