---
layout: post
title:  "Mit detekcji Pass-the-Hash – co naprawdę mówią logi 4624"
date:   2025-06-04 18:29:56 +0300
categories: Windows, Server, Logs, Detection 
back_to_top: true
back_to_top_text: "Back to top"
---

- TOC
{:toc}

## Wstęp
Postanowiłem pogłębić swoją wiedzę na temat ataków na Active Directory. Choć temat był mi znany od strony teoretycznej, brakowało mi doświadczenia w przeprowadzaniu tych ataków. Niedawno przygotowane środowisko testowe było doskonałą okazją do eksperymentów. 

Kilka dni temu realizowałem pokój o nazwie "Threat Hunting: Pivoting" na platformie [TryHackMe](https://tryhackme.com),  gdzie omawiano sposób detekcji ataku Pass-The-Hash (PtH). Uznałem, że będzie to idealny przykład do sprawdzenia. Temat ten jest powszechnie znany, szeroko opisywany i pozornie dobrze zrozumiany. Z pozoru powinno być prosto: zidentyfikować logi, porównać detekcje, wyciągnąć wnioski. Czy na pewno?

## Popularne sposoby detekcji PtH
W poszukiwaniu informacji wykonałem zapytanie do Google: _"how to detect pass the hash in windows logs"_ . Internet nie jest zgodny co do jednej, skutecznej metody. Najczęściej wskazywane indykatory to: 
* **Event ID:** 4624
* **Logon Type:** 3 (Network) 
* **LogonProcessName:** NtLmSsp
* **KeyLength:** 0 

jak również:
* **Event ID:** 4624
* **Logon Type:**  9 (NewCredentials)
* **Authentication Package** = Negotiate
* **Logon Process** = seclogo


## Opis środowiska testowego

Przygotowane środowisko testowe:
* **Windows Server Datacenter 2022** (OsVersion 10.0.20348) - Kontroler Domeny
* **PC-01** z Windows 11 Enterprise
* **Kali linux** - maszyna atakującego. 

Dodatkowo, w celu wspomagania procesu testowania środowisko wyposażone jest w: 
*  **Ubuntu + Arkime + Zeek** - przechwytywanie ruchu sieciowego i generowanie logów Zeek.
*  **Ubuntu + ELK** - agregacja logów z hostów. 
                            
W tym momencie warto zaznaczyć, ze opisane w dalszej części wyniki nie muszą być prawdziwe dla wszystkich (szczególnie poprzednich) wersji Windowsów i ich konfiguracji.  

## Opis ataku Pass-the-hash

Atak Pass-the-Hash polega na wykorzystaniu wcześniej pozyskanego hashu hasła konta (domenowego lub lokalnego) do uwierzytelnienia się w systemie bez znajomości hasła. Atak jest możliwy, ze względu na sposób działania mechanizmu "challenge-response" w protokole NTLM. 


## Zwykłe logowania vs Pass-the-Hash

Protokół NTLM jest dobrym punktem odniesienia, ponieważ logowania interaktywne (czyli takie w których użytkownikowi prezentowany jest ekran pulpitu) korzystają z protokołu Kerberos. Logi 4624 dla NTLM pojawiają się np podczas dostępu do zasobów sieciowych: 
* za pomocą komendy:
{% highlight cmd%}
Net use \\10.10.10.1\c$
{% endhighlight %}

* za pomocą explorer.exe.

Dla takich akcji typowe parametry to: 

```
Logon Type: 3
Logon Process: NtLmSsp
Authentication Package: NTLM
Package Name (NTLM only): NTLM v2
```
 
>Protokół uwierzytelniania wybierany przez system Windows zależy od sposobu, w jaki adresowany jest serwer.
>
>* Użycie **adresu IP** (np. `\\10.10.10.10\`) powoduje, że Kerberos nie może być użyty, brak pełnej nazwy domenowej (FQDN), więc Windows domyślnie przełącza się na **NTLM**.
>* Jeśli natomiast użyjemy **nazwy hosta** w domenie (np. `\\dc1.lab.local\`), system może zastosować **Kerberos**, o ile spełnione są wymagania (np. obecność SPN i ważny ticket TGT).
{: .tip }

### Przykład uzyskania dostępu do zasobu za pomocą komendy "net use" oraz odpowiadający log

<img src="/assets/images/post1/net_use.png" alt="Wykonanie komendy net use" width="600">
<img src="/assets/images/post1/net_use_4624_event.png" alt="Event 4624 wywołany podczas dostępu do sharea za pomocą komendy net use" width="600">
            
### Przykład z uzyskania dostępu do zasobu sieciowego za pomocą explorera. 
<img src="/assets/images/post1/explorer_share_access.png" alt="Event 4624 wywołany podczas dostępu do sharea za pomocą komendy net use" width="600">
<img src="/assets/images/post1/explorer_share_access_event_4624.png" alt="Event 4624 wywołany podczas dostępu do sharea za pomocą komendy net use" width="600">
            
## Test ataku Pass-the-Hash

Uzyskałem hash konta l.skywalker przez atak DCSYNC z użyciem Mimikatz na hoście domenowym. Nastepnie przeprowadziłem atak PtH narzędziem impacket-smbexec z systemu Kali. 

Smbexec oraz psexec wykorzstuje protokół SMB do wykonania zdalnych komend. SMB to protokół, który pozwala na udostępnianie zasobów sieciowych w środowisku domenowym. Oznacza to, że podczas użycia tych narzędzi zostanie wygenerowany log 4624 z wskazanymi wcześniej parametrami: 

```
Logon Type: 3
Logon Process: NtLmSsp
Authentication Package: NTLM
Package Name (NTLM only): NTLM v2
```

Obserwacje: 
* Na PC-01 pojawił się log 4624. Niczym nie różnił się od normalnego logowania z NTLM. 
* Na kontrolerze domeny nie pojawił się odpowiadający log logowania zdalnego.

Następnie wykonałem ten sam atak na DC. Wynik: 
* Log 4624 identyczny jak przy zwykłym dostępie po SMB.
* Dodatkowe logi 5140 (dostęp do udziałów) i 4688 (uruchomienie procesu).

Poniżej przedstawiam screeny logów. 

#### Atak na PC-01
<img src="/assets/images/post1/pth_to_pc01.png" alt="Terminal maszyny Kali z komendą do wykonania ataku pth z użyciem impacket-smbexec" width="600">

<img src="/assets/images/post1/4624_pth_on_pc01.png" alt="Event 4624 wywołany w momencie wykonania ataku PTH za pomocą impacket-smbexec" width="600">


#### Atak na kontroler domeny narzędziem impacket-smbexec

<img src="/assets/images/post1/smbexec_pth_to_dc.png" alt="Komenda do wykonania ataku PTH na kontroler domeny" width="600"> 
<img src="/assets/images/post1/smbexec_pth_na_dc_4624.png" alt="log 4624 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">
<img src="/assets/images/post1/psexec_pth_on_dc_5140_share_access.png" alt="log 5140 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">
<img src="/assets/images/post1/smbexec_pth_na_dc_4688_1.png" alt="log 4688 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">
<img src="/assets/images/post1/smbexec_pth_na_dc_4688_2.png" alt="log 4688 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">
<img src="/assets/images/post1/smbexec_pth_na_dc_4688_3.png" alt="log 4688 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">

<img src="/assets/images/post1/smbexec_new_service_7045.png" alt="log 7045 wygenerowany na kontrolerze domeny po udanym ataku pth z impacket-smbexec.py" width="600">

#### Atak na kontroler domeny narzędziem impacket-psexec
<img src="/assets/images/post1/psexec_pth_na_dc.png" alt="log 4624 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">
<img src="/assets/images/post1/psexec_pth_on_dc_5140_share_access.png" alt="log 5140 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">
<img src="/assets/images/post1/psexec_pth_on_dc_4688_1.png" alt="log 4688 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">
<img src="/assets/images/post1/psexec_pth_on_dc_4688_2.png" alt="log 4688 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">
<img src="/assets/images/post1/psexec_new_service_7045.png" alt="log 7045 wygenerowany na kontrolerze domeny po udanym ataku pth z impacket-psexec.py" width="600">


## Jak właściwie zbudowac detekcję? 

Na podstawie uzyskanych logów i znajomości działania `psexec.py` oraz `smbexec.py` wiemy, że:

1. Wykorzystywany hash uwierzytelnia się przez NTLM (Event ID 4624).
2. Następuje dostęp do udziałów IPC$, C$, ADMIN$ (Event ID 5140).
3. Narzędzia zapisują pliki do C:\Windows i uruchamiają je jako usługę (Event ID 4688).
4. Tworzenie nowej usługi rejestrowane jest jako 7045 i 7036 (stan uruchomienia).
5. `cmd.exe` uruchamia `conhost.exe` – świadczy to o dostępie interaktywnym lub zdalnym shellu (Event ID 4688). 

### Co monitorować? 
Zatem skuteczniejszym podejściem jest korelowanie zdarzeń:
* Event ID 5140 - dostęp do C$, IPC$, ADMIN$ - szczegółnie ze stacji roboczych. 
* Event ID 7045 - tworzenie nowych usług. 
* Event ID 4688 - Nietypowe ciągi wywołań procesów: `tnHcQtqr.exe` → `cmd.exe` → `conhost.exe`. 
Dopiero zestawienie ich ze sobą i analiza kontekstu źródłowego IP, konta oraz procesu daje szansę na detekcję.

## Podsumowanie

Wnioski z testów są jednoznaczne — samo zdarzenie 4624 nie stanowi wiarygodnego wskaźnika ataku Pass-the-Hash. W nowoczesnych środowiskach domenowych, gdzie NTLM jest nadal wykorzystywany, takie logowania są częste i niekoniecznie złośliwe. Różnica sprowadza się często tylko do adresu źródłowego.

Poleganie wyłącznie na zdarzeniach 4624 może wprowadzać w błąd i budować fałszywe poczucie bezpieczeństwa. Skuteczna detekcja wymaga korelacji wielu zdarzeń, znajomości środowiska oraz zrozumienia technik wykorzystywanych przez narzędzia atakujących.
