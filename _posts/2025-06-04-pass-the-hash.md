---
layout: post
title:  "Mit detekcji Pass-the-Hash – co naprawdę mówią logi 4624"
date:   2025-06-04 18:29:56 +0300
categories: Windows, Server, Logs, Detection 
---

## Wstęp
W ostatnim czasie postanowiłem rozszerzyć swoją wiedzę w temacie ataków na Active Directory o których wiele słyszałem, lecz brakowało mi praktycznego doświadczenia w roli atakującego. Uznałem, że będzie to idealna okazja do rozszerzenia wiedzy i wykorzystania środowiska testowego, które ostatnio przygotowałem.

Kilka dni temu przerabiałem pokój o nazwie "Threat Hunting: Pivoting" na platformie [TryHackMe](https://tryhackme.com), w którym omówiony był sposób detekcji ataku Pass-The-Hash. Każdy, kto odrobine interesuje się cyberbezpieczeństwem zapewne o tym ataku słyszał, a w Internecie temat wydaje się wyczerpany i przebadany na wszystkie sposoby. Brzmi jak sztampowy przykład do sprawdzenia, metody ataku opisane wiele razy, sposób detekcji również, powinno pójść gładko i bez niespodzianek, prawda?

## Sposoby detekcji
Wykonałem zapytanie do Google'a ("how to detect pass the hash in windows logs") w celu zorientowania się czego powinienem szukać w logach w celu wykonania ataku i co się okazuje, Internet nie jest zgodny co do sposobu wykrywania ataku. Wiele źródeł opisuje, że wykrywa się go w zdarzeniu 4624, ale różnice są w szczegółach. Większość detekcji opiera się na poniższych założeniach: 
* Event ID: 4624
* Logon Type: 3 (Network) 
* LogonProcessName: NtLmSsp
* KeyLength: 0 

Są również takie, które sugerują, że Pth wykryjemy poniższą detekcją:
* 4624 events on your workstations with:
* Logon Type = 9 (NewCredentials)
* Authentication Package = Negotiate
* Logon Process = seclogo

Oba przykłady są bardzo konkretne, ale czy to wystarczy do złapania tego ataku? Zobaczmy jak to wygląda w praktyce. Oto plan:

1. Zasymulowanie normalnego logowania za pomocą NTLM. 
2. Przeprowadzenie ataku Pth z maszyny kali. 
3. Porównanie wygenerowanych logów. 

## Opis środowiska testowego

Środowisko testowe, które przygotowałem do tego typu testów składa się z:
* Windwos Server Datacenter 2022 (OsVersion 10.0.20348) w roli kontrolera domeny.
* PC-01 - Windows 11 Enterprise
* Kali linux

Dodatkowo, w celu wspomagania procesu testowania środowisko wyposażone jest w: 
* Serwer Ubuntu z Arkime, który zbiera pcap ze wszystkich maszyn oraz generuje logi Zeek. 
* Serwer Ubuntu z statkiem ELK, który zbiera logi z Zeeka oraz z hostów za pomocą winlogbeatów. 
                            
W tym momencie warto zaznaczyć, ze opisane w dalszej części wyniki nie muszą być prawdziwe dla wszystkich (szczególnie poprzednich) wersji Windowsów.  

## Opis ataku Pass-the-hash

Atak Pass the Hash polega na wykorzystaniu wcześniej pozyskanego hashu hasła konta domenowego/lokalnego do zalogowania się za jego pomocą do innego komputera/serwera celem przeprwoadzenia np. tzw latteral movement w środowisku domenowym. Atak jest możliwy, ze względu na sposób działania procesu "challenge-response" w protokole NTLM. 


## Poprawne logowania a atak pass the hash
            
Ponieważ wykorzystywany jest tutaj protokół NTLM, jest to dobry wskaźnik jeżeli chodzi o sposób wykrywania ataku, ponieważ interaktywne logowania (czyli takie w których użytkownikowi prezentowany jest ekran pulpitu) wykorzystują protokół Kerberos. Można to łatwo zaobserwować w zdarzeniach 4624. Niestety, protokół NTLM jest powszechnie wykorzystywany w środowisku domenowych i nie wszystkie logowania z wykorzystaniem tego protokołu wskazują na atak, a raczej większość z nich atakiem nie jest. 
Zdarzenia 4624 świadczące o logowaniu protokołem zostaną wygenerowane np. W przypadku uzyskania dostępu do zasobów sieciowych w domenie. Można to zrobić za pomocą explorer.exe lub cmd.exe komendą 
{% highlight cmd%}
Net use \\10.10.10.1\c$
{% endhighlight %}

Dokonałem dostępu do mojego zasobu sieciowego za pomocą obu tych opcji i sprawdziłem zdarzenia 4624 dla tych logowań, wyniki przedstawiam poniżej na screenach. Proszę zwrócić uwagę na: 
```
Logon Process: NtLmSsp
Authentication Package: NTLM
Package Name (NTLM only): NTLM v2
```
 

### Przykład uzyskania dostępu do zasobu za pomocą komendy "net use" oraz odpowiadający log

<img src="/assets/images/post1/net_use.png" alt="Wykonanie komendy net use" width="600">
<img src="/assets/images/post1/net_use_4624_event.png" alt="Event 4624 wywołany podczas dostępu do sharea za pomocą komendy net use" width="600">
            
### Przykład z uzyskania dostępu do zasobu sieciowego za pomocą explorera. 
<img src="/assets/images/post1/explorer_share_access.png" alt="Event 4624 wywołany podczas dostępu do sharea za pomocą komendy net use" width="600">
<img src="/assets/images/post1/explorer_share_access_event_4624.png" alt="Event 4624 wywołany podczas dostępu do sharea za pomocą komendy net use" width="600">
            

## Przeprowadzenie ataku Pass-the-hash

Wiem jak wyglądają logi z nieszkodliwego logowania NTLM, czas zobaczyć jak wyglądają w przypadku ataku Pass-The-Hash. Oczywiście do przeprowadzenia ataku potrzebny jest hash hasła użytkownika. Ja pozyskałem hash poprzez przeprowadzenie ataku DCSYNC za pomocą oprogramowania mimikatz uruchomionego na hoście w domenie. Dla uproszczenia wyłączyłem Windows Defendera (który skutecznie wykrywa i blokuje ogólnodostępną wersję mimikatza) a program uruchomiłem z konta administratora domeny. 

Komenda użyta do przeprowadzenia dcsync: 
```
lsadump::dcsync /user:Labo\l.skwyalker 
	- Labo - to nazwa domeny testowej, l.skywaker to użytkownik. 
```
Pozyskany hash skopiowałem do systemu Kali, gdzie wykorzystałem narzędzia impacket-smbexec do przeprowadzenia ataków. Smbexec wykorzstuje protokół SMB do wykonania zdalnych komend na wybranej stacji. SMB to ten sam protokół, który pozwala na udostępnianie zasobów sieciowych w środowisku domenowym. Oznacza to, ze do logowania najprawdopodobniej zostanie wykorzystany protokół NTLM, co będzie można zobaczyć w logu 4624. Najpierw przeprowadziłem atak na stację roboczą PC-01. 

Komendy na kalim

<img src="/assets/images/post1/pth_to_pc01.png" alt="Terminal maszyny Kali z komendą do wykonania ataku pth z użyciem impacket-smbexec" width="600">

Event 4624 ze stacji PC-01. Na kontrolerze domeny zdarzenie 4624 o logowaniu do komputera PC-01 nie zostało wygenerowane. 
<img src="/assets/images/post1/4624_pth_on_pc01.png" alt="Event 4624 wywołany w momencie wykonania ataku PTH za pomocą impacket-smbexec" width="600">


Ok, czas na zaatakowanie kontrolera domeny. Narzędzie impacket smbexec wykorzystuje protokół SMB do wykonania poleceń na zdalnym komputerze. Jak wiemy, 
Komendy na kalim.

<img src="/assets/images/post1/smbexec_pth_to_dc.png" alt="Komenda do wykonania ataku PTH na kontroler domeny" width="600">

Poniżej zdarzenia z dziennika Security na kontrolerze domeny. 
<img src="/assets/images/post1/smbexec_pth_na_dc_4624.png" alt="log 4624 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">
<img src="/assets/images/post1/psexec_pth_on_dc_5140_share_access.png" alt="log 5140 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">
<img src="/assets/images/post1/smbexec_pth_na_dc_4688_1.png" alt="log 4688 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">
<img src="/assets/images/post1/smbexec_pth_na_dc_4688_2.png" alt="log 4688 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">
<img src="/assets/images/post1/smbexec_pth_na_dc_4688_3.png" alt="log 4688 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">

Ponownie, log 4624 wygląda te wygenerowane podczas normalne aktywności. Tym razem można zaobserwować ciekawe logi 4688, które świadczą o tym, że wydarzyło się coś ciekawego. 

No dobra, ale co ze wskaźnikami odnoszącymi się do zdarzenia 4624, które znalazłem w Internecie, część z nich nie występuje, a część występuje w normalnej aktywności, nie pozwala to na zbudowanie detekcji. 

Dla dodatkowego upewnienia się przeprowadzić ten sam atak ponownie, z wykorzystaniem impacket-psexec.

<img src="/assets/images/post1/psexec_pth_na_dc.png" alt="log 4624 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">
<img src="/assets/images/post1/psexec_pth_on_dc_5140_share_access.png" alt="log 5140 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">
<img src="/assets/images/post1/psexec_pth_on_dc_4688_1.png" alt="log 4688 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">
<img src="/assets/images/post1/psexec_pth_on_dc_4688_2.png" alt="log 4688 wygenerowany na kontrolerze domeny po udanym ataku pth" width="600">

Znów to samo, brak różnicy w logach. 


## Jak właściwie zbudowac detekcję? 

Wykorzystując wiedzę o działaniu narzędzi impacket psexec.py i smbexec.py oraz przeglądając zebrane logi przeanalizujmy co dzieje się na atakowanych stacjach: 

1. Wykradziony hash zostaje wykorzystany do uwierzytelnienia się do stacji (event 4624).
2. Narzędzie uzyskuje dostęp do usługi IPC$ (log 5140 w przypadku psexec).
3. Zarówno psexec(plik exe) jak i smbexec (plik bat) zapisują pliki w C$ (czyli C:\Windows) a następnie wykorzystuja je do uruchomienia usługi na kontrolerze domeny (logi 4688).
4. Utworzenie nowej usługi powinno zostać odłozone w logu 7036 w dzienniku SYSTEM i faktycznie tak sie stało (screeny ponizej). 

### Logi potwierdzające utworzenie nowej usługi na DC
<img src="/assets/images/post1/smbexec_new_service_7045.png" alt="log 7045 wygenerowany na kontrolerze domeny po udanym ataku pth z impacket-smbexec.py" width="600">
<img src="/assets/images/post1/psexec_new_service_7045.png" alt="log 7045 wygenerowany na kontrolerze domeny po udanym ataku pth z impacket-psexec.py" width="600">

5. Cmd.exe uruchamia process conchost.exe co oznacza zdalne wykonanie komendy lub otworzenie zdalnej interaktywnej sesji. (logi 4688)

Co więc warto monitorować? 
* Event ID 5140 - dostęp do C$, IPC$, ADMIN$ - szczegółnie ze stacji roboczych. 
* Event ID 7036 - tworzenie nowych usług. 
* Event ID 4688 - podejrzane uruchomienia procesów ( przykład z naszego testu tnHcQtqr.exe > cmd.exe  > conhost.exe ). 

            
## Podsumowanie

Jak widać sposoby detekcji Pass-the-hash oparte na logu 4624 nie sprawdzają się w nowoczesnych środowiskach domenowych. Jedyna zaobserwowana różnica to adres źródłowy, który zmienił się, ponieważ atak wykonałem z maszyny z zainstalowanym Kali, ale nic nie stoi na przeszkodzie, żeby to samo wykonać ze skompromitowanej stacji roboczej. 

Opieranie się wyłącznie na zdarzeniach 4624 może nie przynieść zamierzonych skutków, a jedynie zbudować fałszywe poczucie bezpieczeństwa w organizacji. 

Wierzę, że autorzy artykułów i reguł detekcji opierający się na logach 4624 wykonali rzetelną pracę i prawdopodobnie te metody sprawdzały się w poprzednich wersjach systemów Windows lub w innych konfiguracjach środowiska. 

