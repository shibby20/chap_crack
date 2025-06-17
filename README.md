# chap_crack

CHAP Cracker to wielowątkowy program w C++ do łamania haseł uwierzytelniania CHAP (Challenge-Handshake Authentication Protocol) na podstawie przechwyconych danych: ID, CHALLENGE i RESPONSE.

Program wykorzystuje brute-force do generowania i testowania haseł o wzorze:
5 małych liter + 3 cyfry (np. abcde123), co daje ~11 miliardów możliwych kombinacji.


Jak działa?

CHAP używa funkcji:
MD5(ID + hasło + challenge)

Program generuje wszystkie możliwe hasła w formacie aaaaa000 do zzzzz999, oblicza hash MD5 i porównuje go z podanym RESPONSE.


Przykład działania

CHAP ID (2 znaki hex): 05
CHALLENGE (32 znaki hex): a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
RESPONSE (32 znaki hex): deadbeef0123456789abcdef11223344
Liczba wątków (ENTER = max): [ENTER]
[*] Startujemy z 8 wątkami
[LOG] Sprawdzone: 5,400,000 | Szybkość: 2.70 MH/s | Ostatnie hasło: afkmp205
[!] ZNALEZIONO HASŁO: apple123

Kompilacja

Wymagane:
    Kompilator C++17+
    Biblioteka OpenSSL (do MD5)

Linux / macOS
g++ chap_crack.cpp -o chap_crack -static -static-libgcc -static-libstdc++ -lssl -lcrypto -pthread

Dane wejściowe 
    CHAP ID — 1 bajt w postaci 2 znaków hex (np. 05)
    CHALLENGE — 16 bajtów (32 znaki hex)
    RESPONSE — 16 bajtów (32 znaki hex)
    Liczba wątków — opcjonalna, ENTER = automatycznie wykryta liczba rdzeni


Uwaga prawna

Program przeznaczony wyłącznie do celów edukacyjnych i testowych — np. testowania bezpieczeństwa własnych systemów. Użycie na systemach, do których nie masz uprawnień, może być nielegalne.
