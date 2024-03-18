# Ansible-Plugin-for-FortiSIEM
# 18.03.2024 V2.0

Dieses Repository enthält [1] einen Mockup-Server, der das Verhalten einer API von FortiSIEM emuliert.
Dabei werden [2] Beispielantworten auf dedizierte Abfragen generiert.
Die Abfragen (queries) eruiert das Ansible-Plugin [3].
Das [4] Ansible-Playbook verweist mit Angabe von "appServer"; "username"; "password" und "query" auf das Ansible Plugin um die Abfrage auszuführen.

Mögliche Beispielabfragen die als "query" im Ansible Playbook verwendet werden können sind "malicious site".
Das Ergebnis der Abfrage wird in results gespeichert und kann als register weiter in Playbooks verwendet werden.

[1] Mockup-Server: FortiSIEM-Mockup
[2] Beispielantworten: 050601.xml & 171493.xml
[3] Ansible Plugin: fortisiem_query.py
[4] Ansible Playbook: siem_query.yml
