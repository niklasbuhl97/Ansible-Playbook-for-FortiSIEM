# Ansible-Plugin-for-FortiSIEM
# 25.01.2024 V1.0

Dieses Repository enthält [1] einen Mockup-Server, der das Verhalten von FortiSIEM emuliert.
Dabei werden [2] Beispielantworten auf dedizierte Abfragen generiert.
Die Abfragen (query) eruiert das [3] Ansible-Plugin.
Das [4] Ansible-Playbook verweist mit Angabe von "appServer"; "username"; "password" und "query" auf das Ansible Plugin um die Abfrage auszuführen.

Das Ergebnis der Abfrage wird in results gespeichert und kann als register weiter in Playbooks verwendet werden.
