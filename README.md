# Skilled Threat Analyzer

An interactive Python CLI security suite for network scanning, log analysis, configuration auditing, and threat detection.

## Features

* **Network Scanner (Socket & Nmap):** Multi-threaded port scanning with banner grabbing and automated Nmap script execution.
* **Log Analyzer:** Parses SSH `auth.log`, Nginx access logs, and system logs to flag potential brute-force attempts.
* **Config Security Linter:** Scans local directories for exposed secrets, weak SSH setups, insecure Docker configurations, and plain-text `.env` keys.
* **Traffic & DoS Detector:** Leverages `tshark` packet captures and socket inspections to identify high-volume connection anomalies and potential flood attacks.
*

# Skilled Threat Analyzer

ინტერაქტიული Python CLI უსაფრთხოების ინსტრუმენტი ქსელის სკანირების, ლოგების ანალიზის, კონფიგურაციის აუდიტისა და საფრთხეების გამოვლენისთვის.

## ფუნქციები

* **ქსელის სკანერი (Socket & Nmap):** მრავალნაკადიანი პორტების სკანირება ბანერების ამოღებითა და Nmap სკრიპტების ავტომატიზებული შესრულებით.
* **ლოგების ანალიზატორი:** ახდენს SSH `auth.log`-ის, Nginx-ის წვდომის ლოგებისა და სისტემური ლოგების პარსინგს სავარაუდო Brute-force შეტევების გამოსავლენად.
* **კონფიგურაციის უსაფრთხოების ლინტერი (Linter):** სკანირებს ლოკალურ დირექტორიებს გაჟონილი საიდუმლო გასაღებების (secrets), სუსტი SSH კონფიგურაციების, დაუცველი Docker პარამეტრებისა და ღია `.env` ფაილების აღმოსაჩენად.
* **ტრაფიკისა და DoS შეტევების დეტექტორი:** იყენებს `tshark` პაკეტების ჩაჭრასა და სოკეტების ინსპექტირებას მაღალი მოცულობის ანომალიური კავშირებისა და შესაძლო Flood შეტევების იდენტიფიცირებისთვის.
