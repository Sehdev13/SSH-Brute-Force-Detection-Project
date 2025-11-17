# SSH-Brute-Force-Detection-Project

## Objective

The purpose of this project was to simulate an SSH brute force attack within a controlled environment and analyze how different monitoring tools detect, record, and present attack-related activity. This project demonstrates the process of identifying attack indicators, reviewing logs, using network analysis tools, and evaluating which monitoring solutions provide actionable visibility during an intrusion.

## Project Overview

This project involved launching a brute force attack from an attacker machine (192.168.16.17) against a web host (192.168.16.4) using SSH on port 22. Multiple logs, dashboards, and monitoring systems were used to track the attack. The goal was to understand how brute force attacks appear in various system logs, how to manually investigate them, and how log-management tools visualize the attack patterns.

### Skills Learned

- Understanding how brute force attacks appear in system logs.
- Ability to analyze /var/log/auth.log and syslog entries for SSH authentication attempts.
- Hands-on experience using Logwatch, LogAnalyzer, tcpdump, and SNMP monitoring tools.
- Distinguishing which monitoring systems detect attacks and which require custom rules.
- Strengthened investigation, documentation, and attack-tracking methodology.

## Tools Used

- **Hydra** – automated password-guessing tool used for SSH brute-force testing  
- **Logwatch** – log analysis tool summarizing SSH failures and activity  
- **LogAnalyzer** – real-time log viewing for SSH authentication failures  
- **SNMP Traps** – monitored device events such as reboots, but not SSH failures  
- **LibreNMS** – network monitoring tool displaying system events and SNMP traps  

## Steps & Evidence

1. **Attack Setup & Preparation**

   Explanation:
   A controlled lab environment was created to simulate an SSH brute force attack.  
   Components included:  
   - Attacker: Kali Linux (192.168.16.17)  
   - Target: WebHost (192.168.16.4)  
   - Wordlist: Custom passlist.txt  
   - Tool: Hydra for automated password attempts  

   This environment mimicked a real-world scenario where an attacker targets exposed SSH services.

2. **Attack Execution with Hydra**
   
   <img width="3003" height="1688" alt="image" src="https://github.com/user-attachments/assets/79424ef1-c121-459e-ac6e-4af2d9fd257e" />


   Explanation:
   The brute force attack was launched from Kali using Hydra.  
   **Command Used:**  
   `hydra -l sehdev -P passlist.txt ssh://192.168.16.4`

   Hydra attempted thousands of SSH login combinations using a multithreaded approach.  
   The tool eventually discovered valid credentials:

   - Username: sehdev  
   - Password: sehdev
  
3. **First Evidence of Attack in Logs**

   <img width="3000" height="1688" alt="image" src="https://github.com/user-attachments/assets/965200f8-f3ba-4928-9f47-5c4b24f9c5e4" />

   **Explanation:**  
   The earliest signs of brute force activity appeared in `/var/log/auth.log`, showing:

   - Repeated failed logins
   - Attack targeted SSH on port **22**  
   - Username targeted: **sehdev**  
   - Attacker IP: **192.168.16.17**

   This confirmed continuous unauthorized access attempts.

4. **Logwatch – SSHD Report**
   
    <img width="3000" height="1688" alt="image" src="https://github.com/user-attachments/assets/3872156e-a1a1-482b-ade0-4f3b6ce31d70" />

   **Explanation:**  
   Logwatch detected suspicious SSH activity and summarized:

   - Multiple repeated failed SSH login attempts  
   - All attempts targeted the user **sehdev**  
   - Attempts originated from the attacker IP **192.168.16.17**  
   - Logwatch flagged these entries as part of its SSHD summary  

   This helped identify the brute-force pattern early.

5. **Logwatch – pam_unix Report**

    <img width="3000" height="1688" alt="image" src="https://github.com/user-attachments/assets/7db7ac50-accd-4be2-ad5b-643d50502a1a" />

   **Explanation:**  
   The Logwatch `pam_unix` section showed:

   - Repeated authentication failures for SSH  
   - Frequent failed password attempts targeting **sehdev**  
   - Evident brute-force pattern due to rapid repeated failures  
   - Extra login/session messages providing additional context  

   This added another layer of confirmation that brute-force activity was occurring.

6. **LogAnalyzer – Real-Time SSH Failure Logs**
   
   <img width="2984" height="1687" alt="image" src="https://github.com/user-attachments/assets/324a0ae5-59e7-4c4e-a88e-a6484c149551" />

   **Explanation:**  
   LogAnalyzer provided real-time visibility into the attack:

   - Flood of failed login attempts  
   - IP: **192.168.16.17**  
   - User targeted: **sehdev**  
   - Timestamped entries showing continuous activity  

   This tool clearly captured the attack as it happened.


7. **tcpdump – Packet Capture of SSH Attempts**

   <img width="3000" height="1688" alt="image" src="https://github.com/user-attachments/assets/a9b71e6d-2f45-4118-bef5-638c23923d88" />


   **Explanation:**  
   tcpdump captured live SSH traffic during the brute-force attack:

   - Constant TCP SYN packets to port **22**  
   - Shows brute-force traffic at the network level  
   - Confirms the attack was actively hitting the server  


9. **SNMP Trap Logs**

    <img width="3000" height="1688" alt="image" src="https://github.com/user-attachments/assets/bd12c62b-fe36-444a-bf49-073aacd75fa3" />


    **Explanation:**  
    SNMP trap logs recorded:

    - System boot messages  
    - Device status changes  

    However, SNMP did **not** detect brute-force activity, showing it is not suitable for authentication-level monitoring.


11. **LibreNMS Event Log**

    <img width="3000" height="1687" alt="image" src="https://github.com/user-attachments/assets/e17d0300-d0c8-4046-8721-5d85eb640536" />

    **Explanation:**  
    LibreNMS captured:

    - System reboot events  
    - SNMP trap notifications  

    But similar to SNMP traps, it did **not** log any SSH brute-force attempts, indicating limited detection capability without custom alerting.


13. **Attack Prevention & Mitigation**

    **Explanation:**  
    To prevent future SSH brute-force attacks, several mitigation strategies were identified:

    - **Fail2ban / Account Lockout Policies**  
    - **Strong Passwords & SSH Key-Based Authentication**  
    - **Limit SSH Access by IP**  
      (via `hosts.allow`, `hosts.deny`, or firewall rules)  
    - **Change Default SSH Port**  
      (security-by-obscurity, but reduces noise from bots)

    Implementing these controls reduces exposure and increases detection accuracy.


   

