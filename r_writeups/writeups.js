// Datos de writeups
const writeups = [
  {
    name: "Eighteen",
    os: "windows",
    difficulty: "easy",
    status: "active",
    techniques: "Este writeup se publicará una vez la máquina sea retirada, conforme a las normativas de HackTheBox",
    date: "2026-01-06",
    link: "#",
    image: "../images/htb/Eighteen.png"
  },
  {
    name: "MonitorsFour",
    os: "windows",
    difficulty: "easy",
    status: "active",
    techniques: "Este writeup se publicará una vez la máquina sea retirada, conforme a las normativas de HackTheBox",
    date: "2026-01-06",
    link: "#",
    image: "../images/htb/MonitorsFour.png"
  },
  {
    name: "Gavel",
    os: "linux",
    difficulty: "medium",
    status: "active",
    techniques: "Este writeup se publicará una vez la máquina sea retirada, conforme a las normativas de HackTheBox",
    date: "2026-01-06",
    link: "#",
    image: "../images/htb/Gavel.png"
  },
  {
    name: "Fries",
    os: "windows",
    difficulty: "hard",
    status: "active",
    techniques: "Este writeup se publicará una vez la máquina sea retirada, conforme a las normativas de HackTheBox",
    date: "2026-01-06",
    link: "#",
    image: "../images/htb/Fries.png"
  },
  {
    name: "WhiteRabbit",
    os: "linux",
    difficulty: "insane",
    status: "retired",
    techniques: "Subdomain Enumeration, Advanced Directory Fuzzing, Uptime Kuma Analysis, HMAC Signature Generation, Blind SQL Injection, Database Enumeration, Restic Backup Exploitation, 7z Archive Password Cracking, SSH Key Extraction, Container Escape via Restic Sudo Abuse, Time-based PRNG Password Generation Analysis, Custom Password Dictionary Generation, SSH Brute Force, Privilege Escalation via Sudo",
    date: "2026-01-08",
    link: "../writeups/view/WhiteRabbit",
    image: "../images/htb/WhiteRabbit.png"
  },
  {
    name: "Soulmate",
    os: "linux",
    difficulty: "easy",
    status: "active",
    techniques: "Este writeup se publicará una vez la máquina sea retirada, conforme a las normativas de HackTheBox",
    date: "2026-01-06",
    link: "#",
    image: "../images/htb/Soulmate.png"
  },
  {
    name: "Imagery",
    os: "linux",
    difficulty: "medium",
    status: "retired",
    techniques: "XSS (Cross-Site Scripting), Cookie Hijacking, Admin Session Theft, LFI (Local File Inclusion), Database Enumeration (db.json), Command Injection via ImageMagick Convert, Python Reverse Shell, AES File Decryption (pyAesCrypt), Password Cracking (MD5), Sudo Privilege Abuse (charcol), Cron Job Manipulation, Root Flag Extraction via Scheduled Task",
    date: "2026-01-28",
    link: "../writeups/view/Imagery",
    image: "../images/htb/Imagery.png"
  },
  {
  name: "HackNet",
  os: "linux",
  difficulty: "medium",
  status: "retired",
  techniques: "Django SSTI (Server-Side Template Injection), User Enumeration via Likes Feature, Password Extraction via SSTI, SSH Access, Django Cache Poisoning, Pickle Deserialization Attack, GPG Key Cracking (gpg2john), GPG Encrypted Backup Decryption, MySQL Root Password Extraction from SQL Backup",
  date: "2026-01-20",
  link: "../writeups/view/HackNet",
  image: "../images/htb/HackNet.png"
  },
  {
    name: "Browsed",
    os: "linux",
    difficulty: "medium",
    status: "active",
    techniques: "Este writeup se publicará una vez la máquina sea retirada, conforme a las normativas de HackTheBox",
    date: "2026-01-13",
    link: "#",
    image: "../images/htb/Browsed.png"
  },
  {
    name: "Conversor",
    os: "linux",
    difficulty: "easy",
    status: "active",
    techniques: "Este writeup se publicará una vez la máquina sea retirada, conforme a las normativas de HackTheBox",
    date: "2026-01-06",
    link: "#",
    image: "../images/htb/Conversor.png"
  },
  {
    name: "CodePartTwo",
    os: "linux",
    difficulty: "easy",
    status: "active",
    techniques: "Este writeup se publicará una vez la máquina sea retirada, conforme a las normativas de HackTheBox",
    date: "2026-01-06",
    link: "#",
    image: "../images/htb/CodePartTwo.png"
  },
  {
    name: "Era",
    os: "linux",
    difficulty: "medium",
    status: "retired",
    techniques: "Subdomain Enumeration, IDOR (Insecure Direct Object Reference), SQLite Database Exploitation, Bcrypt Hash Cracking, SSRF (Server-Side Request Forgery), FTP Access, PHP Wrapper Exploitation (ssh2.exec), ELF Binary Signature Manipulation, Cron Job Abuse, SUID Privilege Escalation",
    date: "2026-01-08",
    link: "../writeups/view/Era",
    image: "../images/htb/Era.png"
  },
  {
    name: "Outbound",
    os: "linux",
    difficulty: "easy",
    status: "retired",
    techniques: "Roundcube RCE (CVE-2025-49113), MySQL Database Enumeration, 3DES Password Decryption, Docker Container Escape, CVE-2025-27591 (Below Log Manipulation), Symlink Attack",
    date: "2026-01-08",
    link: "../writeups/view/Outbound",
    image: "../images/htb/Outbound.png"
  },
  {
  name: "Guardian",
  os: "linux",
  difficulty: "hard",
  status: "active",
  techniques: "Este writeup se publicará una vez la máquina sea retirada, conforme a las normativas de HackTheBox",
  date: "2026-01-20",
  link: "#",
  image: "../images/htb/Guardian.png"
  },
  {
  name: "Expressway",
  os: "linux",
  difficulty: "easy",
  status: "active",
  techniques: "Este writeup se publicará una vez la máquina sea retirada, conforme a las normativas de HackTheBox",
  date: "2026-01-20",
  link: "#",
  image: "../images/htb/Expressway.png"
  },
  {
  name: "Previous",
  os: "linux",
  difficulty: "medium",
  status: "retired",
  techniques: "Port Scanning, Web Enumeration, NextJS Middleware Authentication Bypass (CVE-2025-29927), Protected Route Access, JavaScript Chunk Analysis, API Enumeration, Local File Inclusion (LFI), NextAuth Configuration Disclosure, Credential Extraction, SSH Access, Sudo Misconfiguration, Terraform Provider Override Abuse, Privilege Escalation to Root",
  date: "2026-01-10",
  link: "../writeups/view/Previous",
  image: "../images/htb/Previous.png"
  },
  {
  name: "Cobblestone",
  os: "linux",
  difficulty: "insane",
  status: "active",
  techniques: "Este writeup se publicará una vez la máquina sea retirada, conforme a las normativas de HackTheBox",
  date: "2026-01-28",
  link: "#",
  image: "../images/htb/Cobblestone.png"
  },
  {
  name: "Overwatch",
  os: "windows",
  difficulty: "medium",
  status: "active",
  techniques: "Este writeup se publicará una vez la máquina sea retirada, conforme a las normativas de HackTheBox",
  date: "2026-01-28",
  link: "#",
  image: "../images/htb/Overwatch.png"
  }

];

let filteredWriteups = [...writeups];

function renderWriteups() {
  const container = document.getElementById('writeupsList');
  const resultCount = document.getElementById('resultCount');

  resultCount.textContent = filteredWriteups.length;

  requestAnimationFrame(() => {
    if (filteredWriteups.length === 0) {
      container.innerHTML = `<div class="writeups-empty"> <p>No se encontraron writeups con los filtros seleccionados.</p> </div>`;
      return;
    }

    container.innerHTML = filteredWriteups.map(writeup => `
      <div class="writeup-card">
        <div class="writeup-image">
          ${writeup.image 
            ? `<img src="${writeup.image}" alt="${writeup.name}" onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
               <span class="writeup-image-fallback" style="display:none;">${writeup.name[0]}</span>`
            : `<span class="writeup-image-fallback">${writeup.name[0]}</span>`
          }
        </div>
        <div class="writeup-content">
          <div class="writeup-tags">
            <span class="tag os-${writeup.os}">${writeup.os}</span>
            <span class="tag difficulty-${writeup.difficulty}">${writeup.difficulty}</span>
            <span class="tag status-${writeup.status}">${writeup.status === 'active' ? 'Activa' : 'Retirada'}</span>
          </div>
          <h3 class="writeup-title">${writeup.name}</h3>
          <div class="writeup-techniques">${writeup.techniques}</div>
          <div class="writeup-footer">
            <span class="writeup-date">${writeup.status === 'active' ? 'Próximamente' : formatDate(writeup.date)}</span>
            ${writeup.status === 'active' 
              ? '<span class="writeup-link disabled">No disponible</span>'
              : `<a href="${writeup.link}" class="writeup-link">Ver Writeup →</a>`
            }
          </div>
        </div>
      </div>
    `).join('');
  });
}


function formatDate(dateStr) {
  const date = new Date(dateStr);
  const options = { year: 'numeric', month: 'short', day: 'numeric' };
  return date.toLocaleDateString('es-ES', options);
}

function applyFilters() {
  const status = document.getElementById('statusFilter').value;
  const difficulty = document.getElementById('difficultyFilter').value;
  const os = document.getElementById('osFilter').value;
  const sort = document.getElementById('sortFilter').value;

  filteredWriteups = writeups.filter(writeup => {
    const statusMatch = status === 'all' || writeup.status === status;
    const difficultyMatch = difficulty === 'all' || writeup.difficulty === difficulty;
    const osMatch = os === 'all' || writeup.os === os;
    return statusMatch && difficultyMatch && osMatch;
  });

  filteredWriteups.sort((a, b) => {
    const dateA = new Date(a.date);
    const dateB = new Date(b.date);
    return sort === 'desc' ? dateB - dateA : dateA - dateB;
  });

  renderWriteups();
}

// Inicializar event listeners para los filtros
function initFilters() {
  document.getElementById('statusFilter').addEventListener('change', applyFilters);
  document.getElementById('difficultyFilter').addEventListener('change', applyFilters);
  document.getElementById('osFilter').addEventListener('change', applyFilters);
  document.getElementById('sortFilter').addEventListener('change', applyFilters);
}

// Inicializar la página
document.addEventListener('DOMContentLoaded', () => {
  initFilters();
  applyFilters();
});
