/* qeli panel i18n — DOM-translation layer.
 *
 * Localisation without rewriting every template string: the panel ships in
 * English; this walks the rendered DOM and swaps text/placeholder/title against a
 * per-language dictionary keyed by the exact English string (HTML entities are
 * already decoded in the live DOM, so keys use & < > etc.). Missing keys fall
 * back to English, so a partial dictionary is safe. A MutationObserver keeps
 * Alpine-rendered content translated. PATTERNS handle interpolated counters.
 *
 * Add a language: append it to LANGS and add a dictionary under DICT (+ optional
 * PATTERNS). That's it.
 */
(function () {
  const LANGS = [
    { code: 'en', name: 'English' },
    { code: 'ru', name: 'Русский' },
  ];

  // Regex fallbacks for strings with embedded values (tried after exact match).
  const PATTERNS = {
    ru: [
      [/^(\d+) users$/, '$1 польз.'],
      [/^(\d+) lines$/, '$1 строк'],
      [/^(\d+) entries$/, '$1 записей'],
      [/^(\d+) outbound profile\(s\)$/, '$1 исходящих профилей'],
    ],
  };

  // English-string -> translation. 'en' is identity (no entry needed).
  const DICT = {
    ru: {
      // ── chrome / nav ──
      'Dashboard': 'Панель',
      'Users': 'Пользователи',
      'Config': 'Конфигурация',
      'Configuration': 'Конфигурация',
      'Client': 'Клиент',
      'Client connections': 'Клиентские подключения',
      'Logs': 'Журнал',
      'Log out': 'Выйти',
      'Server online': 'Сервер онлайн',
      'Server offline': 'Сервер офлайн',
      'Total clients:': 'Всего клиентов:',
      'Auto-refresh': 'Автообновление',
      'Language': 'Язык',
      'Qeli VPN': 'Qeli VPN',

      // ── login ──
      'Admin panel': 'Панель администратора',
      'Username': 'Имя пользователя',
      'Password': 'Пароль',
      'Sign in': 'Войти',
      'Qeli VPN · secure management': 'Qeli VPN · защищённое управление',
      'Enter a username and password': 'Введите имя пользователя и пароль',
      'Sign in failed': 'Не удалось войти',
      'Invalid username or password': 'Неверное имя пользователя или пароль',

      // ── dashboard: quick start ──
      'Quick start — launch a server in one click': 'Быстрый старт — запуск сервера в один клик',
      'Builds a ready profile, applies it & restarts the server': 'Создаёт готовый профиль, применяет и перезапускает сервер',
      'Pick a masking mode — we configure TUN, NAT, DNS, the IP pool and obfuscation, then bring the server up. After that, add users.':
        'Выберите режим маскировки — мы настроим TUN, NAT, DNS, пул IP и обфускацию, затем поднимем сервер. После — добавьте пользователей.',
      'flagship': 'флагман',
      'REALITY': 'REALITY',
      'HTTPS (fake-TLS)': 'HTTPS (fake-TLS)',
      'Obfuscated': 'Обфускация',
      'QUIC (UDP)': 'QUIC (UDP)',
      'Genuine TLS 1.3 — looks like a real HTTPS site, beats active probing.':
        'Настоящий TLS 1.3 — выглядит как реальный HTTPS-сайт, устойчив к активному зондированию.',
      'Mimics a TLS 1.3 handshake. Near-zero overhead — the default mode.':
        'Имитирует рукопожатие TLS 1.3. Почти без накладных расходов — режим по умолчанию.',
      'ChaCha20 stream + WebSocket fronting. Structure-free, beats entropy DPI.':
        'Поток ChaCha20 + WebSocket-фронтинг. Без структуры, обходит энтропийный DPI.',
      'UDP datagrams shaped like QUIC / HTTP3. Lower latency for mobile.':
        'UDP-датаграммы под QUIC / HTTP3. Меньше задержка для мобильных.',
      'server is live': 'сервер запущен',
      'is running on': 'работает на',
      'REALITY short_id': 'REALITY short_id',
      'to this on every client': 'на это значение на каждом клиенте',
      'obfs pre-shared key': 'предобщий ключ obfs',
      "Clients also need the server's pinned public key — run": 'Клиентам также нужен пиннингованный публичный ключ сервера — выполните',
      'on the server. Then add users below and share a QR/link from the Users page.':
        'на сервере. Затем добавьте пользователей ниже и поделитесь QR/ссылкой со страницы «Пользователи».',
      'Open config': 'Открыть конфиг',
      'Add users': 'Добавить пользователей',
      'Close': 'Закрыть',

      // ── dashboard: stats / clients ──
      'Connected clients': 'Подключённые клиенты',
      'Active profiles': 'Активные профили',
      'Total sent': 'Отправлено всего',
      'Total received': 'Принято всего',
      'Connected Clients': 'Подключённые клиенты',
      'No clients connected': 'Нет подключённых клиентов',
      'All profiles': 'Все профили',
      'Refresh': 'Обновить',
      'Profile': 'Профиль',
      'IP Address': 'IP-адрес',
      'Uptime': 'Время в сети',
      '↑ Sent': '↑ Отпр.',
      '↓ Recv': '↓ Прин.',
      'Bandwidth': 'Полоса',
      'Actions': 'Действия',
      'Set bandwidth': 'Задать полосу',
      'Kick': 'Отключить',
      'Set Bandwidth': 'Ограничение полосы',
      'Limit (Mbps) — 0 = unlimited': 'Лимит (Мбит/с) — 0 = без лимита',
      'Apply': 'Применить',
      'Cancel': 'Отмена',
      'clients': 'клиентов',

      // ── users ──
      'Add User': 'Добавить пользователя',
      'No users configured': 'Пользователи не настроены',
      'Status': 'Статус',
      'Static IP': 'Статический IP',
      'Group': 'Группа',
      'Profiles': 'Профили',
      'Max Sessions': 'Макс. сессий',
      'Unlimited': 'Без лимита',
      'all': 'все',
      'Enable': 'Включить',
      'Disable': 'Отключить',
      'Share / QR': 'Поделиться / QR',
      'Edit': 'Изменить',
      'Delete': 'Удалить',
      'New User': 'Новый пользователь',
      'Edit User': 'Изменение пользователя',
      "(enter plaintext — we'll hash it)": '(введите открытым текстом — мы захешируем)',
      '(leave empty to keep current)': '(пусто — оставить текущий)',
      'New Password': 'Новый пароль',
      'Hash': 'Хешировать',
      'Password hashed with argon2id': 'Пароль захеширован argon2id',
      'Bandwidth limit (Mbps)': 'Лимит полосы (Мбит/с)',
      'Burst (Mbps)': 'Burst (Мбит/с)',
      '0 = unlimited': '0 = без лимита',
      '0 = same as limit': '0 = как лимит',
      '(optional)': '(необязательно)',
      'Max simultaneous sessions': 'Макс. одновременных сессий',
      '(0 = from group)': '(0 = из группы)',
      'Allowed profiles': 'Разрешённые профили',
      '(interfaces; none checked = all)': '(интерфейсы; ничего не отмечено = все)',
      'no profiles configured': 'нет настроенных профилей',
      'Allowed networks': 'Разрешённые сети',
      '(CIDR allow-list; empty = unrestricted)': '(белый список CIDR; пусто = без ограничений)',
      '+ Add network': '+ Добавить сеть',
      'Per-user routes': 'Маршруты пользователя',
      "(overrides the profile's pushed routes)": '(переопределяет проброшенные маршруты профиля)',
      '+ Add route': '+ Добавить маршрут',
      'Create User': 'Создать пользователя',
      'Save Changes': 'Сохранить',
      'Group templates': 'Шаблоны групп',
      '— defaults a user inherits unless it overrides them': '— значения по умолчанию, которые наследует пользователь, если не переопределит',
      'Add Group': 'Добавить группу',
      'No groups defined': 'Группы не заданы',
      'Bandwidth limit': 'Лимит полосы',
      'Max sessions': 'Макс. сессий',
      'New Group': 'Новая группа',
      'Group name': 'Название группы',
      '(blank = unset)': '(пусто = не задано)',
      'Allowed networks (CIDR)': 'Разрешённые сети (CIDR)',
      'Save Group': 'Сохранить группу',
      'Share connection (QR)': 'Ссылка подключения (QR)',
      'This only builds a connection link/QR for an': 'Это лишь создаёт ссылку/QR подключения для',
      'existing': 'существующего',
      'user — it does': 'пользователя — это',
      'NOT': 'НЕ',
      'change the password. The server keeps only the password hash, so you re-enter the user\'s':
        'меняет пароль. Сервер хранит только хеш пароля, поэтому вы один раз вводите',
      'current': 'текущий',
      'password once to embed it into the': 'пароль пользователя, чтобы вшить его в',
      'link.': 'ссылку.',
      'Public host': 'Публичный хост',
      "User's current password": 'Текущий пароль пользователя',
      '(does NOT change it — embedded into the link only)': '(НЕ меняет его — только вшивается в ссылку)',
      'Label': 'Метка',
      '(optional, shown in the app)': '(необязательно, показывается в приложении)',
      'qeli:// link': 'ссылка qeli://',
      'Scan the QR with the qeli app, or paste the link to import the profile.':
        'Отсканируйте QR в приложении qeli или вставьте ссылку, чтобы импортировать профиль.',
      'Generate QR': 'Сгенерировать QR',
      'Copy': 'Копировать',
      '(plaintext)': '(открытым текстом)',
      'Issues a connection link/QR for an': 'Создаёт ссылку/QR подключения для',
      'user from the password stored on the server —': 'пользователя из сохранённого на сервере пароля —',
      'no password entry needed': 'ввод пароля не нужен',
      ', and it does': ', и это',
      'change the password.': 'меняет пароль.',
      'Reset password & issue config': 'Сбросить пароль и выдать конфиг',
      'No stored password for this user — reset to issue a config?': 'Для этого пользователя нет сохранённого пароля — сбросить, чтобы выдать конфиг?',
      'Password was reset.': 'Пароль сброшен.',
      'New password:': 'Новый пароль:',
      "— the user's previous config no longer works.": '— прежний конфиг пользователя больше не работает.',

      // ── config: toolbar / common ──
      'Form': 'Форма',
      'Raw INI': 'Сырой INI',
      'Unsaved changes': 'Несохранённые изменения',
      'Reload': 'Перезагрузить',
      'Save to Disk': 'Сохранить на диск',
      'Apply & Restart': 'Применить и перезапустить',
      'Restarting…': 'Перезапуск…',
      'writes the config (applied on next restart).': 'записывает конфиг (применится при следующем перезапуске).',
      'saves and restarts the server now so changes go live immediately.':
        'сохраняет и перезапускает сервер сейчас, чтобы изменения вступили в силу немедленно.',
      'Global': 'Общие',
      'profile name': 'имя профиля',
      'Enabled': 'Включён',
      'Disabled': 'Выключен',
      'Remove Profile': 'Удалить профиль',

      // ── config: section headers ──
      'Authentication': 'Аутентификация',
      'Web UI': 'Веб-интерфейс',
      'Logging': 'Логирование',
      'Server identity keys': 'Ключи идентичности сервера',
      'Transport, Bind & Identity': 'Транспорт, привязка и идентичность',
      'TUN/TAP Interface': 'Интерфейс TUN/TAP',
      'IP Address Pool': 'Пул IP-адресов',
      'Routing': 'Маршрутизация',
      'DNS Proxy': 'DNS-прокси',
      'DHCP Server': 'DHCP-сервер',
      '(for TAP/bridged mode)': '(для режима TAP/bridged)',
      'Traffic Obfuscation': 'Обфускация трафика',
      'Performance': 'Производительность',
      'Wire Mode': 'Режим канала',
      'TLS Masking': 'TLS-маскировка',
      'Connection Limits': 'Лимиты подключений',
      'TCP Settings': 'Настройки TCP',
      'TUN Buffer': 'Буфер TUN',
      'Brute-force Protection': 'Защита от брутфорса',

      // ── config: auth ──
      'Users file': 'Файл пользователей',
      'Path to the users file (INI, used if no inline users)': 'Путь к файлу пользователей (INI, если нет inline-пользователей)',
      'Password hash algorithm': 'Алгоритм хеша пароля',
      'Algorithm used for password verification': 'Алгоритм для проверки пароля',
      'Token TTL (seconds)': 'TTL токена (сек)',
      'Lifetime of an authenticated session token': 'Время жизни токена аутентифицированной сессии',
      'Require pinned server key': 'Требовать пиннинг ключа сервера',
      "Reject clients that have not pinned this server's public key; also hides the key from scanners. Use":
        'Отклонять клиентов, не запиннивших публичный ключ сервера; также скрывает ключ от сканеров. Используйте',
      '(or the Dashboard) to get the key for clients.': '(или Панель), чтобы получить ключ для клиентов.',
      'Bind identity to session keys': 'Привязать идентичность к сессионным ключам',
      'H-1 · default on': 'H-1 · по умолч. вкл',
      "Folds the static-ephemeral DH into the session KDF (Noise-IK), so a failed ephemeral RNG alone can't expose the tunnel. ON (default since 0.7.1) admits only H-1 clients that pin the key. Turn":
        'Вплетает static-ephemeral DH в KDF сессии (Noise-IK), так что сбой эфемерного RNG сам по себе не раскроет туннель. ВКЛ (по умолчанию с 0.7.1) пускает только H-1-клиентов с пиннингом ключа. Выключайте',
      'off': 'выкл',
      'only to interoperate with a legacy 0.7.0 / TOFU fleet until all clients are upgraded.':
        'только для совместимости со старым 0.7.0 / TOFU-парком, пока все клиенты не обновлены.',
      'Max attempts': 'Макс. попыток',
      'Failed logins before lockout': 'Неудачных входов до блокировки',
      'Window (seconds)': 'Окно (сек)',
      'Time window for counting failures': 'Окно времени для подсчёта неудач',
      'Lockout duration (seconds)': 'Длительность блокировки (сек)',
      'How long to block after exceeding limit': 'Насколько блокировать после превышения лимита',

      // ── config: web ──
      'Enable Web UI': 'Включить веб-интерфейс',
      'HTTP management interface': 'HTTP-интерфейс управления',
      'Bind address': 'Адрес привязки',
      'Interface to listen on (0.0.0.0 = all)': 'Интерфейс для прослушивания (0.0.0.0 = все)',
      'Port': 'Порт',
      'HTTP port for Web UI': 'HTTP-порт веб-интерфейса',
      'Admin username': 'Имя администратора',
      'Username for Basic Auth': 'Имя пользователя для Basic Auth',
      'Admin password hash': 'Хеш пароля администратора',
      'argon2id hash — empty = no authentication (dangerous!)': 'argon2id-хеш — пусто = без аутентификации (опасно!)',
      'Secure session cookie': 'Secure-кука сессии',
      'Add the': 'Добавляет атрибут',
      'Secure': 'Secure',
      'attribute — auto-on when Native HTTPS is enabled; enable manually only behind a TLS reverse proxy. Leave OFF for plain-HTTP localhost / SSH-tunnel access, or a Secure cookie locks you out.':
        '— включается автоматически при встроенном HTTPS; вручную включайте только за TLS-реверс-прокси. Оставьте ВЫКЛ для plain-HTTP localhost / доступа по SSH-туннелю, иначе Secure-кука вас заблокирует.',
      'Set admin password': 'Задать пароль администратора',
      'Enter a plaintext password to hash (argon2id) into the field above.': 'Введите пароль открытым текстом, чтобы захешировать (argon2id) в поле выше.',
      'Required': 'Обязательно',
      'for a non-loopback bind — without it the panel refuses to start.': 'для не-loopback привязки — без него панель не запустится.',
      'Hash & set': 'Хешировать и задать',
      'Password hashed and set above — Save to apply.': 'Пароль захеширован и подставлен выше — сохраните, чтобы применить.',
      'Native HTTPS (TLS)': 'Встроенный HTTPS (TLS)',
      'for public bind': 'для публичной привязки',
      'Serve the panel over HTTPS directly (rustls) so it can be exposed on a public IP without a reverse proxy. Empty cert/key = auto self-signed (browser warns once; traffic encrypted). Auto-enables the Secure cookie.':
        'Отдавать панель по HTTPS напрямую (rustls), чтобы публиковать на внешнем IP без реверс-прокси. Пустые cert/key = авто self-signed (браузер предупредит один раз; трафик шифруется). Автоматически включает Secure-куку.',
      'TLS certificate (PEM)': 'TLS-сертификат (PEM)',
      'Path to cert chain. Empty = auto self-signed at /etc/qeli/web-tls-cert.pem': 'Путь к цепочке сертификатов. Пусто = авто self-signed в /etc/qeli/web-tls-cert.pem',
      '(empty = self-signed)': '(пусто = self-signed)',
      'TLS private key (PEM)': 'Закрытый ключ TLS (PEM)',
      'Path to private key. Empty = auto self-signed': 'Путь к закрытому ключу. Пусто = авто self-signed',
      'Source-IP allowlist': 'Белый список IP',
      'CIDRs or bare IPs allowed to reach the panel; empty = any source. Strongest barrier for a public bind (e.g. 203.0.113.4, 10.0.0.0/8).':
        'CIDR или отдельные IP, которым разрешён доступ к панели; пусто = любой источник. Самый сильный барьер для публичной привязки (напр. 203.0.113.4, 10.0.0.0/8).',
      '+ Add IP / CIDR': '+ Добавить IP / CIDR',
      'Public host for share links': 'Публичный хост для ссылок',
      "The server's reachable address (host or host:port). Pre-fills the Share/QR dialog so you don't retype it each time — it's still editable there.":
        'Доступный адрес сервера (host или host:port). Предзаполняет диалог Share/QR, чтобы не вводить каждый раз — там его всё равно можно изменить.',
      'Pool': 'Пул',
      'Obfuscation': 'Обфускация',

      // ── config: logging ──
      'Log level': 'Уровень логов',
      'Minimum severity level to record': 'Минимальный уровень для записи',
      'error — only errors': 'error — только ошибки',
      'warn — errors and warnings': 'warn — ошибки и предупреждения',
      'info — standard (recommended)': 'info — стандартно (рекомендуется)',
      'debug — verbose': 'debug — подробно',
      'trace — very verbose': 'trace — очень подробно',
      'Log format': 'Формат логов',
      'Output format for log lines': 'Формат строк лога',
      'Log file path': 'Путь к файлу логов',
      'Leave empty to use stderr / journald': 'Пусто — использовать stderr / journald',

      // ── config: identity ──
      "Each profile has its own pinned public key. Set it as": 'У каждого профиля свой пиннингованный публичный ключ. Задайте его как',
      "on that profile's clients (anti-MITM). Replaces the old \"SSH in and run":
        'на клиентах этого профиля (анти-MITM). Заменяет старое «зайти по SSH и выполнить',
      '" step.': '».',
      'Loading keys…': 'Загрузка ключей…',
      'No profiles yet.': 'Профилей пока нет.',
      'Rotate': 'Ротация',

      // ── config: bind ──
      'Protocol': 'Протокол',
      'TCP — reliable, easier to route. UDP — lower latency, better for mobile.': 'TCP — надёжно, проще маршрутизировать. UDP — меньше задержка, лучше для мобильных.',
      'Listen address': 'Адрес прослушивания',
      '0.0.0.0 listens on all interfaces': '0.0.0.0 — слушать на всех интерфейсах',
      'Port 443 blends with HTTPS traffic': 'Порт 443 сливается с HTTPS-трафиком',
      'Identity key path': 'Путь к ключу идентичности',
      'Per-profile server identity (private key). Empty = default /etc/qeli/identity/<name>.key': 'Идентичность сервера на профиль (закрытый ключ). Пусто = по умолчанию /etc/qeli/identity/<name>.key',

      // ── config: tun ──
      'Device type': 'Тип устройства',
      'TUN — IP-level (recommended). TAP — Ethernet-level (legacy).': 'TUN — на уровне IP (рекомендуется). TAP — на уровне Ethernet (устаревшее).',
      'TUN (IP)': 'TUN (IP)',
      'TAP (Ethernet)': 'TAP (Ethernet)',
      'Interface name': 'Имя интерфейса',
      'Name of the OS network interface': 'Имя сетевого интерфейса ОС',
      'Max packet size. 1400–1480 avoids fragmentation with encapsulation overhead.': 'Макс. размер пакета. 1400–1480 избегает фрагментации с учётом инкапсуляции.',
      'Gateway IP (server address)': 'Шлюз (адрес сервера)',
      'IP of this server on the VPN network': 'IP этого сервера в VPN-сети',
      'Subnet mask': 'Маска подсети',
      'Defines the VPN subnet': 'Определяет подсеть VPN',
      'TX queue length': 'Длина очереди TX',
      'Kernel transmit queue size. Higher = more buffering.': 'Размер очереди передачи в ядре. Больше = больше буферизации.',
      'TUN queues (multi-queue)': 'Очереди TUN (multi-queue)',
      'IFF_MULTI_QUEUE: 0 = auto (CPU count) so the kernel RSS-spreads packets across cores. 1 = single pump (legacy).':
        'IFF_MULTI_QUEUE: 0 = авто (число CPU), ядро RSS-распределяет пакеты по ядрам. 1 = одна очередь (legacy).',

      // ── config: pool ──
      'Pool CIDR': 'CIDR пула',
      'Subnet from which client IPs are assigned. Must contain the gateway IP.': 'Подсеть, из которой выдаются IP клиентам. Должна содержать IP шлюза.',
      'Lease time (seconds)': 'Время аренды (сек)',
      'How long an IP is reserved for a user': 'Сколько IP зарезервирован за пользователем',
      'Excluded IPs': 'Исключённые IP',
      'IPs that will never be assigned to clients (e.g. gateway, reserved hosts)': 'IP, которые никогда не выдаются клиентам (напр. шлюз, зарезервированные узлы)',
      '+ Add excluded IP': '+ Добавить исключённый IP',
      'Static reservations': 'Статические резервации',
      'Always assign a specific IP to a specific username': 'Всегда выдавать конкретный IP конкретному пользователю',
      '+ Add reservation': '+ Добавить резервацию',

      // ── config: routing ──
      'Client-to-client routing': 'Маршрутизация клиент-клиент',
      'Allow connected clients to communicate with each other': 'Разрешить подключённым клиентам общаться между собой',
      'Forward private networks': 'Проброс приватных сетей',
      'Route traffic to 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 through VPN': 'Маршрутизировать 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 через VPN',
      'NAT masquerade': 'NAT masquerade',
      "MASQUERADE client traffic through the server's internet interface": 'MASQUERADE трафика клиентов через интернет-интерфейс сервера',
      'Interface:': 'Интерфейс:',
      'Pushed routes': 'Проброшенные маршруты',
      'Routes advertised to clients — they install them automatically (e.g. reach a LAN behind the server)': 'Маршруты, анонсируемые клиентам — они ставятся автоматически (напр. доступ к LAN за сервером)',
      '+ Add pushed route': '+ Добавить маршрут',

      // ── config: dns ──
      'Enable DNS proxy': 'Включить DNS-прокси',
      'Forward client DNS queries through the server, prevents DNS leaks': 'Проксировать DNS-запросы клиентов через сервер, предотвращает DNS-утечки',
      'Should match the VPN gateway IP': 'Должен совпадать с IP шлюза VPN',
      'Listen port': 'Порт прослушивания',
      'Standard DNS port is 53': 'Стандартный DNS-порт — 53',
      'Upstream protocol': 'Протокол upstream',
      'Protocol for upstream DNS queries': 'Протокол для upstream DNS-запросов',
      'UDP (faster)': 'UDP (быстрее)',
      'TCP (reliable)': 'TCP (надёжнее)',
      'Cache size': 'Размер кэша',
      'Number of DNS entries to cache': 'Сколько DNS-записей кэшировать',
      'Timeout (seconds)': 'Таймаут (сек)',
      'Upstream query timeout': 'Таймаут upstream-запроса',
      'Upstream DNS servers': 'Upstream DNS-серверы',
      'Queries are forwarded to these servers in order': 'Запросы пересылаются этим серверам по порядку',
      '+ Add upstream server': '+ Добавить upstream-сервер',
      'Domain blocklist': 'Чёрный список доменов',
      'Queries for these domains (and subdomains) are refused — basic ad/tracker blocking': 'Запросы к этим доменам (и поддоменам) отклоняются — базовая блокировка рекламы/трекеров',
      '+ Add blocked domain': '+ Добавить домен в блок',

      // ── config: dhcp ──
      'In normal': 'В обычном режиме',
      'mode client IPs are assigned by the built-in': 'IP клиентам выдаёт встроенный',
      'IP pool': 'пул IP',
      '(the': '(секция',
      'section above —': 'выше —',
      '/ static reservations),': 'CIDR / статические резервации),',
      'not': 'не',
      'by DHCP. This DHCP server is only needed for': 'через DHCP. Этот DHCP-сервер нужен только для',
      'TAP / bridged': 'TAP / bridged',
      'setups. Leave it off for TUN — addresses are still assigned.': 'конфигураций. Для TUN оставьте выключенным — адреса всё равно выдаются.',
      'Enable DHCP server': 'Включить DHCP-сервер',
      'Automatically assign IPs via DHCP (mainly useful for TAP mode)': 'Автоматически выдавать IP по DHCP (в основном для режима TAP)',
      'DHCP listen address': 'Адрес прослушивания DHCP',
      'Usually 0.0.0.0:67': 'Обычно 0.0.0.0:67',
      'Pool start IP': 'Начальный IP пула',
      'First IP to hand out via DHCP': 'Первый IP для выдачи по DHCP',
      'Pool end IP': 'Конечный IP пула',
      'Last IP to hand out via DHCP': 'Последний IP для выдачи по DHCP',
      'How long a DHCP lease is valid': 'Сколько действует аренда DHCP',
      'Domain name': 'Доменное имя',
      'Pushed to clients as search domain': 'Передаётся клиентам как search-домен',

      // ── config: obfuscation ──
      'Mode': 'Режим',
      'fake-tls = mimic a TLS 1.3 handshake. obfs = ChaCha20 stream (structure-free). Must match the client.': 'fake-tls = имитация рукопожатия TLS 1.3. obfs = поток ChaCha20 (без структуры). Должно совпадать с клиентом.',
      'fake-tls (mimic TLS)': 'fake-tls (имитация TLS)',
      'obfs (random stream)': 'obfs (случайный поток)',
      'Cipher (AEAD)': 'Шифр (AEAD)',
      'Data-plane authenticated cipher': 'AEAD-шифр плоскости данных',
      'obfs fronting': 'obfs fronting',
      'websocket wraps the nonce exchange in an HTTP Upgrade (beats "fully-encrypted" DPI). Must match the client.': 'websocket оборачивает обмен nonce в HTTP Upgrade (обходит DPI «полностью зашифрованного»). Должно совпадать с клиентом.',
      'websocket (recommended)': 'websocket (рекомендуется)',
      'none (raw nonce)': 'none (сырой nonce)',
      'Required for obfs mode — must match the client exactly': 'Обязательно для режима obfs — должно точно совпадать с клиентом',
      'Generate': 'Сгенерировать',
      'SNI (Server Name)': 'SNI (имя сервера)',
      'Domain in the fake TLS ClientHello — should be a real CDN/HTTPS site': 'Домен в фейковом TLS ClientHello — должен быть реальным CDN/HTTPS-сайтом',
      'TLS session ID': 'TLS session ID',
      'Include a random TLS session ID (more realistic handshake)': 'Включать случайный TLS session ID (реалистичнее рукопожатие)',
      'Enabled (recommended)': 'Включено (рекомендуется)',
      'Key-share entropy (bytes)': 'Энтропия key_share (байт)',
      'Size of the decoy key_share in the fake ClientHello': 'Размер ложного key_share в фейковом ClientHello',
      'Decoy SNI pool': 'Пул ложных SNI',
      'Candidate camouflage hostnames (config-surfaced; per-profile override of the built-in list)': 'Кандидаты-хосты для камуфляжа (в конфиге; переопределение встроенного списка на профиль)',
      '+ Add SNI': '+ Добавить SNI',
      'Supported groups (key-exchange)': 'Поддерживаемые группы (обмен ключами)',
      'Named groups advertised in the fake ClientHello (e.g. x25519, secp256r1)': 'Именованные группы в фейковом ClientHello (напр. x25519, secp256r1)',
      '+ Add group': '+ Добавить группу',
      'Genuine browser TLS 1.3. "Foreign"/prober traffic is transparently proxied to a real HTTPS site; our clients are recognised by a REALITY short_id token and (optionally) terminated with real TLS.':
        'Настоящий браузерный TLS 1.3. «Чужой»/зондирующий трафик прозрачно проксируется на реальный HTTPS-сайт; наши клиенты опознаются по токену REALITY short_id и (опционально) терминируются настоящим TLS.',
      'Camouflage target (real site)': 'Камуфляж-цель (реальный сайт)',
      'Where non-client / prober TLS is proxied — a real HTTPS site whose cert the prober sees': 'Куда проксируется не-клиентский / зондирующий TLS — реальный HTTPS-сайт, чей сертификат видит зонд',
      'Target port': 'Порт цели',
      'usually 443': 'обычно 443',
      'Peek timeout (ms)': 'Таймаут подглядывания (мс)',
      'How long to read the ClientHello before classifying client vs probe (high-latency safe). Default 1500.': 'Сколько читать ClientHello до классификации клиент/зонд (безопасно для высокой задержки). По умолч. 1500.',
      'Genuine TLS termination': 'Полноценная TLS-терминация',
      'Terminate our authenticated clients with a real TLS 1.3 session and run the qeli tunnel inside it — real TLS on the wire (Xray-REALITY level). Off = legacy fake-TLS handshake.':
        'Терминировать наших аутентифицированных клиентов настоящей TLS 1.3-сессией и гнать туннель qeli внутри — настоящий TLS на проводе (уровень Xray-REALITY). Выкл = legacy fake-TLS.',
      'Requires at least one short_id.': 'Требуется хотя бы один short_id.',
      'Hand-rolled TLS stack': 'Собственный TLS-стек',
      "Borrow the target's real certificate chain and mirror its ServerHello JA3S (Xray-REALITY parity). OFF falls back to rustls (self-signed cert + rustls JA3S — weaker camouflage).":
        'Заимствует реальную цепочку сертификатов цели и зеркалит её ServerHello JA3S (паритет Xray-REALITY). ВЫКЛ откатывается на rustls (self-signed + rustls JA3S — слабее камуфляж).',
      'Accepted short_ids': 'Принимаемые short_ids',
      '(hex, ≤8 bytes / 16 chars)': '(hex, ≤8 байт / 16 симв.)',
      'REALITY tokens that mark a connection as one of our clients. Each client sets a matching': 'Токены REALITY, помечающие соединение как наше. Каждый клиент задаёт совпадающий',
      '. Empty = legacy ALPN-absence detection.': '. Пусто = legacy-детект по отсутствию ALPN.',
      '+ Add short_id': '+ Добавить short_id',
      'Random padding': 'Случайная набивка',
      'Add random bytes to each packet to disguise payload size patterns': 'Добавлять случайные байты к пакетам, скрывая паттерны размеров',
      'Min padding (bytes)': 'Мин. набивка (байт)',
      'Max padding (bytes)': 'Макс. набивка (байт)',
      'Probability': 'Вероятность',
      'Fraction of packets that get padding (0.0–1.0)': 'Доля пакетов с набивкой (0.0–1.0)',
      'Randomize length': 'Случайная длина',
      'Random length in [min,max]; off = fixed min': 'Случайная длина в [min,max]; выкл = фиксированный min',
      'Heartbeat / keep-alive': 'Heartbeat / keep-alive',
      'Send periodic dummy packets to prevent connection timeouts and normalize traffic timing': 'Слать периодические пустышки, чтобы не было таймаутов и нормализовать тайминг трафика',
      'Interval (ms)': 'Интервал (мс)',
      'How often to send heartbeats': 'Как часто слать heartbeat',
      'Jitter (ms)': 'Джиттер (мс)',
      'Random delay ±jitter to prevent timing fingerprints': 'Случайная задержка ±jitter против таймингового фингерпринта',
      'Payload size (bytes)': 'Размер нагрузки (байт)',
      'Size of dummy data in heartbeat packets': 'Размер пустых данных в heartbeat-пакетах',
      'TLS record fragmentation': 'Фрагментация TLS-записей',
      'Split handshake records into multiple TCP segments — defeats DPI that looks for full records': 'Разбивать записи рукопожатия на несколько TCP-сегментов — против DPI, ищущего целые записи',
      'Min chunk (bytes)': 'Мин. чанк (байт)',
      'Max chunk (bytes)': 'Макс. чанк (байт)',
      'Max fragments': 'Макс. фрагментов',
      'HTTP/2 frame masking': 'Маскировка под HTTP/2',
      'Interleave traffic with synthetic HTTP/2 frames so the stream resembles HTTP/2-over-TLS': 'Перемежать трафик синтетическими HTTP/2-кадрами, чтобы поток походил на HTTP/2-over-TLS',
      'Frame ratio': 'Доля кадров',
      'Fraction of synthetic frames mixed in (0.0–1.0)': 'Доля подмешиваемых синтетических кадров (0.0–1.0)',
      'Traffic normalization': 'Нормализация трафика',
      'Pad packets up to fixed "round" sizes so payload lengths leak no information': 'Дополнять пакеты до фиксированных «круглых» размеров, чтобы длины не утекали',
      'Randomize sequence': 'Случайный порядок',
      'Shuffle the order in which round sizes are applied': 'Перемешивать порядок применения круглых размеров',
      'Round sizes (bytes)': 'Круглые размеры (байт)',
      'Packets are padded up to the next size in this set': 'Пакеты дополняются до следующего размера из набора',
      '+ Add round size': '+ Добавить размер',
      'Anti-fingerprinting': 'Анти-фингерпринтинг',
      'Rotate cipher suites and add handshake jitter to defeat static fingerprints': 'Ротация наборов шифров и джиттер рукопожатия против статических отпечатков',
      'Rotate ciphers every (seconds)': 'Ротация шифров каждые (сек)',
      'Add handshake jitter': 'Джиттер рукопожатия',
      'Randomize handshake timing': 'Случайный тайминг рукопожатия',
      'QUIC masking': 'Маскировка под QUIC',
      'UDP only': 'только UDP',
      'Wrap UDP packets in fake QUIC headers to look like QUIC/HTTP3 traffic': 'Оборачивать UDP-пакеты в фейковые QUIC-заголовки под трафик QUIC/HTTP3',
      'Connection-ID length (bytes)': 'Длина Connection-ID (байт)',
      'QUIC CID size in the synthetic header': 'Размер QUIC CID в синтетическом заголовке',
      'QUIC version': 'Версия QUIC',
      'Version number advertised (1 = RFC 9000)': 'Анонсируемый номер версии (1 = RFC 9000)',
      'Stream bonding (multipath)': 'Объединение потоков (multipath)',
      'Aggregate several parallel connections into ONE tunnel session to beat the single-stream TCP-over-TCP throughput ceiling. Leave off on UDP profiles.': 'Агрегировать несколько параллельных соединений в ОДНУ сессию-туннель, обходя потолок TCP-over-TCP одного потока. Для UDP-профилей выключайте.',
      'Max streams': 'Макс. потоков',
      'Server-enforced ceiling on parallel streams per session': 'Потолок параллельных потоков на сессию (контролирует сервер)',
      'Adaptive ramp': 'Адаптивный разгон',
      'Client auto-ramps 1→max by measured throughput (max becomes a ceiling). Off = open exactly max.': 'Клиент авторазгоняется 1→max по измеренной скорости (max становится потолком). Выкл = открывать ровно max.',

      // ── config: performance ──
      'Max simultaneous clients': 'Макс. одновременных клиентов',
      'Maximum number of connected clients per profile': 'Макс. число подключённых клиентов на профиль',
      'Handshake timeout (s)': 'Таймаут рукопожатия (с)',
      'Max time for key exchange + authentication': 'Макс. время на обмен ключами + аутентификацию',
      'Idle timeout (s)': 'Таймаут простоя (с)',
      'Disconnect clients with no traffic for this long. 0 = never.': 'Отключать клиентов без трафика дольше этого. 0 = никогда.',
      'Rate limit (packets/s)': 'Лимит (пакетов/с)',
      'Per-session packet rate cap (anti-flood)': 'Потолок скорости пакетов на сессию (анти-флуд)',
      'New-session burst (max)': 'Всплеск новых сессий (макс.)',
      'Max fresh sessions per source IP per window (connection-flood guard)': 'Макс. новых сессий с одного IP за окно (защита от флуда подключений)',
      'New-session window (s)': 'Окно новых сессий (с)',
      'Window for the new-session burst limit': 'Окно для лимита всплеска новых сессий',
      'TCP_NODELAY': 'TCP_NODELAY',
      "Disable Nagle's algorithm — lower latency, less throughput": 'Отключить алгоритм Нейгла — меньше задержка, меньше пропускная способность',
      'Keepalive interval (s)': 'Интервал keepalive (с)',
      'TCP keepalive probe interval': 'Интервал TCP keepalive-проб',
      'Send buffer (bytes)': 'Буфер отправки (байт)',
      'SO_SNDBUF for client sockets': 'SO_SNDBUF для клиентских сокетов',
      'Recv buffer (bytes)': 'Буфер приёма (байт)',
      'SO_RCVBUF for client sockets': 'SO_RCVBUF для клиентских сокетов',
      'Read buffer size (bytes)': 'Размер буфера чтения (байт)',
      'Buffer for reading from the TUN interface': 'Буфер для чтения из интерфейса TUN',
      'Write buffer size (bytes)': 'Размер буфера записи (байт)',
      'Buffer for writing to the TUN interface': 'Буфер для записи в интерфейс TUN',
      'Read timeout (ms)': 'Таймаут чтения (мс)',
      'Poll timeout on the TUN read loop': 'Таймаут опроса в цикле чтения TUN',
      'Max pending packets': 'Макс. пакетов в очереди',
      'Queue size for outgoing packets before dropping': 'Размер очереди исходящих пакетов до отбрасывания',

      // ── config: JSON/raw views ──
      'server config (saved as INI)': 'конфиг сервера (сохраняется как INI)',
      'Format': 'Форматировать',
      'on-disk INI — verbatim, comments preserved': 'INI с диска — дословно, комментарии сохранены',
      'Saved to the file': 'Сохраняется в файл',
      'verbatim': 'дословно',
      '— keeps your hand-written comments. Validated by parsing before write. Restart the server to apply.': '— сохраняет ваши комментарии. Перед записью проверяется парсингом. Перезапустите сервер для применения.',
      'Path:': 'Путь:',

      // ── logs ──
      'All levels': 'Все уровни',
      'ERROR': 'ERROR',
      'WARN': 'WARN',
      'INFO': 'INFO',
      'DEBUG': 'DEBUG',
      'lines': 'строк',
      'Search logs…': 'Поиск в журнале…',
      'No log entries match the current filter': 'Нет записей под текущий фильтр',
      'Showing': 'Показано',
      'Bottom': 'Вниз',

      // ── client tab (outbound tunnels) ──
      'Import qeli:// link': 'Импорт qeli://-ссылки',
      'Paste INI config': 'Вставить INI-конфиг',
      'Add manually': 'Добавить вручную',
      'Outbound connections: this box dials out to other qeli servers (a client role). Add one by importing a qeli:// link, filling the form, or pasting a full INI config, then Connect.':
        'Исходящие подключения: этот узел сам дозванивается до других qeli-серверов (роль клиента). Добавьте профиль импортом qeli://-ссылки, через форму или вставкой полного INI-конфига, затем нажмите «Подключить».',
      'No client profiles yet — Import a qeli:// link or Add one manually.':
        'Профилей пока нет — импортируйте qeli://-ссылку или добавьте вручную.',
      'Server': 'Сервер',
      '↻ autostart': '↻ автозапуск',
      '⚠ full-tunnel': '⚠ полный туннель',
      '● Connected': '● Подключён',
      '○ Disconnected': '○ Отключён',
      'Connect': 'Подключить',
      'Disconnect': 'Отключить',
      'Connection string': 'Строка подключения',
      'Profile name': 'Имя профиля',
      'auto from the link': 'авто из ссылки',
      'Import': 'Импортировать',
      'Edit profile': 'Изменить профиль',
      'Add client profile': 'Добавить клиентский профиль',
      '↤ Form view': '↤ Форма',
      'Raw INI ↦': 'Сырой INI ↦',
      'Name': 'Имя',
      'Server (host:port)': 'Сервер (host:port)',
      'Wire mode': 'Режим канала',
      'User': 'Пользователь',
      'Pinned server key (hex)': 'Пиннингованный ключ сервера (hex)',
      '(required for reality-tls)': '(обязательно для reality-tls)',
      'from qeli show-identity': 'из qeli show-identity',
      'QUIC masking (UDP only) — mask the handshake as QUIC': 'Маскировка QUIC (только UDP) — маскирует рукопожатие под QUIC',
      'Auto-connect this profile when the server/panel starts': 'Автоподключение профиля при старте сервера/панели',
      'Route private/LAN networks through the tunnel': 'Заворачивать приватные/LAN-сети в туннель',
      'Full-tunnel (route ALL traffic) — can cut off this panel / SSH on a server box.':
        'Полный туннель (ВЕСЬ трафик) — на сервере может отрезать эту панель / SSH.',
      'Need dev / mtu / dns / kill_switch / [logging]? Switch to Raw INI for the full config.':
        'Нужны dev / mtu / dns / kill_switch / [logging]? Переключитесь на «Сырой INI» для полного конфига.',
      'Client config (INI)': 'Конфиг клиента (INI)',
      'Every client key: server, proto, user, pass, key, bind_static, mode, sni, reality_sid, obfs_key, front, quic, dev, mtu, gateway, route_local, kill_switch, dns, autostart and [logging]. See client.conf.':
        'Все ключи клиента: server, proto, user, pass, key, bind_static, mode, sni, reality_sid, obfs_key, front, quic, dev, mtu, gateway, route_local, kill_switch, dns, autostart и [logging]. См. client.conf.',
      'Save': 'Сохранить',
      'Deleted': 'Удалено',

      // ── theme ──
      'Theme': 'Тема',
      'Dark': 'Тёмная',
      'Light': 'Светлая',

      // ── misc ──
      'Mbps': 'Мбит/с',
      'User:': 'Пользователь:',
      'burst': 'burst',
    },
  };

  const STORAGE_KEY = 'qeli_lang';
  const ATTRS = ['placeholder', 'title'];
  const origText = new WeakMap(); // text node -> original EN string
  let lang = localStorage.getItem(STORAGE_KEY) || 'en';
  let observer = null;
  let scheduled = false;

  function tr(en) {
    const d = DICT[lang];
    if (!d) return en;
    const key = en.trim();
    if (!key) return en;
    if (d[key] !== undefined) return en.replace(key, d[key]);
    const pats = PATTERNS[lang];
    if (pats) {
      for (const [re, rep] of pats) {
        if (re.test(key)) return en.replace(key, key.replace(re, rep));
      }
    }
    return en;
  }

  function processText(node) {
    const p = node.parentNode;
    if (!p) return;
    const tag = p.nodeName;
    if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'TEXTAREA' || tag === 'OPTION') return;
    if (!origText.has(node)) {
      if (!node.nodeValue || !node.nodeValue.trim()) return;
      origText.set(node, node.nodeValue);
    }
    const en = origText.get(node);
    const want = lang === 'en' ? en : tr(en);
    if (node.nodeValue !== want) node.nodeValue = want;
  }

  function processAttrs(el) {
    if (!el.hasAttribute) return;
    for (const a of ATTRS) {
      if (!el.hasAttribute(a)) continue;
      const stash = 'data-i18n-' + a;
      let en = el.getAttribute(stash);
      if (en === null) {
        en = el.getAttribute(a);
        el.setAttribute(stash, en);
      }
      const want = lang === 'en' ? en : tr(en);
      if (el.getAttribute(a) !== want) el.setAttribute(a, want);
    }
  }

  function walk(root) {
    if (root.nodeType === Node.TEXT_NODE) { processText(root); return; }
    if (root.nodeType !== Node.ELEMENT_NODE && root.nodeType !== Node.DOCUMENT_NODE) return;
    const tw = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = [];
    let n;
    while ((n = tw.nextNode())) nodes.push(n);
    nodes.forEach(processText);
    if (root.querySelectorAll) root.querySelectorAll('[placeholder],[title]').forEach(processAttrs);
    if (root.nodeType === Node.ELEMENT_NODE) processAttrs(root);
  }

  function apply() {
    if (!observer) return;
    observer.disconnect();
    try { walk(document.body); } finally {
      observer.observe(document.body, {
        childList: true, subtree: true, characterData: true,
        attributes: true, attributeFilter: ATTRS,
      });
    }
  }

  function schedule() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => { scheduled = false; apply(); });
  }

  function populateSelect() {
    const sel = document.getElementById('qeli-lang');
    if (!sel) return;
    sel.innerHTML = '';
    for (const l of LANGS) {
      const o = document.createElement('option');
      o.value = l.code; o.textContent = l.name;
      if (l.code === lang) o.selected = true;
      sel.appendChild(o);
    }
    sel.addEventListener('change', () => window.setQeliLang(sel.value));
  }

  window.QELI_LANGS = LANGS;
  window.qeliLang = () => lang;
  window.setQeliLang = function (code) {
    lang = code;
    try { localStorage.setItem(STORAGE_KEY, code); } catch (e) {}
    apply();
  };

  function start() {
    populateSelect();
    observer = new MutationObserver(() => schedule());
    apply();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
