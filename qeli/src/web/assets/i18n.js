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

      // ── update banner (opt-in) ──
      'Update available:': 'Доступна новая версия:',
      'View release': 'Открыть релиз',
      'Dismiss': 'Скрыть',
      'Copy': 'Копировать',
      'Copy command': 'Копировать команду',
      'Command copied': 'Команда скопирована',
      'Run on the server to update — qeli never installs anything itself.':
        'Выполните на сервере для обновления — qeli сам ничего не устанавливает.',
      'Copy failed': 'Не удалось скопировать',

      // ── login ──
      'Admin panel': 'Панель администратора',
      'Username': 'Имя пользователя',
      'Password': 'Пароль',
      'Sign in': 'Войти',
      'Qeli VPN · secure management': 'Qeli VPN · защищённое управление',
      'Enter a username and password': 'Введите имя пользователя и пароль',
      'Sign in failed': 'Не удалось войти',
      'Invalid username or password': 'Неверное имя пользователя или пароль',

      // ── quick start page ──
      'Quick start — launch any masking mode in one click': 'Быстрый старт — запуск любого режима маскировки в один клик',
      'Each row is a complete masking mode. Click Launch and the panel builds a ready profile — TUN interface, NAT egress, in-tunnel DNS, an IP pool and the full obfuscation stack with the curated stealth posture (Poisson flow-shaping instead of a fixed heartbeat, MTU 1280, stream bonding on TCP) — then saves it and restarts the server.':
        'Каждая строка — полноценный режим маскировки. Нажмите Launch, и панель соберёт готовый профиль: интерфейс TUN, NAT-выход, DNS внутри туннеля, пул IP и полный стек обфускации с подобранной stealth-постурой (пуассоновский шейпинг вместо фиксированного heartbeat, MTU 1280, бондинг потоков на TCP) — затем сохранит его и перезапустит сервер.',
      'Each mode gets its own interface, subnet and port, so they never collide — launch as many as you like and clients pick whichever port suits their network. After a server is up, add users and share a qeli:// link or QR; for full manual control over every option, open the config.':
        'У каждого режима свой интерфейс, подсеть и порт, поэтому они не конфликтуют — поднимайте сколько угодно, клиенты сами выберут подходящий их сети порт. После запуска сервера добавьте пользователей и поделитесь ссылкой qeli:// или QR; для полного ручного контроля над каждым параметром откройте конфигурацию.',
      'Modes are independent — running several at once is the recommended production layout (it is exactly what server-multiprofile.conf.example ships). A client connects to whichever port gets through its network.':
        'Режимы независимы — запуск нескольких сразу это рекомендованная боевая схема (ровно то, что поставляется в server-multiprofile.conf.example). Клиент подключается к тому порту, который проходит через его сеть.',
      'flagship': 'флагман',
      'server is live': 'сервер запущен',
      'is running on': 'работает на',
      'REALITY short_id': 'REALITY short_id',
      '— set reality_sid to this on every client': '— задайте этим reality_sid на каждом клиенте',
      'obfs pre-shared key': 'предобщий ключ obfs',
      '— set obfs_key to this on every client': '— задайте этим obfs_key на каждом клиенте',
      "Clients also need the server's pinned public key — run qeli show-identity on the server. Then add users below and share a QR/link from the Users page.":
        'Клиентам также нужен пиннингованный публичный ключ сервера — выполните qeli show-identity на сервере. Затем добавьте пользователей ниже и поделитесь QR/ссылкой со страницы «Пользователи».',
      'Mobile / LTE clients: the large handshake can black-hole behind a sub-1500 path MTU. On the server apply the OS tuning (outer-port MSS clamp + BBR/PMTU probing) — see docs/PANEL.md → "Mobile / LTE" or CONFIG.md → "sysctl + iptables". The install-reality-server.sh installer does this automatically.':
        'Клиенты на Mobile / LTE: крупное рукопожатие может «провалиться» при path MTU ниже 1500. На сервере примените тюнинг ОС (MSS-clamp по внешнему порту + BBR/PMTU-зондирование) — см. docs/PANEL.md → «Mobile / LTE» или CONFIG.md → «sysctl + iptables». Установщик install-reality-server.sh делает это автоматически.',
      'Open config': 'Открыть конфиг',
      'Add users': 'Добавить пользователей',
      'Close': 'Закрыть',
      'Port already in use': 'Порт уже используется',
      'Port {port} is already used by profile {name}. Change its port in Configuration first, then launch again.':
        'Порт {port} уже занят профилем {name}. Сначала измените его порт в Конфигурации, затем запустите снова.',

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
      'Confirm': 'Подтвердить',
      'Disable user': 'Отключить пользователя',
      'Delete user': 'Удалить пользователя',
      'Delete group': 'Удалить группу',
      'Delete users': 'Удалить пользователей',
      'Enable users': 'Включить пользователей',
      'Disable users': 'Отключить пользователей',
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
      // config action buttons — tooltips + inline help (3-button layout)
      'Reload the config from disk (discards unsaved edits)':
        'Перечитать конфиг с диска (несохранённые правки отбрасываются)',
      'Save and do a full systemctl restart — applies everything, including panel-socket changes (web.bind/port/tls/enabled). Your login survives if web.persist_session_key is on (default).':
        'Сохранить и выполнить полный systemctl restart — применяет всё, включая изменения сокета панели (web.bind/port/tls/enabled). Сессия входа сохранится, если включён web.persist_session_key (по умолчанию).',
      'writes the config to disk (applied on next restart);':
        'записывает конфиг на диск (применится при следующем перезапуске);',
      're-reads it from disk (discards unsaved edits).':
        'перечитывает его с диска (несохранённые правки отбрасываются).',
      'saves and does a full systemctl restart — applies everything, including panel-socket changes (web.bind/port/tls/enabled); your login survives if web.persist_session_key is on (default).':
        'сохраняет и выполняет полный systemctl restart — применяет всё, включая изменения сокета панели (web.bind/port/tls/enabled); сессия входа сохранится, если включён web.persist_session_key (по умолчанию).',
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
      'Brute-force protection — VPN authentication': 'Защита от брутфорса — аутентификация VPN',
      'Locks out source IPs after repeated failed VPN logins. Independent of the web-panel login policy (set in the Web UI card below).':
        'Блокирует IP-адреса источников после повторных неудачных входов в VPN. Независимо от политики входа в веб-панель (задаётся в карточке «Веб-интерфейс» ниже).',
      'Enable VPN-auth lockout': 'Включить блокировку VPN-аутентификации',
      'Off = no rate-limiting on VPN authentication (e.g. behind an external limiter).':
        'Выкл = без ограничения частоты VPN-аутентификации (например, за внешним лимитером).',
      'Brute-force protection — panel login': 'Защита от брутфорса — вход в панель',
      'Locks out source IPs after repeated failed admin logins to this panel. Separate from the VPN-auth policy (Authentication card).':
        'Блокирует IP-адреса источников после повторных неудачных входов админа в эту панель. Отдельно от политики VPN-аутентификации (карточка «Аутентификация»).',
      'Enable panel-login lockout': 'Включить блокировку входа в панель',
      'Off = no rate-limiting on panel logins (only safe on a trusted / loopback bind).':
        'Выкл = без ограничения частоты входов в панель (безопасно только на доверенном / loopback-бинде).',

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
      "The server's reachable address (host or host:port). Pre-fills the Share/QR dialog so you don't retype it each time — it's still editable there. Also accepted as a CSRF origin.":
        'Доступный адрес сервера (host или host:port). Предзаполняет диалог Share/QR, чтобы не вводить каждый раз — там его всё равно можно изменить. Также принимается как CSRF-origin.',
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
      'TUN — IP-level (L3, the usual choice). TAP — Ethernet-level (L2, for bridging Ethernet frames).': 'TUN — на уровне IP (L3, обычный выбор). TAP — на уровне Ethernet (L2, для L2-моста / Ethernet-кадров).',
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
      'IFF_MULTI_QUEUE: 0 = auto (CPU count) so the kernel RSS-spreads packets across cores. 1 = single queue.':
        'IFF_MULTI_QUEUE: 0 = авто (число CPU), ядро RSS-распределяет пакеты по ядрам. 1 = одна очередь.',

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
      'Terminate our authenticated clients with a real TLS 1.3 session and run the qeli tunnel inside it — real TLS on the wire (Xray-REALITY level). Off = plain fake-TLS handshake (TLS-shaped, directly on the socket).':
        'Терминировать наших аутентифицированных клиентов настоящей TLS 1.3-сессией и гнать туннель qeli внутри — настоящий TLS на проводе (уровень Xray-REALITY). Выкл = обычный fake-TLS (форма TLS прямо на сокете).',
      'Requires at least one short_id.': 'Требуется хотя бы один short_id.',
      'Hand-rolled TLS stack': 'Собственный TLS-стек',
      "Borrow the target's real certificate chain and mirror its ServerHello JA3S (Xray-REALITY parity). OFF falls back to rustls (self-signed cert + rustls JA3S — weaker camouflage).":
        'Заимствует реальную цепочку сертификатов цели и зеркалит её ServerHello JA3S (паритет Xray-REALITY). ВЫКЛ откатывается на rustls (self-signed + rustls JA3S — слабее камуфляж).',
      'Accepted short_ids': 'Принимаемые short_ids',
      '(hex, ≤8 bytes / 16 chars)': '(hex, ≤8 байт / 16 симв.)',
      'REALITY tokens that mark a connection as one of our clients. Each client sets a matching': 'Токены REALITY, помечающие соединение как наше. Каждый клиент задаёт совпадающий',
      '. Empty = fall back to ALPN-absence detection.': '. Пусто = фолбэк-детект по отсутствию ALPN.',
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
      'Route ALL private ranges (RFC1918) through the tunnel — server-pushed routes apply regardless':
        'Заворачивать ВСЕ приватные диапазоны (RFC1918) в туннель — маршруты, раздаваемые сервером, применяются в любом случае',
      'Full-tunnel (route ALL traffic) — can cut off this panel / SSH on a server box.':
        'Полный туннель (ВЕСЬ трафик) — на сервере может отрезать эту панель / SSH.',
      'Need dev / mtu / dns / kill_switch / [logging]? Switch to Raw INI for the full config.':
        'Нужны dev / mtu / dns / kill_switch / [logging]? Переключитесь на «Сырой INI» для полного конфига.',
      'Client config (INI)': 'Конфиг клиента (INI)',
      'Every client key: server, proto, user, pass, key, bind_static, mode, sni, reality_sid, obfs_key, front, quic, dev, mtu, gateway, route_local, kill_switch, dns, autostart and [logging]. See client.conf.':
        'Все ключи клиента: server, proto, user, pass, key, bind_static, mode, sni, reality_sid, obfs_key, front, quic, dev, mtu, gateway, route_local, kill_switch, dns, autostart и [logging]. См. client.conf.',
      'Save': 'Сохранить',
      'Deleted': 'Удалено',

      // ── dashboard: host metrics + per-user usage (Tier) ──
      'Host load': 'Нагрузка хоста',
      'Tunnel throughput': 'Пропускная способность',
      'load avg': 'ср. нагрузка',
      'qeli proc': 'процесс qeli',
      'memory': 'память',
      'disk': 'диск',
      '— Profile:': '— Профиль:',
      'WAN net': 'сеть WAN',
      'conns · uptime': 'соедин. · аптайм',
      'collecting…': 'сбор данных…',
      '⤓ Backup': '⤓ Бэкап',
      '⤒ Restore': '⤒ Восстановить',
      'Data usage': 'Использование трафика',
      'NAT masquerade is enabled on a profile, but `iptables` is not installed — full-tunnel internet egress will NOT work. Install it: apt install iptables.':
        'На профиле включён NAT masquerade, но `iptables` не установлен — полнотуннельный выход в интернет НЕ работает. Установите: apt install iptables.',

      // ── quick start page ──
      'One-click presets': 'Пресеты в один клик',
      'All masking modes': 'Все режимы маскировки',
      'the full multiprofile set — configure any of these on the Config page': 'полный набор мультипрофиля — настраивается на странице «Конфигурация»',
      'Transport · Port': 'Транспорт · Порт',
      'What it does': 'Что делает',
      'Launch': 'Запустить',
      'Action': 'Действие',
      'Pick a masking mode below. The panel builds a ready profile for you — TUN interface, NAT egress, in-tunnel DNS, an IP pool and the full obfuscation stack with the curated stealth posture (Poisson flow-shaping instead of a fixed heartbeat, MTU 1280, stream bonding on TCP) — saves it, and restarts the server.':
        'Выберите режим маскировки ниже. Панель соберёт готовый профиль — интерфейс TUN, NAT-выход, DNS в туннеле, пул IP и полный стек обфускации с боевой stealth-постурой (Poisson flow-shaping вместо фиксированного heartbeat, MTU 1280, объединение потоков на TCP) — сохранит и перезапустит сервер.',
      'Genuine TLS 1.3 carries the tunnel — indistinguishable from a real HTTPS site, beats active probing. Best default.':
        'Туннель внутри настоящего TLS 1.3 — неотличимо от реального HTTPS-сайта, устойчив к активному зондированию. Лучший выбор по умолчанию.',
      'REALITY proxy: foreign / prober traffic is bridged to a real site; our clients are recognised by a short_id token (fake-TLS, no inner TLS).':
        'REALITY-прокси: чужой/зондирующий трафик проксируется на реальный сайт; наши клиенты опознаются по токену short_id (fake-TLS, без внутреннего TLS).',
      'Mimics a TLS 1.3 handshake. Near-zero overhead — the lightweight default.':
        'Имитирует рукопожатие TLS 1.3. Почти без накладных расходов — лёгкий вариант.',
      'ChaCha20 stream + WebSocket fronting. Structure-free, beats "fully-encrypted" / entropy DPI.':
        'Поток ChaCha20 + WebSocket-фронтинг. Без структуры, обходит DPI «полностью зашифрованного» / энтропийный.',
      'ChaCha20 stream obfuscation without fronting — bare random-looking stream.':
        'Обфускация ChaCha20 без фронтинга — голый случайный поток.',
      'Raw tunnel, no obfuscation. For debugging or fully trusted links only.':
        'Голый туннель без обфускации. Только для отладки или полностью доверенных каналов.',
      'fake-TLS handshake over UDP. Lower latency than TCP-carried modes.':
        'fake-TLS-рукопожатие поверх UDP. Меньше задержка, чем у TCP-режимов.',
      'fake-TLS + QUIC masking — looks like QUIC / HTTP3 traffic. Best for mobile.':
        'fake-TLS + маскировка под QUIC — выглядит как трафик QUIC / HTTP3. Лучший для мобильных.',
      'ChaCha20 stream obfuscation over UDP.': 'Обфускация потока ChaCha20 поверх UDP.',
      'obfs + AmneziaWG-style junk preamble — prepends jc random junk packets before the handshake (the Amnezia analog). Both ends need the same jc.':
        'obfs + junk-преамбула в стиле AmneziaWG — добавляет jc случайных junk-пакетов перед рукопожатием (аналог Amnezia). На обоих концах нужен одинаковый jc.',

      // ── usage modal ──
      'Data cap (GB)': 'Лимит трафика (ГБ)',
      'Download cap (GB)': 'Лимит загрузки (ГБ)',
      '— 0 = unlimited': '— 0 = без лимита',
      '— 0 = unlimited · counts download only': '— 0 = без лимита · считается только загрузка',
      'Expire in (days)': 'Истекает через (дней)',
      '— 0 = never': '— 0 = никогда',
      'Or until date': 'Или до даты',
      'Data cap & expiry': 'Лимит трафика и срок',
      'Reset': 'Сбросить',

      // ── i18n audit: nav / dashboard / logs / users ──
      'Quick start': 'Быстрый старт',
      'Download /etc/qeli backup (.tar.gz)': 'Скачать бэкап /etc/qeli (.tar.gz)',
      'Restore /etc/qeli from a backup .tar.gz': 'Восстановить /etc/qeli из бэкапа .tar.gz',
      '100 lines': '100 строк',
      '200 lines': '200 строк',
      '500 lines': '500 строк',
      '1000 lines': '1000 строк',
      'Clear': 'Очистить',
      'Set data cap / expiry': 'Задать лимит / срок',
      'Reset usage counter': 'Сбросить счётчик',
      'Reset usage': 'Сброс счётчика',

      // ── i18n audit: config — origins / traffic shaping ──
      '+ Add origin': '+ Добавить origin',
      'Allowed browser origins (CSRF)': 'Разрешённые browser-origins (CSRF)',
      'Extra origins the panel accepts mutating requests from, for access via a domain / reverse proxy whose host differs from the bind. Without these a public panel loads but every save returns 403. Use host or host:port (e.g. panel.example.com, panel.example.com:8443). The bind, loopback and public host are always allowed.':
        'Дополнительные origin, от которых панель принимает мутирующие запросы — для доступа через домен / reverse-proxy, чей хост отличается от bind. Без них публичная панель открывается, но любой save возвращает 403. Формат host или host:port (напр. panel.example.com, panel.example.com:8443). Bind, loopback и публичный хост разрешены всегда.',
      'Add profile': 'Добавить профиль',
      'Traffic shaping (idle cover)': 'Шейпинг трафика (cover в простое)',
      'Idle gap mean (ms)': 'Средний интервал в простое (мс)',
      'Mean of the exponential inter-cover gap': 'Среднее экспоненциального интервала между cover-пакетами',
      'Idle gap min (ms)': 'Мин. интервал в простое (мс)',
      'Idle gap max (ms)': 'Макс. интервал в простое (мс)',
      'Cover budget (bytes/sec)': 'Бюджет cover (байт/с)',
      'Max cover traffic; 0 = none': 'Макс. cover-трафик; 0 = нет',
      'Cover size min (bytes)': 'Мин. размер cover (байт)',
      'Cover size max (bytes)': 'Макс. размер cover (байт)',
      'Stealth — trade speed for DPI cover': 'Stealth — скорость в обмен на DPI-cover',
      'Rate-caps the data plane and runs cover under load, breaking the bulk-download size + timing tell. Sacrifices throughput.':
        'Ограничивает скорость дата-плейна и гонит cover под нагрузкой, ломая size+timing-теллы bulk-загрузки. Жертвует пропускной способностью.',
      'Stealth rate cap (Mbps)': 'Потолок скорости stealth (Мбит/с)',
      'Lower = less like a bulk download (and slower)': 'Ниже = меньше похоже на bulk-загрузку (и медленнее)',

      // ── i18n audit: config misc / users modal / placeholders ──
      '● Unsaved changes': '● Несохранённые изменения',
      'Wire-breaking.': 'Несовместимо по проводу.',
      'Per-profile server identity (private key). Empty = default /etc/qeli/identity/<name>.key':
        'Идентичность сервера для профиля (приватный ключ). Пусто = по умолчанию /etc/qeli/identity/<name>.key',
      'recommended': 'рекомендуется',
      'gateway (optional)': 'шлюз (необязательно)',
      'new admin password': 'новый пароль администратора',
      'username': 'имя пользователя',
      '$argon2id$… (leave empty for open access)': 'хеш argon2id… (пусто = открытый доступ)',
      'Reset the lifetime usage counter for': 'Сбросить счётчик трафика для',
      'to zero? The data cap and expiry stay unchanged.': 'в ноль? Лимит и срок действия не изменятся.',
      'enter password': 'введите пароль',
      'gateway (opt)': 'шлюз (необяз.)',

      // ── notifications page ──
      'Notifications': 'Уведомления',
      'Get alerted on key server events via Telegram and a generic webhook. The two channels are fully independent — each has its own switch, credentials, event selection and test. Outbound TLS certificates are verified; sends are best-effort and never block the data plane.':
        'Получайте оповещения о ключевых событиях сервера через Telegram и произвольный webhook. Каналы полностью независимы — у каждого свой переключатель, реквизиты, набор событий и тест. Сертификаты исходящего TLS проверяются; отправка best-effort и не блокирует дата-плейн.',
      'Server name': 'Имя сервера',
      'Prefixed to every notification so several servers reporting to one Telegram chat / webhook are distinguishable (e.g. "[prod-eu] …"). Empty = omit.':
        'Подставляется в начало каждого уведомления, чтобы различать несколько серверов, шлющих в один Telegram-чат / webhook (например, «[prod-eu] …»). Пусто = не добавлять.',
      'Send messages through a Telegram bot.': 'Отправка сообщений через Telegram-бота.',
      'POST a JSON payload to any HTTP(S) endpoint.': 'POST JSON на любой HTTP(S)-эндпоинт.',
      'Notify on': 'Уведомлять о',
      'Save changes': 'Сохранить изменения',
      'Test sent — see the result': 'Тест отправлен — см. результат',
      'Bot token': 'Токен бота',
      'Create a bot with @BotFather and paste its token. Write-only — leave blank to keep the current one.':
        'Создайте бота через @BotFather и вставьте его токен. Только запись — оставьте пустым, чтобы сохранить текущий.',
      'Current token:': 'Текущий токен:',
      'Chat ID': 'ID чата',
      'Destination chat — your user id, a group, or a channel (e.g. 123456789 or -1001234567890). Message @userinfobot to get yours.':
        'Чат назначения — ваш user id, группа или канал (например, 123456789 или -1001234567890). Узнать свой — напишите @userinfobot.',
      'Generic webhook': 'Произвольный webhook',
      'Webhook URL': 'URL webhook',
      'An HTTP(S) endpoint that receives a JSON POST: { event, detail, text, ts }. HTTPS recommended.':
        'HTTP(S)-эндпоинт, принимающий JSON POST: { event, detail, text, ts }. Рекомендуется HTTPS.',
      'Events': 'События',
      'Server start / restart': 'Старт / рестарт сервера',
      'The control plane came up (e.g. after a restart).': 'Управляющий слой поднялся (например, после рестарта).',
      'Quota breach': 'Превышение квоты',
      'A user hit their data cap or their subscription expired.': 'Пользователь исчерпал лимит трафика или истёк срок подписки.',
      'Panel login lockout': 'Блокировка входа в панель',
      'An IP was locked out after too many failed panel logins.': 'IP заблокирован после слишком многих неудачных входов в панель.',
      'VPN auth IP lockout': 'Блокировка IP (VPN-авторизация)',
      'An IP was locked out after repeated wrong VPN login/password.': 'IP заблокирован после повторного неверного логина/пароля VPN.',
      'Config restored': 'Конфиг восстановлен',
      'The /etc/qeli config was restored from a backup.': 'Конфиг /etc/qeli восстановлен из бэкапа.',
      'Client connected': 'Клиент подключился',
      'A client established a new tunnel session. Can be frequent — off by default.': 'Клиент установил новую туннельную сессию. Может быть частым — по умолчанию выкл.',
      'Client disconnected': 'Клиент отключился',
      'A client tunnel session ended (TCP clean close). Off by default.': 'Туннельная сессия клиента завершилась (чистое TCP-закрытие). По умолчанию выкл.',
      'Send test': 'Отправить тест',
      'Test result': 'Результат теста',
      'Notification settings saved': 'Настройки уведомлений сохранены',
      'Test sent — see the result below': 'Тест отправлен — см. результат ниже',
      'Save failed': 'Не удалось сохранить',
      'Test failed': 'Не удалось отправить тест',
      'configure Telegram or a webhook URL first': 'сначала настройте Telegram или URL webhook',

      // ── blocked IPs page ──
      'Blocked IPs': 'Заблокированные IP',
      'The lockout policy (max attempts, time window, lockout duration) is configured in Configuration → Brute-force Protection; it governs both web-panel login and VPN authentication.':
        'Политика блокировки (число попыток, окно времени, длительность) настраивается в разделе Конфигурация → Защита от брутфорса; действует и на вход в веб-панель, и на VPN-аутентификацию.',
      'Lockout policy': 'Политика блокировки',
      '— panel login and VPN auth are limited independently':
        '— вход в панель и VPN-аутентификация ограничиваются независимо',
      "Applied live (no restart); saving resets that surface's failure counters. Turn a switch off to disable rate-limiting for that surface entirely.":
        'Применяется на лету (без рестарта); сохранение сбрасывает счётчики этой поверхности. Выключите переключатель, чтобы полностью отключить ограничение для неё.',
      'VPN authentication': 'Аутентификация VPN',
      'Panel login': 'Вход в панель',
      'Saved — applied live': 'Сохранено — применено на лету',
      'Applies to both web-panel login and VPN authentication':
        'Действует и на вход в веб-панель, и на аутентификацию VPN',
      'After this many failed attempts within the window, a source IP is locked out for the lockout duration.':
        'После стольких неудачных попыток в течение окна IP-адрес источника блокируется на заданное время.',
      'Window (seconds)': 'Окно (секунды)',
      'Lockout (seconds)': 'Блокировка (секунды)',
      'Save policy': 'Сохранить политику',
      'Saving applies live and resets the current counters.':
        'Сохранение применяется на лету и сбрасывает текущие счётчики.',
      'Saved & applied': 'Сохранено и применено',
      'Request failed': 'Ошибка запроса',
      'Source IPs currently locked by brute-force protection (repeated wrong passwords). Locks clear on their own after the timeout; here you can release them early.':
        'IP-адреса источников, заблокированные защитой от брутфорса (повторный неверный пароль). Блокировки снимаются сами по истечении таймаута; здесь их можно снять досрочно.',
      'Source IPs currently locked by brute-force protection, kept as two separate journals. Locks clear on their own after the timeout; here you can release them early.':
        'IP-адреса источников, заблокированные защитой от брутфорса, ведутся как два отдельных журнала. Блокировки снимаются сами по истечении таймаута; здесь их можно снять досрочно.',
      'Clear all': 'Очистить все',
      'Unblock ALL currently-blocked addresses?': 'Разблокировать ВСЕ заблокированные адреса?',
      'Failed to unblock': 'Не удалось разблокировать',
      'Failed to clear': 'Не удалось очистить',
      'No blocked IPs.': 'Нет заблокированных IP.',
      'IP address': 'IP-адрес',
      'Failures': 'Неудачных попыток',
      'Unblock in': 'Разблокировка через',
      'Unblock': 'Разблокировать',

      // ── theme ──
      'Theme': 'Тема',
      'Dark': 'Тёмная',
      'Light': 'Светлая',

      // ── misc ──
      'Mbps': 'Мбит/с',
      'User:': 'Пользователь:',
      'burst': 'burst',

      // ── API messages / toasts (server-returned; shown as panel notifications) ──
      'Unauthorized': 'Не авторизован',
      'worker restarting': 'Рабочий процесс перезапускается',
      'unknown channel': 'Неизвестный канал',
      'password field required': 'Требуется поле пароля',
      'password too long (max 1024 bytes)': 'Пароль слишком длинный (макс. 1024 байта)',
      'brute-force settings saved and applied': 'Настройки защиты от брутфорса сохранены и применены',
      'config saved — web/panel settings applied live; restart to apply profile/bind/tun changes': 'Конфиг сохранён — настройки веб-панели применены на лету; перезапустите для применения изменений профиля/бинда/TUN',
      'raw config saved (comments preserved) — web/panel settings applied live; restart to apply profile/bind/tun changes': 'Сырой конфиг сохранён (комментарии сохранены) — настройки веб-панели применены на лету; перезапустите для применения изменений профиля/бинда/TUN',
      'config_path not set — running from in-memory config': 'config_path не задан — работа из конфига в памяти',
      "No recoverable password for this user (created before re-issue was enabled, or the key changed). Reset to issue a new config — the user's old config will stop working.": 'Пароль этого пользователя восстановить нельзя (создан до включения перевыпуска или ключ сменился). Нажмите «Сброс», чтобы выдать новый конфиг — старый конфиг пользователя перестанет работать.',
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
  // Translate a string from JS (e.g. confirm()/alert() text the DOM walker can't
  // reach). Falls back to the input for an unknown key or English.
  window.qeliT = (en) => tr(en);
  window.setQeliLang = function (code) {
    lang = code;
    try { localStorage.setItem(STORAGE_KEY, code); } catch (e) {}
    apply();
  };

  // Drop the anti-FOUC guard set by the inline <head> script (no-op on English,
  // where nothing was hidden).
  function reveal() {
    try {
      document.documentElement.style.visibility = '';
    } catch (e) {}
  }

  function start() {
    populateSelect();
    observer = new MutationObserver(() => schedule());
    apply();
    // Re-translate once more after Alpine's initial x-text/x-for render lands,
    // then reveal — so the page is shown already localized, never in English.
    if (typeof requestAnimationFrame === 'function') {
      requestAnimationFrame(() => {
        apply();
        reveal();
      });
    } else {
      reveal();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
