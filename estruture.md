/project-bolt/
│
├── app.py                  # Arquivo principal da aplicação Flask
├── requirements.txt        # Dependências do projeto
├── README.md               # Documentação do projeto
│
├── /data/                  # Pasta para armazenar dados JSON
│   ├── passwords.json      # Arquivo JSON para armazenar senhas
│   └── users.json          # Arquivo JSON para armazenar usuários (futura implementação)
│
├── /tokens/                # Pasta para armazenar tokens (opcional, se necessário)
│   └── blacklist_tokens/   # Pasta para tokens revogados (futura implementação)
│
├── /static/                # Pasta para arquivos estáticos (CSS, JS, imagens)
│   ├── /css/
│   │   └── styles.css      # Arquivo CSS personalizado
│   └── /js/
│       └── scripts.js      # Arquivo JavaScript (futura implementação)
│
├── /templates/             # Pasta para templates HTML
│   ├── base.html           # Template base
│   ├── login.html          # Página de login
│   ├── dashboard.html      # Página do painel de controle
│   └── partials/           # Pasta para templates parciais (futura implementação)
│
├── /models/                # Pasta para modelos de dados (futura implementação)
│   └── user_model.py       # Modelo de usuário (futura implementação)
│
├── /utils/                 # Pasta para utilitários (funções auxiliares)
│   └── security_utils.py   # Funções de segurança (hashing, tokens, etc.)
│
└── /logs/                  # Pasta para logs da aplicação (futura implementação)
    └── app.log             # Arquivo de log
