
# Resumão Redes e Git

## Sumário

### Redes
- [Topologias](#topologias)
- [Protocolos](#protocolos)
- [Endereçamento IP](#endereçamento-ip)
- [Serviços e Aplicações WEB](#serviços-e-aplicações-web)
- [DNS](#dns)
- [Arquitetura da internet](#arquitetura-da-internet)
- [Redes de computadores](#redes-de-computadores)
- [Segurança de Redes](#segurança-de-redes)
- [Segurança WEB](#segurança-web)
- [Tendências e Desafios nas Redes modernas](#tendências-e-desafios-nas-redes-modernas)
### Git
- [Git](#git)
- [Branch e Merge](#branch-e-merge)
- [Repositório remoto](#repositório-remoto)
- [Pull Request](#pull-request)


## Topologias

-   **Barramento**
    Descrição: Dispositivos compartilham um único cabo de comunicação.
    Vantagens: Simples de implementar.
-   **Estrela**
    Descrição: Dispositivos conectados a um ponto central (hub/switch).
    Vantagens: Falha de um dispositivo não afeta os outros.
-   **Anel**
    Descrição: Dispositivos conectados em um loop fechado.
    Vantagens: Altamente eficiente.
-   **Malha**
    Descrição: Cada dispositivo conectado a todos os outros.
    Vantagens: Alta redundância e confiabilidade.



## Protocolos

### Protocolos de rede
-   **IP (Internet Protocol)**
    Função principal: Endereçamento e roteamento de pacotes. É o protocolo fundamental da Internet.
    Uso típico: Entrega de dados entre redes distintas.
-   **ICMP (Internet Control Message Protocol)**
    Função principal: Usado para enviar mensagens de erro e informações operacionais.
    Uso típico: Comandos ping e traceroute.
-   **ARP (Address Resolution Protocol)**
    Função principal: Mapeia endereços IP para endereços MAC (físicos) na rede local.
    Uso típico: Comunicação dentro de uma mesma rede local.

### Protocolos de transporte
-   **TCP (Transmission Control Protocol)**
    Característica principal: Orientado à conexão e confiável. Garante a entrega, a ordem e a retransmissão de dados perdidos.
    Uso típico: Navegação Web (HTTP/HTTPS), Transferência de Arquivos (FTP), E-mail (SMTP).
-   **UDP (User Datagram Protocol)**
    Característica principal: Não orientado à conexão e não confiável. Entrega mais rápida, mas sem garantia de ordem ou retransmissão.
    Uso típico: Streaming de Vídeo/Áudio, Jogos Online, DNS (Domain Name System).

### Protocolos de aplicação
-   **HTTP (Hypertext Transfer Protocol)**
    Função principal: Transferência de hipertexto (páginas web).
    Uso típico: Acesso a websites.
-   **SMTP (Simple Mail Transfer Protocol)**
    Função principal: Envio de e-mails.
    Uso típico: Servidores de e-mail.
-   **FTP (File Transfer Protocol)**
    Função principal: Transferência de arquivos entre cliente e servidor.
    Uso típico: Upload e download de arquivos.

### Protocolos de segurança
-   **SSL/TLS (Secure Sockets Layer / Transport Layer Security)**
    Função principal: Criptografa a comunicação entre cliente e servidor. O TLS é o sucessor do SSL.
    Uso típico: Websites seguros (HTTPS), VPNs, E-mail seguro.
-   **IPsec (Internet Protocol Security)**
    Função principal: Conjunto de protocolos para proteger as comunicações IP, fornecendo autenticação e criptografia.
    Uso típico: Criação de Redes Privadas Virtuais (VPNs) na camada de rede.
-   **SSH (Secure Shell)**
    Função principal: Permite acesso remoto seguro a um sistema, substituindo protocolos não seguros como o Telnet.
    Uso típico: Administração remota de servidores.


## Endereçamento IP

### IPv4

O IPv4 é a versão original e ainda mais amplamente utilizada. Ele usa um endereço de 32 bits, geralmente representado por quatro números decimais separados por pontos (ex: 192.168.1.1).A principal limitação do IPv4 é o número finito de endereços disponíveis (aproximadamente 4,3 bilhões), o que levou à necessidade de uma nova versão.

### IPv6

O IPv6 foi desenvolvido para superar a escassez de endereços do IPv4. Ele utiliza um endereço de 128 bits, representado por oito grupos de quatro dígitos hexadecimais separados por dois pontos (ex: 2001:0db8:85a3:0000:0000:8a2e:0370:7334). O IPv6 oferece um número virtualmente ilimitado de endereços (cerca de $3,4 \times 10^{38}$), além de melhorias como:

- **Cabeçalho simplificado:** Para roteamento mais eficiente.
- **Segurança integrada:** O IPsec é obrigatório no IPv6.
- **Configuração automática:** Capacidade de autoconfiguração de endereços.

### Máscara de Sub-rede e Segmentação de Redes

- **Máscara de Sub-rede**
A máscara é composta por uma sequência de bits "1" (que representam a porção de rede) seguida por uma sequência de bits "0" (que representam a porção de host).
- **Segmentação de Redes (Sub-redes)**
A segmentação de redes, ou subnetting, é o processo de dividir uma rede maior em sub-redes menores e mais gerenciáveis.

### Firewall

O firewall é um sistema de segurança de rede que atua como uma barreira entre uma rede confiável (como uma rede interna) e uma rede não confiável (como a Internet). Sua função principal é monitorar e controlar o tráfego de rede de entrada e saída com base em um conjunto predefinido de regras de segurança.

- **Filtragem de Pacotes:** O tipo mais básico, que examina o cabeçalho de cada pacote (endereço IP de origem/destino, porta de origem/destino) e decide se o pacote deve ser permitido ou negado.
- **Inspeção de Estado (Stateful Inspection):** A maioria dos firewalls modernos rastreia o estado das conexões ativas, permitindo que o tráfego de retorno de uma conexão legítima seja automaticamente permitido.
- **Filtragem de Aplicação (Proxy):** Atua como um intermediário, inspecionando o conteúdo da aplicação (camada 7 do modelo OSI).


## Serviços e Aplicações WEB

### APIs e Web Services
**API (Application Programming Interface)** é um conjunto de definições e protocolos que permite que diferentes softwares se comuniquem entre si. Uma API define os métodos e formatos de dados que as aplicações podem usar para solicitar e trocar informações.

**Web Service** é um tipo específico de API que é acessível através de protocolos de rede, como HTTP. Embora todo Web Service seja uma API, nem toda API é um Web Service (por exemplo, uma API de biblioteca de software local). A principal diferença reside no escopo: Web Services são projetados para comunicação baseada em rede, frequentemente entre máquinas.

### SOAP e REST

- **SOAP (Simple Object Access Protocol)** é um protocolo estrito para troca de informações estruturadas na implementação de Web Services. Ele utiliza XML para formatar as mensagens e depende de outros protocolos de aplicação, como HTTP ou SMTP, para a transmissão.
Características do SOAP: É orientado a mensagens, altamente padronizado, e mais adequado para ambientes corporativos que exigem transações complexas e segurança robusta, como sistemas bancários

- **REST (Representational State Transfer)** é um estilo arquitetural que define um conjunto de diretrizes para a criação de Web Services. Os serviços RESTful utilizam operações HTTP padrão (GET, POST, PUT, DELETE) para manipular recursos, geralmente usando JSON ou XML para a representação dos dados.
Características do REST: É mais simples, flexível, escalável e utiliza o protocolo HTTP de forma mais eficiente. É o estilo dominante na construção de APIs modernas e microsserviços.

### Microsserviços

Microsserviços é uma abordagem arquitetural onde uma aplicação é construída como uma coleção de serviços pequenos, independentes e fracamente acoplados. Cada serviço é executado em seu próprio processo e se comunica com outros serviços, geralmente através de APIs RESTful

### Aplicativos Web Interativos (Web 2.0)

O termo Web 2.0, popularizado a partir de 2004, refere-se à segunda geração de serviços e comunidades baseados na web, que enfatiza a interatividade, a colaboração e o conteúdo gerado pelo usuário.
Características: Uso de tecnologias como AJAX (JavaScript assíncrono e XML) para criar interfaces de usuário ricas e dinâmicas, transformando páginas estáticas em aplicativos interativos (como redes sociais, blogs e wikis).

### Autenticação e Segurança em Serviços Web

- **Autenticação Básica HTTP:** Envio de credenciais (usuário e senha) codificadas em Base64.
- **Tokens:** Uso de tokens de acesso (como JWT - JSON Web Tokens) após o login, que são enviados em cada requisição para provar a identidade sem a necessidade de enviar as credenciais repetidamente.
- **TLS/SSL:** O uso de HTTPS (HTTP sobre TLS/SSL) é fundamental para criptografar o tráfego e garantir a confidencialidade e a integridade dos dados em trânsito.
- **OAuth 2.0 e OpenID Connect (OIDC):** São protocolos de autorização e autenticação, respectivamente, que permitem que aplicações de terceiros acessem recursos protegidos sem expor as credenciais do usuário. O OIDC é construído sobre o OAuth 2.0 e é amplamente utilizado para Single Sign-On (SSO).


## DNS

O Sistema de Nomes de Domínio (DNS) é a espinha dorsal da navegação na Internet, atuando como um tradutor universal que converte nomes de domínio legíveis por humanos (como www.google.com) em endereços IP numéricos (como 142.250.190.132) que as máquinas utilizam para se comunicar. Sem o DNS, a navegação na web seria impraticável, exigindo que os usuários memorizassem longas sequências numéricas.

### Hierarquia

- **Resolvedor Recursivo (ou Servidor DNS Local):** É o primeiro ponto de contato. Recebe a consulta do usuário e se encarrega de encontrar a resposta, consultando outros servidores em nome do cliente.
- **Servidores Raiz (Root Servers):** O topo da hierarquia. Eles não armazenam informações específicas de domínios, mas direcionam o resolvedor para o servidor TLD apropriado.
- **Servidores TLD (Top-Level Domain):** Gerenciam informações para domínios de nível superior, como .com, .org, .br. Eles direcionam o resolvedor para o servidor autoritativo.
- **Servidores Autoritativos:** Armazenam os registros DNS reais para um domínio específico (por exemplo, exemplo.com). É aqui que a tradução final de nome para IP ocorre.

### Zonas DNS

- **A -** Address Record (Endereço). Mapeia um nome de domínio para um endereço IPv4. É o registro mais fundamental para a navegação web.
- **AAAA -** Quad-A Record. Mapeia um nome de domínio para um endereço IPv6. Essencial para a adoção da nova versão do protocolo IP.
- **CNAME -** Canonical Name (Nome Canônico). Cria um apelido para outro nome de domínio. É útil para apontar subdomínios para o mesmo endereço IP sem duplicar registros A.
- **MX -** Mail Exchanger (Servidor de Correio). Especifica os servidores de e-mail responsáveis por aceitar mensagens para o domínio, incluindo uma prioridade.
- **NS -** Name Server (Servidor de Nomes). Indica os servidores de nomes autoritativos para a zona.
- **PTR -** Pointer Record. Usado para a resolução reversa (mapeia um endereço IP para um nome de domínio).
- **TXT -** Text Record. Contém texto arbitrário, frequentemente usado para fins de segurança e verificação, como registros SPF (Sender Policy Framework) e DKIM (DomainKeys Identified Mail).

### Cache DNS

O Cache DNS é um mecanismo de otimização de desempenho onde os resolvedores DNS e os sistemas operacionais armazenam temporariamente as respostas de consultas DNS bem-sucedidas.

- **Funcionamento:** Cada registro DNS possui um valor TTL (Time-To-Live) que define por quanto tempo a resposta pode ser armazenada em cache. Enquanto o registro estiver em cache e o TTL não tiver expirado, o resolvedor pode fornecer a resposta instantaneamente, sem precisar refazer a consulta completa na hierarquia DNS.
- **Impacto:** O cache reduz drasticamente a latência de acesso a sites e diminui a carga de tráfego nos servidores DNS autoritativos em todo o mundo.

### DNSSEC

O DNS original foi projetado sem mecanismos de segurança para validar a origem dos dados, tornando-o vulnerável a ataques como o Cache Poisoning (envenenamento de cache), onde um invasor insere informações falsas no cache de um resolvedor. O DNSSEC (Domain Name System Security Extensions) resolve essa vulnerabilidade adicionando autenticação criptográfica aos dados DNS.

- **Mecanismo:** O DNSSEC utiliza assinaturas digitais (baseadas em criptografia de chave pública) para assinar os registros DNS. O resolvedor recursivo verifica essa assinatura digital antes de entregar a resposta ao usuário.
- **Benefício:** Garante a integridade e a autenticidade dos dados. O resolvedor pode ter certeza de que a resposta veio do servidor autoritativo correto e não foi alterada durante o trânsito.

### DoH e DoT

Tradicionalmente, as consultas DNS entre o resolvedor e o cliente são enviadas em texto simples (sem criptografia), o que permite que terceiros (como provedores de internet ou atacantes) monitorem o histórico de navegação do usuário. DNS over TLS (DoT) e DNS over HTTPS (DoH) são protocolos que criptografam essas consultas para proteger a privacidade.


## Arquitetura da internet

### Backbones

O Backbone (espinha dorsal) da Internet é a infraestrutura de rede de alta capacidade que forma o núcleo da comunicação global. É composto por cabos de fibra óptica de alta velocidade, frequentemente submarinos e terrestres, que interligam grandes redes, países e continentes. O backbone é mantido por grandes provedores de serviços de Internet (ISPs) de Nível 1 e empresas de telecomunicações, e sua função é transportar grandes volumes de dados a longas distâncias com a máxima velocidade e confiabilidade.

### IXPs

Os IXPs (Pontos de Troca de Internet) são locais físicos onde diferentes redes (como ISPs, redes de conteúdo e grandes empresas) se conectam diretamente para trocar tráfego de forma eficiente.

- **Função:** O principal objetivo de um IXP é manter o tráfego localmente, evitando que ele precise viajar por longas distâncias através de redes de terceiros (o que seria mais caro e lento). Essa troca direta de tráfego é chamada de peering.
- **Benefício:** Reduz a latência, aumenta a largura de banda disponível e diminui os custos de tráfego para as redes participantes.

### Roteadores e Encaminhamento de Dados

Os Roteadores são dispositivos de rede que operam na Camada 3 (Rede) do modelo OSI e são responsáveis por conectar diferentes redes e determinar o melhor caminho para o tráfego de dados. O Encaminhamento de Dados é o processo central realizado pelo roteador. Ao receber um pacote de dados, o roteador examina o endereço IP de destino e consulta sua Tabela de Roteamento para decidir para qual interface de saída o pacote deve ser enviado.

### QoS (Quality of Service)

QoS (Qualidade de Serviço) é um conjunto de tecnologias e técnicas que gerenciam o tráfego de rede para garantir que certas aplicações ou tipos de dados recebam um nível de serviço prioritário. Em redes congestionadas, o tráfego sensível ao tempo (como voz e vídeo) pode sofrer atrasos (delay), variação de atraso (jitter) e perda de pacotes. O QoS resolve isso priorizando esse tráfego em detrimento de tráfego menos sensível (como e-mail ou transferência de arquivos).

### Desafios de Segurança em Redes

- **Evolução das Ameaças:** Os ataques cibernéticos estão se tornando mais sofisticados e automatizados, exigindo que as defesas evoluam constantemente.
- **Adoção da Nuvem (Cloud):** A migração de dados e aplicações para a nuvem cria novos perímetros de segurança e exige a proteção de dados em ambientes remotos e compartilhados.
- **Dispositivos IoT e Móveis:** O grande número de dispositivos conectados (IoT e BYOD - Bring Your Own Device) expande a superfície de ataque e introduz vulnerabilidades.
- **Fator Humano:** Falhas humanas, como o uso de senhas fracas ou o envio incorreto de informações, continuam sendo uma das principais causas de violações de segurança.
- **Escassez de Profissionais:** A falta de profissionais especializados em cibersegurança dificulta a gestão eficaz das políticas de segurança.


## Redes de computadores

**PAN (Personal Area Network):** Focada na interconexão de dispositivos próximos ao usuário. A tecnologia mais comum é o Bluetooth.

**LAN (Local Area Network):** Caracterizada por alta velocidade e baixa latência. É tipicamente de propriedade privada e interliga dispositivos em uma área geográfica limitada. As tecnologias mais usadas são Ethernet (cabeada) e Wi-Fi (sem fio).

**MAN (Metropolitan Area Network):** Maior que uma LAN, mas menor que uma WAN. Geralmente conecta múltiplas LANs dentro de uma cidade. Frequentemente utiliza tecnologias de fibra óptica ou enlaces de rádio de alta capacidade.

**WAN (Wide Area Network):** Conecta redes em grandes distâncias geográficas. Envolve o uso de tecnologias de telecomunicações de longa distância e é fundamental para a comunicação global. A Internet é o maior exemplo de WAN.

### Wi-fi

Wi-Fi é uma tecnologia de rede sem fio baseada no padrão IEEE 802.11 que permite que dispositivos eletrônicos se conectem à Internet ou troquem dados sem a necessidade de cabos.

#### Funcionamento
- **Transmissão:** O dispositivo (ex: laptop) envia dados através de um adaptador sem fio, convertendo-os em ondas de rádio.
- **Recepção:** O Ponto de Acesso recebe essas ondas e as converte de volta em dados digitais.
- **Encaminhamento:** O AP envia os dados para a rede cabeada (LAN) ou para a Internet.
- **Comunicação Bidirecional:** O processo é inverso para dados que chegam da Internet ao dispositivo.


## Segurança de redes

**Ameaças à Segurança de Redes** - As ameaças à segurança de redes referem-se a qualquer perigo potencial que possa comprometer a integridade, confidencialidade ou disponibilidade de uma rede de computadores. Elas podem se manifestar de diversas formas, incluindo malware (como vírus, ransomware e spyware), ataques de phishing (tentativas de obter informações confidenciais por engano), e ataques de Negação de Serviço Distribuída (DDoS), que sobrecarregam a rede para torná-la indisponível.

**Exploração de Vulnerabilidades** - A exploração de vulnerabilidades ocorre quando um agente malicioso (threat actor) se aproveita de uma falha ou fraqueza em um sistema de hardware, software ou na administração de uma rede. Essas vulnerabilidades podem ser erros de programação (buffer overflow), software desatualizado ou mal configurado, ou até mesmo configurações de segurança padrão que não foram alteradas. A exploração permite que o atacante obtenha acesso não autorizado, execute código malicioso ou cause falhas no sistema.

### Firewalls

- **Firewall de Filtragem de Pacotes (Packet Filtering):** O tipo mais básico. Examina os pacotes de dados individualmente com base em informações como endereço IP de origem/destino e porta.
- **Firewall de Inspeção com Estado (Stateful Inspection):** Vai além da filtragem de pacotes, rastreando o estado das conexões ativas. Ele decide se permite ou bloqueia o tráfego com base no contexto da sessão, sendo mais seguro.
- **Firewall Proxy (Application-Level Gateway):** Atua como um intermediário entre a rede interna e a externa, inspecionando o tráfego em um nível mais profundo (camada de aplicação). Ele esconde o endereço IP interno do cliente.
- **Firewall de Próxima Geração (Next-Generation Firewall - NGFW):** Combina as funcionalidades dos firewalls tradicionais com recursos avançados, como inspeção profunda de pacotes (DPI), prevenção de intrusão (IPS) e controle de aplicativos.

### Antivírus

O antivírus é um software projetado para detectar, prevenir e remover softwares maliciosos (malware) de um sistema de computador. Ao contrário do firewall, que protege a periferia da rede (o tráfego de entrada e saída), o antivírus protege o endpoint (o dispositivo individual). Ele funciona comparando arquivos com um banco de dados de assinaturas de malware conhecido e, mais recentemente, usando análise heurística e comportamental para identificar novas ameaças. O antivírus é essencial para neutralizar ameaças que conseguiram passar pela barreira do firewall.


## Segurança WEB

### HTTP/HTTPS

HTTP e HTTPS O HTTP (Hypertext Transfer Protocol) é o protocolo base para a transferência de dados na World Wide Web. No entanto, o HTTP é inerentemente inseguro, pois a comunicação entre o navegador e o servidor é enviada em texto simples, tornando-a vulnerável a interceptações. O HTTPS (Hypertext Transfer Protocol Secure) é a versão segura do HTTP. A única diferença prática é que o HTTPS utiliza os protocolos SSL/TLS para criptografar e autenticar as solicitações e respostas, protegendo os dados de olhares indesejados.

### SSL/TLS

São protocolos criptográficos que estabelecem um canal de comunicação seguro entre duas partes (geralmente um navegador e um servidor web). O TLS é a versão mais moderna e segura, mas o termo SSL ainda é amplamente utilizado.

- **Criptografia:** Codifica os dados transmitidos para que não possam ser lidos por terceiros.
- **Integridade:** Garante que os dados não foram alterados durante a transmissão.
- **Autenticação:** Verifica a identidade do servidor (e, opcionalmente, do cliente) usando Certificados Digitais.

### Autoridades certificadoras

As Autoridades Certificadoras (CAs) são entidades terceirizadas de confiança que emitem e gerenciam os Certificados SSL/TLS. Elas atuam como um elo de confiança, verificando a identidade do proprietário de um site antes de emitir o certificado. Quando um navegador se conecta a um site HTTPS, ele verifica se o certificado foi emitido por uma CA confiável. Se a verificação for bem-sucedida, o navegador confia na identidade do site e estabelece a conexão segura (o "cadeado verde" na barra de endereço).

## Tendências e Desafios nas Redes Modernas

### IoT(Internet das coisas)

Internet das Coisas (IoT) A Internet das Coisas (IoT) refere-se à rede de objetos físicos (dispositivos, veículos, edifícios, etc.) incorporados com sensores, software e outras tecnologias que lhes permitem conectar e trocar dados com outros dispositivos e sistemas pela Internet. A IoT gera um volume massivo de dados e, por isso, é frequentemente integrada com tecnologias como Machine Learning e Blockchain para análise e segurança.

### Planos de dados e controle

O desacoplamento de planos de dados e controle é o princípio fundamental da Rede Definida por Software (SDN). Em redes tradicionais, as funções de controle (tomada de decisão sobre o tráfego) e de dados (encaminhamento de pacotes) estão acopladas no mesmo dispositivo (roteador/switch). O desacoplamento separa essas funções:

- **Plano de Controle:** Centralizado em um controlador SDN, que gerencia a lógica da rede.
- **Plano de Dados:** Permanece nos dispositivos de rede, que apenas executam as regras de encaminhamento definidas pelo controlador. Isso permite uma gestão de rede mais programável, flexível e centralizada.

### Blockchains

Blockchains são livros-razão digitais descentralizados e distribuídos que registram transações de forma segura e imutável. Cada transação é agrupada em um "bloco" que é encadeado criptograficamente ao bloco anterior. Sua natureza distribuída e imutável oferece transparência e segurança sem a necessidade de uma autoridade central, sendo aplicável em segurança de IoT e autenticação.

### Machine Learning

É um subcampo da Inteligência Artificial (IA) que permite aos sistemas aprender e melhorar a partir da experiência sem serem explicitamente programados. Em redes e segurança, o ML é usado para análise de dados massivos (como os gerados pela IoT), detecção de anomalias e identificação de ameaças que seriam difíceis de detectar por métodos tradicionais.

### Autenticação Multifator (MFA)

É um método de segurança que exige que o usuário forneça duas ou mais formas de verificação para acessar um recurso. Os fatores de autenticação geralmente se enquadram em três categorias.

### Redes de Entrega de Conteúdo (CDNs)

é um grupo de servidores geograficamente distribuídos que trabalham juntos para fornecer conteúdo da Internet (como páginas web, imagens e vídeos) de forma rápida, confiável e segura. O objetivo principal é reduzir a latência ao armazenar cópias do conteúdo em servidores (edge servers) mais próximos do usuário final. Isso melhora a experiência do usuário e a capacidade do site de lidar com picos de tráfego.


## Git

Git é um Sistema de Controle de Versão Distribuído (DVCS). Sua função principal é rastrear e gerenciar as alterações no código-fonte de um projeto ao longo do tempo. Ser distribuído significa que cada desenvolvedor possui uma cópia completa do histórico do projeto em seu repositório local, permitindo que trabalhem offline e garantindo redundância.


## Branch e Merge

**Branch (Ramificação)** Uma branch é essencialmente um ponteiro para um commit (ponto no histórico). Ela permite que os desenvolvedores se isolem da linha principal de desenvolvimento (main branch) para trabalhar em novos recursos, correções de bugs ou experimentos sem afetar o código estável. O uso de branches é fundamental para o desenvolvimento paralelo e seguro em equipes.

**Merge (Fusão)** O merge é o processo de integrar as alterações feitas em uma branch de volta para outra branch (geralmente a main branch). O Git tenta combinar automaticamente as alterações. Se houver conflitos (alterações diferentes na mesma linha de código), o desenvolvedor deve resolvê-los manualmente antes de finalizar a fusão.


## Repositório remoto

Um repositório remoto é uma versão do seu projeto que está hospedada em um servidor na Internet ou na rede (como GitHub, GitLab ou Bitbucket). Ele serve como o ponto central de colaboração e backup para a equipe. Os comandos git push (enviar alterações locais para o remoto) e git pull (baixar e integrar alterações do remoto) são usados para interagir com ele.


## Pull Request

Requisição de Pull é um mecanismo de colaboração usado em plataformas de hospedagem de repositórios remotos. É uma solicitação formal para que as alterações feitas em uma branch sejam revisadas e, se aprovadas, fundidas (merge) em outra branch (geralmente a principal). O PR facilita a revisão de código por pares, discussões e testes automatizados antes que o código seja integrado ao projeto principal.

