Markdown

# 🔍 Threat Hunting & Anomaly Detection com Splunk (SPL)

Este repositório contém o relatório técnico e a documentação prática do laboratório **"Splunk: Exploring SPL"** do TryHackMe. O objetivo deste projeto foi desenvolver habilidades práticas na linguagem **SPL (Search Processing Language)** para investigar incidentes de segurança, realizar auditoria de logs do ecossistema Windows e aplicar técnicas estatísticas de detecção de anomalias em acessos corporativos (VPN).

---

## 🛠️ Tecnologias e Ferramentas Utilizadas
* **SIEM:** Splunk Enterprise
* **Linguagem de Consulta:** SPL (Search Processing Language)
* **Fontes de Dados (Log Sources):**
  * Eventos do Windows (EventID 4624 - Logins Bem-sucedidos)
  * Logs do Sysmon (Microsoft-Windows-Sysmon/Operational - EventID 1)
  * Logs de conexões VPN (`index=vpnlogs`)
* **Enriquecimento:** Bases de Inteligência de Ameaças (Lookups de Risk Score) e Geolocalização (`iplocation`)

---

## 📋 Cenários Investigados & Metodologia

A investigação foi dividida em três fases principais de análise de dados de segurança dentro do SIEM:

### 1. Auditoria de Eventos e Processos do Windows

A análise inicial consistiu em mapear o comportamento padrão (baseline) do ambiente computacional do Windows e caçar persistências maliciosas através do Sysmon.

* **Identificação de Criação de Usuário Malicioso (Sysmon EventID 1):**
  Ao auditar a criação de processos, identificamos um atacante tentando criar uma conta local para persistência no sistema através do comando:
  `net user /add A1berto paw0rd1`

* **Query de Baseline (Processos mais comuns):**
'''splunk
  index=windowslogs | top Image

    Análise Técnica: O processo legítimo C:\windows\system32\svchost.exe foi identificado no topo da atividade com 1.642 ocorrências (38.8% do volume de logs), o que se enquadra na atividade normal do sistema operacional.

    Nota de Aprendizado: Durante a execução, observamos a estrita necessidade de seguir a regra case-sensitive do Splunk. A busca pelo campo em minúsculo (image) falhou (retornando No results found), exigindo a correção imediata para o padrão indexado (Image).

2. Enriquecimento de Dados & Threat Intelligence

Para acelerar a triagem de alertas no SOC, utilizei técnicas de cruzamento de dados nativas do Splunk para correlacionar indicadores brutos com inteligência de ameaças.
A. Análise de Risco com Tabelas de Lookup Externalizadas

Cruzamento do campo de processos ativos (Image) com uma base de dados externa de reputação (image_riskscore) para isolar binários de alto impacto baseando-se em uma métrica de criticidade (RiskScore).
Snippet de código

index=windowslogs 
| lookup image_riskscore Image OUTPUT RiskScore 
| stats count by Image RiskScore 
| sort - RiskScore

Campo Image (Caminho do Binário)	RiskScore	Significado Analítico
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe	10	Crítico: Indica potencial abuso de LOLBins (Living off the Land Binaries) para execução de scripts arbitrários em memória.
C:\Windows\System32\lsass.exe	9	Alto: Alvo comum para técnicas de Credential Dumping (ex: Mimikatz).
B. Geolocalização de Acessos Suspeitos

Aplicação do comando iplocation para converter IPs brutos em coordenadas geográficas e regiões administrativas, rastreando a origem de vetores externos de ataque.
Snippet de código

index=windowslogs | iplocation SourceIp | stats count by Region

    Resultado: Identificação de um volume anômalo de conexões concentrado na região da California, validando a necessidade de isolamento de rede do IP de origem.

3. Detecção Avançada de Anomalias (UBA)

Na última fase, o foco mudou para a análise do comportamento dos usuários em logs de VPN (index=vpnlogs). Foi implementada uma query avançada utilizando Z-Score para calcular desvios-padrão de comportamento e isolar outliers de horário de login.
Snippet de código

index=vpnlogs
| eval hour=tonumber(strftime(_time, "%H")) + tonumber(strftime(_time, "%M"))/60
| eventstats avg(hour) as typical_hour stdev(hour) as stdev_hour by user
| eval zscore=abs(hour - typical_hour) / stdev_hour
| where zscore > 3
| eval hour=round(hour, 2), typical_hour=round(typical_hour, 2), stdev_hour=round(stdev_hour, 2), zscore=round(zscore, 2)
| table _time user src_ip src_country hour typical_hour stdev_hour zscore
| sort - hour_zscore

🚨 Achados Críticos (Outliers Detectados):

    Desvio de Perfil Horário (njackson): O usuário autenticou-se na VPN às 03:17 da manhã (hour = 3.28), sendo que o seu horário típico histórico de acesso registrado era às 13:50 (typical_hour = 13.50). Essa ação gerou um Z-Score de 5.49, classificando o evento como uma anomalia comportamental grave (potencial comprometimento de credencial).

    Desvio de Origem Geográfica (jsmith): Identificação de login bem-sucedido a partir de um país completamente anômalo ao histórico padrão do colaborador.

🎯 Conclusões e Aprendizados

    Estrutura de Sintaxe: Consolidação do entendimento sobre o comportamento case-sensitive do Splunk e a necessidade de validação estrita de strings na construção de regras de detecção.

    Redução de Falsos Positivos: A criação de baselines estatísticos (como a contagem de processos volumosos estáveis) provou-se essencial para limpar o ruído do painel de monitoramento do analista de SOC.

    Automação Estatística: O uso de funções como eventstats combinadas com operadores lógicos avançados permite que detecções fujam de simples assinaturas estáticas e passem a procurar desvios dinâmicos de comportamento (UBA).

Nota: Este projeto faz parte do meu desenvolvimento contínuo em Security Operations e Threat Hunting.

* **Query de Baseline (Processos mais comuns):**
'''splunk
  index=windowslogs | top Image
