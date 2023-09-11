4. (2) Pretende-se desenvolver um novo esquema criptográfico, HCA, para enviar uma mensagem com confidencialidade e autenticidade entre dois participantes (A e B). Assume-se que A conhece a chave pública de B (KeB) e que a chave simétrica k muda em cada comunicação. O novo esquema usa cifra assimétrica (Ea), cifra simétrica (Es) e MAC (T). O símbolo || representa a concatenação: 
HCA(KeB,k,m) = Ea(KeB)(k)||Es(k)(m)||T(k)(m)
Descreva como é feita a decifra e verificação de autenticidade da mensagem ‘m’, nomeadamente a ordem de operações e as chaves utilizadas (identifique claramente as chaves e indique o seu papel no esquema).

```
Decifração e Verificação de Autenticidade por B:

a. B recebe a mensagem criptografada 'c' de A: c = HCA(KeB, k, m) = Ea(KeB)(k) || Es(k)(m) || T(k)(m)

b. B começa por decifrar a parte da chave simétrica (k) usando a sua chave privada, que é KeB. Isso resulta na recuperação da chave simétrica original 'k'.

c. Usando a chave simétrica 'k', B descriptografa a parte da mensagem cifrada simetricamente (m) usando o algoritmo de criptografia simétrica 'Es'. Isso recupera a mensagem original 'm'.

d. Em seguida, B verifica a autenticidade da mensagem usando o código de autenticação de mensagem (MAC) T. Ele aplica o algoritmo MAC com a chave 'k' para a mensagem 'm' e compara o resultado com a parte do MAC presente na mensagem 'c'. Se os valores coincidirem, a autenticidade é verificada.

Resumindo, B realiza as seguintes etapas na decifração e verificação de autenticidade da mensagem 'm':

Decifra a parte da chave simétrica usando a sua chave privada (KeB) para obter a chave simétrica 'k'.
Descriptografa a parte da mensagem usando a chave simétrica 'k'.
Verifica a autenticidade da mensagem usando o código de autenticação de mensagem (MAC) aplicado à mensagem 'm' com a chave 'k'.
Esse esquema combina criptografia assimétrica (para compartilhar a chave simétrica), criptografia simétrica (para criptografar a mensagem) e um MAC (para garantir autenticidade) para fornecer confidencialidade e autenticidade à mensagem 'm' entre A e B.

HCA1(KeC,k,m)
HCA1 -> esquema criptográfico de decifra
KeC -> chave privada de B
k -> chave simétrica
m -> mensagem
Ea -> cifra assimétrica (para a troca de chaves)
Es -> cifra simétrica (para a criptografia da mensagem)
T -> verificação de autenticidade (MAC)

HCA1(KeC,k,m)=Ea(KeC)(k)||Es(k)(m)||T(k)(m)

```

Considere o diagrama da figura, onde são apresentadas duas hierarquias de certificados semelhantes às usadas no trabalho. CA-X e CA-Y são raízes de confiança, e KsA,KsB,KsC,KsR,KsT são chaves privadas associadas aos respetivos certificados. Assuma que Bob (cliente) irá estabelecer uma sessão TLS com o servidor-R com autenticação do cliente. Indique, usando os identificadores a figura, o menor conjunto de certificados e chaves privadas que devem ser instalados no cliente e no servidor.

O diagrama da figura é assim

Alice, Bob, Carol é assinado pelo Int-X que porventura é assinado por um certificado de confiança/raiz CA-X
Alice tem chave privada KSA
Bob tem chave privada KSB
Carol tem chave privada KSC

servidor-R e servidor T é assinado pelo Int-Y que porventura é assinado por um certificado de confiança/raiz CA-Y
servidor-R tem chave privada KSR
servidor-T tem chave privada KST

```
Para estabelecer uma sessão TLS com autenticação do cliente entre Bob (cliente) e o servidor-R, irá ser necessário instalar os seguintes certificados e chaves privadas:

No Cliente (Bob):

Certificado de Bob (identificado como "Bob") assinado por Int-X.
Chave privada de Bob (KSB).
Certificado de confiança/raiz CA-X.

No Servidor-R:

Certificado do servidor-R (identificado como "servidor-R") assinado por Int-Y.
Chave privada do servidor-R (KSR).
Certificado de confiança/raiz CA-Y.
Isso permitirá que Bob se autentique para o servidor-R durante a negociação da sessão TLS. O servidor-R poderá então verificar a autenticidade do cliente (Bob) usando o certificado de Bob assinado por Int-X e a chave privada correspondente (KSB).

Observe que o servidor-R não precisa da chave privada de Bob. Ele precisa apenas do certificado de Bob para verificar a autenticidade do cliente durante o processo de autenticação do cliente TLS.
```

ALTERAÇÃO

Considere o diagrama da figura, onde é apresentada uma hierarquia de certificados semelhantes às usadas no trabalho. CA-Y é raíz de confiança, e KsA,KsB,KsC,KsR,KsT são chaves privadas associadas aos respetivos certificados. Assuma que Bob (cliente) irá estabelecer uma sessão TLS com o servidor-R com autenticação do cliente. Indique, usando os identificadores a figura, o menor conjunto de certificados e chaves privadas que devem ser instalados no cliente e no servidor.

O diagrama da figura é assim

Alice, Bob, Carol é assinado pelo Int-X que porventura é assinado por um certificado de confiança/raiz CA-Y
Alice tem chave privada KSA
Bob tem chave privada KSB
Carol tem chave privada KSC

servidor-R e servidor T é assinado pelo Int-Y que porventura é assinado por um certificado de confiança/raiz CA-Y
servidor-R tem chave privada KSR
servidor-T tem chave privada KST

```
No Cliente (Bob):

Certificado de Bob (identificado como "Bob") assinado por Int-X.
Chave privada de Bob (KSB).
Certificado Int-X (identificado como "Int-X") assinado por CA-Y.
Certificado de confiança/raiz CA-Y.

No Servidor-R:
Certificado do servidor-R (identificado como "servidor-R") assinado por Int-Y.
Chave privada do servidor-R (KSR).
Certificado Int-Y (identificado como "Int-Y") assinado por CA-Y.
Certificado de confiança/raiz CA-Y.
```

Considere o diagrama da figura, onde é apresentada uma hierarquia de certificados semelhantes às usadas no trabalho. CA-Y é raíz de confiança, e KsA,KsB,KsC,KsR,KsT são chaves privadas associadas aos respetivos certificados. Assuma que Bob (cliente) irá estabelecer uma sessão TLS com o servidor-R com autenticação do cliente. Indique, usando os identificadores a figura, o menor conjunto de certificados e chaves privadas que devem ser instalados no cliente e no servidor.

O diagrama da figura é assim

Alice, Bob, Carol é assinado pelo certificado de confiança/raiz CA-Y
Alice tem chave privada KSA
Bob tem chave privada KSB
Carol tem chave privada KSC

servidor-R e servidor T é assinado pelo Int-Y que porventura é assinado por um certificado de confiança/raiz CA-Y
servidor-R tem chave privada KSR
servidor-T tem chave privada KST

```
No Cliente (Bob):

Certificado de Bob (identificado como "Bob") assinado por CA-Y.
Chave privada de Bob (KSB).
Certificado de confiança/raiz CA-Y.

No Servidor-R:
Certificado do servidor-R (identificado como "servidor-R") assinado por Int-Y.
Chave privada do servidor-R (KSR).
Certificado Int-Y (identificado como "Int-Y") por CA-Y.
Certificado de confiança/raiz CA-Y.
```

Considere o sub-protocolo handshake do protocolo TLS.
6.1. (1,5) Descreva o mecanismo criptográfico utilizado quando é necessária a autenticação de cliente, nomeadamente as chaves e as mensagens envolvidas?

```
Chaves de Criptografia:

Chave Privada do Cliente: Cada cliente que deseja se autenticar possui uma chave privada exclusiva que só ele conhece. Essa chave é mantida em sigilo e é usada para assinar digitalmente as mensagens durante o processo de handshake.
Certificado Digital do Cliente: O cliente também possui um certificado digital que contém sua chave pública. Esse certificado é emitido por uma Autoridade Certificadora (CA) confiável e é usado pelo servidor para verificar a autenticidade do cliente.
Mensagens Envolvidas:
O processo de handshake do TLS envolve várias mensagens trocadas entre o cliente e o servidor. Aqui estão as mensagens mais relevantes quando a autenticação do cliente é necessária:

ClienteHello: O cliente inicia o processo enviando uma mensagem ClientHello, que contém informações sobre as versões do TLS suportadas, algoritmos de criptografia disponíveis e outros parâmetros.

ServerHello: O servidor responde com uma mensagem ServerHello, escolhendo uma versão do TLS, um conjunto de criptografia e outros parâmetros. Se a autenticação do cliente for necessária, o servidor também solicitará ao cliente que apresente seu certificado digital.

Certificate: Se o servidor solicitar o certificado do cliente, o cliente enviará seu certificado digital nesta mensagem. O certificado contém sua chave pública e é assinado pela CA.

ClientKeyExchange: O cliente gera uma chave de sessão secreta (premaster secret) e a criptografa com a chave pública do servidor (do certificado do servidor) e envia para o servidor. O servidor usará sua chave privada para descriptografar a chave de sessão.

Finished: Após todas as etapas anteriores serem concluídas com sucesso, tanto o cliente quanto o servidor geram uma mensagem Finished, que é usada para verificar a integridade dos dados trocados e confirmar que a conexão é autêntica e segura.

O processo acima descreve a autenticação do cliente no TLS, onde a chave privada do cliente e o certificado digital são os principais mecanismos criptográficos. A combinação de criptografia assimétrica (usada para a troca de chaves) e criptografia simétrica (usada para a comunicação real após o handshake) garante a segurança e a autenticidade da conexão.
```

```
Estabelecimento da Conexão:

O cliente inicia a comunicação com o servidor enviando uma mensagem SYN (synchronize).
O servidor aceita a comunicação enviando uma mensagem SYN-ACK (synchronize-acknowledgment).
O cliente informa ao servidor que a mensagem foi recebida enviando uma mensagem ACK (acknowledgment).
Negociação:

O cliente envia a mensagem HELLO_CLIENT não criptografada para o servidor, incluindo a versão TLS, uma mensagem aleatória, um identificador de sessão e uma lista de suites de cifra suportadas.
O servidor responde com a mensagem HELLO_SERVER, incluindo a versão TLS, a mensagem aleatória do cliente, o identificador de sessão e a suite de cifra mais forte suportada por ambos.
Se a versão TLS ou a suite de cifra proposta pelo cliente não estiver disponível no servidor, a comunicação é interrompida.
Autenticação do Servidor:

Uma vez que os algoritmos tenham sido negociados, o servidor se autentica enviando seu certificado X.509 (mensagem Certificate).
O servidor pode, opcionalmente, enviar sua chave pública para que o cliente possa criptografar a chave de sessão (Server Key Exchange).
Dependendo da configuração do servidor, ele pode solicitar ao cliente seu certificado com a mensagem Client Certificate Request.
O cliente verifica o formato, data de expiração, status e confiança do certificado do servidor. Se alguma dessas verificações falhar, a transação é abandonada.
Por fim, o servidor envia a mensagem Server Hello Done para indicar que terminou.
Autenticação do Cliente e Geração da Chave de Sessão:

O cliente envia seu próprio certificado para o servidor (Client Certificate) se solicitado.
O servidor realiza verificações semelhantes às realizadas pelo cliente (ver ponto 3) no certificado do servidor.
O cliente cria uma pré-chave-mestra, criptografa-a com a chave pública do certificado do servidor e a envia ao servidor via mensagem Client Key Exchange. Esta chave secreta permite a geração de chaves de sessão compartilhadas entre cliente e servidor.
Se o cliente enviou seu certificado, ele também envia a mensagem Certificate Verify contendo a impressão digital de todas as mensagens anteriores assinadas com sua chave privada. Isso prova que o cliente possui a chave privada associada ao certificado.
Fim do Handshake TLS:

O cliente envia mensagens Change Cipher Spec e Finished, que são criptografadas e assinadas com as chaves mencionadas anteriormente, para indicar que o túnel TLS está estabelecido.
O servidor faz o mesmo, e o Handshake termina.
Cliente e servidor agora se comunicam de acordo com o protocolo Record, garantindo confidencialidade e integridade das mensagens trocadas.
```

No cenário apenas com autenticação de servidor, qual a proteção que existe para detetar ataques de repetição, nos quais o atacante tenta reutilizar as mensagens de cliente de um handshake anterior?

```
O sequence number é um valor aleatório que é gerado em cada novo handshake e não é reutilizado em conexões subsequentes. Isso impede que um atacante reutilize as mensagens do cliente de um handshake anterior em uma tentativa de repetição.

Aqui está como a proteção contra ataques de repetição é alcançada:

Geração de sequence number: Tanto o cliente quanto o servidor geram um sequence number aleatório durante a fase de negociação do handshake. Esse valor é incluído nas mensagens enviadas durante o handshake.

Verificação do sequence number: O servidor verifica se o sequence number recebido do cliente é válido e não foi usado em uma conexão anterior. Isso é importante para garantir que as mensagens do cliente sejam frescas e não tenham sido repetidas de uma conexão anterior.

Controle de Estado: Para manter o controle do estado das conexões e dos sequence numbers usados, o servidor deve manter registos das conexões TLS recentes, garantindo que sequence numbers previamente usados não sejam aceito em uma nova conexão.

Ao adotar essas medidas, o TLS ajuda a proteger contra ataques de repetição, pois os sequence numbers garantem que as mensagens do cliente sejam únicas em cada handshake. Qualquer tentativa de reutilizar mensagens de cliente de um handshake anterior será detectada e rejeitada pelo servidor, tornando mais difícil para um atacante repetir com sucesso um handshake TLS.
```

Considere um sistema de armazenamento de palavras-passe as quais são armazenadas na forma hu = H(pwdu), sendo H um função de hash e pwdu a palavra-passe do utilizador u. Descreva um ataque a esta forma de armazenamento que não implique a utilização da interface de autenticação. Descreva também uma solução para o problema identificado. Admita que a função H é conhecida do atacante.

```
Ataque: Força Bruta e Ataques de Dicionário

Nesses ataques, um atacante tenta adivinhar a senha original de um usuário calculando repetidamente os hashes e comparando-os com o hash armazenado. Isso pode ser feito testando várias combinações de senhas, começando com as mais comuns (ataque de dicionário) ou tentando todas as combinações possíveis (força bruta). Uma vez que a função de hash H é conhecida do atacante, ele pode calcular facilmente o hash de uma senha candidata e compará-lo com o hash armazenado.

Solução: Salt (Sal) e Iterações

Para mitigar esse tipo de ataque, é recomendável usar uma técnica chamada "salt" (sal) e adicionar iterações ao processo de hashing. Aqui está como essa solução funciona:

Salt (Sal): Em vez de simplesmente calcular H(pwdu), você deve gerar um valor de salt aleatório exclusivo para cada usuário e concatená-lo à senha antes de calcular o hash. O salt é armazenado junto com o hash na base de dados, mas não precisa ser secreto.

salt é um valor aleatório exclusivo para cada usuário.
pwdu é a senha do usuário.
H é a função de hash.
O hash armazenado é então calculado como hu = H(salt + pwdu). Isso garante que, mesmo que dois usuários tenham senhas idênticas, seus hashes armazenados sejam diferentes devido ao uso de salts diferentes.

Iterações: Além disso, é recomendável aplicar iterações ao processo de hashing. Isso significa que a senha e o salt são passados pela função de hash várias vezes em sequência. Isso torna o processo de hashing mais lento, o que é desejável para dificultar ataques de força bruta.

hu = H(H(...H(salt + pwdu))) (um número definido de vezes)
```

Considere uma aplicação web que mantém estado de autenticação entre o browser e a aplicação servidor usando cookies. No cookie é guardado um JSON web token (JWT) com o identificador do utilizador. Como é que a aplicação servidor pode detetar se o conteúdo do cookie foi adulterado no browser?

```
Os JWTs são frequentemente usados para manter o estado de autenticação entre o navegador e o servidor, e eles incluem três partes: o cabeçalho (header), a carga útil (payload) e a assinatura (signature).

Aqui está como a verificação pode ser realizada:

Verifique a Assinatura: A aplicação do servidor deve ter uma chave secreta (ou um par de chaves pública/privada) que é usada para assinar os JWTs antes de enviá-los para o navegador. Quando um JWT é recebido de volta no cookie, o servidor verifica a assinatura do token usando a mesma chave secreta. Se a assinatura do token não corresponder ao esperado, isso indica que o token foi adulterado no navegador.

Validade do Token: Além disso, o servidor deve verificar se o token não expirou (com base na data de expiração definida na carga útil) e se ele ainda é válido para o usuário.

Segurança da Chave Secreta: É fundamental que a chave secreta usada para assinar e verificar os JWTs seja mantida em segurança e não seja compartilhada publicamente.
```

Considere uma aplicação web para gestão de projetos de software onde existe a possibilidade de acesso a diferentes recursos (ex: código, documentação, ficheiros de testes).

A biblioteca Casbin aplica políticas tendo por base dois ficheiros. Explique o objetivo destes dois ficheiros no processo de controlo de acesso, em particular no contexto das regras definidas.

Para realizar o controlo de acessos aos recursos foi definida a seguinte política RBAC1 que inclui os papéis (M)ember, (D)eveloper, (T)ester e (S)upervisor.
- U = {u1, u2, u3, u4}
- RH = {M está contido em T,M está contido em D,D está contido em S, T está contido em S, T está contido em T2,D está contido em D2}
- UA = {(u1,M), (u2, T2), (u3,D2), (u4, S)}
- PA = {(M, p1), (D, p2), (T, p3), (D2, p5), (T2, p4)}
Justifique qual o conjunto total de permissões que podem existir numa sessão com o utilizador u4?

```
U, R, P, S (users,roles,permissions e sessions)
UA -> User Assignment
PA -> Permission Assignment

M tem p1
D tem p2, p1
T tem p3, p1
D2 tem p5, p2, p1
T2 tem p4, p3, p1
S tem p2, p1, p3

M está contido em T
T tem M
M está contido em D
D tem M
D está contido em S
S tem D
T está contido em  S
S tem T
T está contido em T2
T2 tem T
D está contido em D2
D2 tem D

Conclusão o conjunto total de permissões que podem existir numa sessão com o utilizador u4 que está associado ao papel S é {p2, p1, p3}
```

```
Arquivo de Modelo (Model File .conf):

Objetivo: O arquivo de modelo é usado para definir a estrutura e a semântica das regras de controle de acesso em seu aplicativo. Ele especifica como as políticas são avaliadas e como as decisões de acesso são tomadas. O arquivo de modelo descreve as entidades envolvidas (como usuários, recursos e ações), bem como as regras de correspondência entre essas entidades.

Conteúdo: O arquivo de modelo geralmente contém definições de tipos de dados, funções, operadores lógicos e regras de correspondência. Ele define como os componentes do sistema se relacionam e como as políticas são expressas em termos desses componentes.

Exemplo: Um arquivo de modelo pode conter definições como "usuário", "recurso", "ação", "função", e regras de correspondência que especificam como os usuários são autorizados a realizar ações em recursos com base em suas funções.

Arquivo de Política (Policy File .csv):

Objetivo: O arquivo de política é onde as políticas de controle de acesso real são definidas. Ele contém as regras de autorização que determinam quem tem permissão para realizar quais ações em recursos específicos. O arquivo de política é onde você configura as políticas específicas de seu aplicativo.

Conteúdo: O arquivo de política inclui as regras de controle de acesso que relacionam entidades do mundo real (como usuários, papéis, recursos e ações) e definem as permissões e restrições associadas a essas entidades.

Exemplo: Um arquivo de política pode conter regras como "Usuário A tem permissão para ler o Recurso X" ou "Usuário B não tem permissão para excluir o Recurso Y".
```

No fluxo Authorization code grant do protocolo OAuth2 as mensagens são classificadas como sendo de front-channel ou back-channel. Explique a diferença entre os dois tipos de mensagens, incluindo a utilização do client_id e client_secret.

```
A diferença entre front-channel e back-channel no fluxo "Authorization Code Grant" do OAuth 2.0 está relacionada ao canal de comunicação utilizado para transmitir as mensagens. O front-channel é visível para o usuário e geralmente usado para redirecionamentos, enquanto o back-channel é confidencial e utilizado para comunicação direta entre os servidores, incluindo a troca de códigos de autorização por tokens de acesso. O client_id é usado em ambos os canais, mas o client_secret é uma credencial sensível que nunca deve ser exposta no front-channel e deve ser usada apenas no back-channel para autenticação do aplicativo junto ao servidor de autorização.
```