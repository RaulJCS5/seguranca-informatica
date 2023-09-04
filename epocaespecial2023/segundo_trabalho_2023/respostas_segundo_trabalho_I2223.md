# Respostas Segundo trabalho, Semestre de Inverno de 22/23

1. Considere o protocolo TLS e as infraestruturas de chave pública:

    a) De que forma é garantida a autenticidade nas mensagens no _record protocol_?

    ```text
        O que é garantir a autenticidade?
            É o que garante a verdadeira autoria da informação, ou seja, que os dados são de fato provenientes de determinada fonte.
        Tendo em conta o protocolo TLS e as infraestruturas de chave pública a autenticidade das mensagens no record protocol é garantida por meio da utilização de chaves MAC separadas para cada direção e pela criptografia simétrica baseada em streams. Um algoritmo MAC, algumas vezes chamado de função de dispersão chaveada (criptografia), recebe como entrada uma chave secreta e uma mensagem de tamanho arbitrário para ser autenticado, e dá como saída um MAC(tag). O valor MAC protege tanto a integridade dos dados da mensagem, assim como a sua autenticidade, permitindo aos verificadores (que também possuem a chave secreta) detetar quaisquer mudanças no conteúdo na mensagem.
    ```

    b) O sub-protocolo handshake assume que o canal de comunicação não envia/recebe mensagem com confidencialidade nem integridade. Sendo assim, como é que o _handshake_deteta a inserção ou adulteração maliciosa de mensagens?

    ```text
    O sub-protocolo handshake deteta a inserção ou adulteração maliciosa de mensagens é detetado com a mensagem __Finished__, a mensagem __Finished__ garante que ambos os endpoints recebem a mesma mensagem. Isso é alcançado também através do uso de assinaturas digitais, cálculos MAC e outros mecanismos de segurança incorporados no protocolo handshake
    ```

    c) Considere a versão do TLS em que o _pre-master secret_ é estabelecido usando chaves públicas e privadas. Porque motivo esta forma de estabelecimento de chaves não garante a propriedade _perfect forward secrecy_

    ```text
    Como garantir perfect forward secrecy?
        Perfect forward secrecy é a propriedade do handshake que garante que, se a chave privada for comprometida, não é possível decifrar master secret anteriores (e consequentemente não é possível decifrar mensagens do record protocol)
    O que acontece na versão do TLS em que o pre-master secret é estabelecido usando chaves públicas e privadas é que se a chave privada for comprometida o pre-master secret dos handshakes seguintes e dos anteriores (guardados pelo  atacante) podem ser decifrados.
    ```

2. Considere uma aplicação web onde as passwords são armazenadas na forma hu=H(pwdu||saltu), sendo H uma função de hash, pwdu a password do utilizador u e saltu um número aleatório gerado no momento do registo do utilizador u, em que || indica a concatenação de bits.

Devido a um erro de programação, a informação sobre os utilizadores, hashs e respetivos salts, ficou exposta numa página da aplicação web. Discuta se este erro facilita um ataque um ataque de dicionário através da interface de autenticação onde o número de tentativas é limitado.

    ```text
    A exposição sobre os utilizadores ,hashs e respetivos salts pode, de fato, facilitar um ataque de dicionário mas como o número de tentativas de autenticação é limitado dificulta muito o ataque. Com os hashes e os salts dos usuários expostos, um atacante tem acesso a informação valiosa. O hash é o resultado da aplicação de uma função de hash com a password do utilizador concatenada com o salt especifico para esse utilizador. O salt é projetado para ser único para cada utilizador e adicionado à password antes do hash para tornar os hashes mais seguros. No contexto de autenticação, um ataque de dicionário envolve o atacante tentar várias passwords possíveis, aplicando a mesma função de hash com o salt correspondente e comparando o resultado com os hashes expostos na página. Caso o resultado da função de hash coincidir com o hash, o atacante terá encontrado a password correspondente. A limitação de tentativas é uma defesa comum contra ataques de dicionário. No entanto, quando o atacante tem acesso aos hashes e aos salts, ele pode realizar tentativas limitadas. Isso torna o ataque mais lento, mas ainda viável
    ```

3. Considere uma aplicação web que guarda no browser cookies contendo o par (u,H(u)), sendo u o identificador de um utilizador e H uma função de hash. Assuma que a construção do cookie é conhecida. A comunicação entre browser e aplicação é feita sobre HTTPS.

    a) Como poderia um atacante fazer-se passar por outro utilizador para o qual sabe o seu identificador?

    ```text
    O atacante poderia fazer-se passar por outro utilizador para o qual sabe o seu identificador ao criar um cookie falso com o identificador do utilizador alvo e o seu valor de hash, com esse cookie falso enviar ao aplicativo e so o aplicativo aceitar esse cookie falso como válido, ele acreditará que o atacante é o utilizador associado ao identificador.
    ```

    b) Que alterações propõe para evitar o ataque anterior?

    ```text
    Para evitar o ataque anterior seria importante implementar práticas de segurança fortes, incluindo proteger a integridade dos dados dos cookies, garantir uma gestão segura de sessões, implementar mecanismos de autenticação adequados e monitorizar regularmente o aplicativo em busca de vulnerabilidades. 
    ```

4. Considere a norma OAuth 2.0 e OpenID Connect no fluxo authorization code grant:

    a) O valor indicado no scope é determinado pela aplicação cliente ou pelo dono de recursos?

    ```text
    O valor indicado no scope é determinado pela aplicação cliente. Estes scopes representam as permissões que o cliente está a solicitar para acessar recursos em nome do utilizador.
    ```

    b) Em que situações o cliente e o servidor de autorização comunicam indiretamente através do browser do dono de recursos?

    ```text
    As situações em que o cliente e o servidor de autorização comunicam indiretamente através do browser do dono de recursos é no redirecionamento da página Login, por exemplo quando um utilizador tenta acessar um recurso protegido por uma aplicação cliente e não está autenticado, a aplicação cliente redireciona o utilizador para o servidor de autorização. Quando existe consentimento após a autenticação bem sucedida com servidor de autorização que mostra uma tela de consentimento no browser do dono de recursos.
    ```

    c) Qual a diferença entre o access_token e o id_token?

    ```text
    Quando é utilizado o id_token assume que o utilizador é autenticado e obtém acesso a dados do utilizador e não verifica se o cliente é permitido o acesso a algo, quando é utilizado access_token verifica se o cliente é permitido para aceder a algo e inspeciona o seu conteúdo no lado do servidor
    ```

    ```text
    Informação Extra:
    access_token -> O access_token é usado para autorizar e autenticar solicitações a recursos protegidos, como APIs. Geralmente, o access_token é enviado no cabeçalho das solicitações HTTP para recursos protegidos, permitindo que o servidor de recursos (resource server) verifique se o cliente tem permissão para acessar o recurso solicitado.
    Contém informação sobre permissões (scopes) concedidas ao cliente (geralmente um ID de cliente), mas não contém informações detalhadas sobre o utilizador.
    id_token -> O id_token é usado especificamente no contexto do OpenID Connect para fornecer informações de identidade do utilizador identificado (perfil do utilizador ex.: nome, email, etc.). Contém informações de identificação do utilizador e, em alguns casos, informações sobre o cliente e o Identity Provider.
    Em resumo, o access_token é usado para autorização de acesso a recursos protegidos, enquanto o id_token é usado para obter informações sobre a identidade do utilizador autenticado. O id_token é uma extensão do OAuth 2.0 que foi introduzida pelo OpenID Connect para permitir a autenticação federada e a obtenção de informações do utilizador em aplicativos que exigem autenticação e autorização.
    ```

5. Considere os modelos de controlo de acessos RBAC1.

    a) Em segurança da informação, o princípio de privilégio mínimo determinado que cada operação (ou conjunto de operações) deve ser realizada com o conjunto mínimo de permissões. De que forma a família de modelos RBAC contribui para implementação deste princípio?

    ```text
    Os modelos RBAC contribuem para a implementação do Princípio de Privilégio Mínimo fornecendo estruturas organizacionais e de permissões que garantem que os utilizadores tenham apenas as permissões que garantem que os utilizadores tenham apenas as permissões necessárias para desempenhar suas funções, ajudando a reduzir riscos de segurança e melhorar o controle de acesso em sistemas de informação.
    ```
    b) Na política RBAC1
    U={u1,u2}
    R={r0,r1,r2,r3,r4}
    P={pa,pb,pc}
    UA={(u1,r1),(u2,r2)}
    PA={(r0,pa),(r1,pb),(r4,pc)}
    RH={(r0<=r2),(r1<=r2),(r1<=r3),(r2<=r4),(r3<=r4)}

    Considere a existência da sessão s2, na qual está o utilizador u2. Neste contexto, o utilizador pretende aceder ao recurso W que exige a permissão pc, e pb. O utilizador u2 poderá aceder a este recurso?

    ```text
    (r0,pa)
    (r1,pb)
    (r4,pc)


    r0<=r2 r0 está contido em r2
    r1<=r2 r1 está contido em r2
    r1<=r3 r1 está contido em r3
    r2<=r4 r2 está contido em r4
    r3<=r4 r3 está contido em r4
    

    r2 tem pa
    r2 tem pb
    r2 tem pa e pb
    r3 tem pb
    r4 tem pc, pa e pb

    Se exige a permissão pc e pb para aceder ao recurso W o utilizador u2 não poderá aceder a este recurso pelo facto de ter apenas pa e pb
    ```

6. Configure um servidor HTTPS, sem e com autenticação de cliente. Tenha por base o ficheiro do servidor no repositório github da disciplina (nodeJS-TLS/http-server-base.js). Considere o certificado e chave privada do servidor www.secure-server.edu em anexo, o qual foi emitido pela CA1-int do primeiro trabalho.

=> No documento de entrega descreva sucintamente as configurações realizadas.

(a) Usando um browser, ligues-se ao servidor HTTPS sem e com autenticação de cliente Alice_2.

(b) Usando a JCA, realize uma aplicação para se ligar ao servidor HTTPS, sem autenticação de cliente

Tenha em conta as seguintes notas:

- Comece pelo cenário base: servidor HTTPS testado com cliente browser sem autenticação. Para executar o servidor tem de ter instalado o ambiente de execução node.js. Após a configuração mínima na secção options do ficheiro server.js, o servidor é colocado em execução com o comando:

  - node http-server-base.js

- Para converter ficheiros CER (certificados) e PFX (chave privada) para PEM use a ferramenta de linha de comandos OpenSSL. Existem vários guias na Internet sobre o assunto, tendo todos por base a documentação oficial [OpenSSL](https://www.openssl.org/docs/manmaster/man1/). Um exemplo de um desses guias pode ser visto aqui: [sslshopper](https://www.sslshopper.com/article-most-common-openssl-commands.html) O ficheiro secure-server.pfx não tem password.

- O certificado fornecido para configurar o servidor associa o nome www.secure-server.edu a uma chave pública. No entanto, o servidor estará a executar localmente, em localhost, ou seja, 127.0.0.1. Para browser aceitar o certificado do servidor, o nome do domínio que consta no URL introduzido na barra de endereços, https://www.secure-server.edu:4433 tem de coincidir com o nome do certificado. Para que o endereço www.secure-server.edu seja resolvido para localhost, terá de fazer a configuração adequada no ficheiro hosts, cuja localização varia entre diferentes sistemas operativos: https://en.wikipedia.org/wiki/Hosts_(file).