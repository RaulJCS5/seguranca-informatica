# Respostas Primeiro trabalho, Semestre de Inverno de 22/23

- 1.Considere um novo modo de operação definido por:

  - Seja _x = x1,...,xL_ a divisão nos blocos _xi_ do texto em claro _x_.
    - _RV_ é um vetor aleatório, com dimensão do bloco, gerado por cada texto em claro _x_
    - Seja _yi = E(k)(xi __XOR__ RV)_, para _i=1,...,L_, onde _E_ é a operação de cifra, _k_ é a chave da cifra, __XOR__ denota o ou-exclusivo bit a bit

    1.1. Defina o algoritmo de decifra para este modo de operação.

    ```
    cifra = yi = E(k)(xi XOR RV)

    - Algoritmo de decifra em pseudo-código:
        - Para cada bloco cifrado yi:
            1. Gerar o mesmo vetor aleatório RV como na cifra
            2. Calcular o bloco intermediário: bloco_inter = yi XOR RV
            3. Decifrar o bloco intermediário com a operação inversa da cifra E com a chave k para obter o bloco de texto em claro xi
            4. Adicionar xi ao texto em claro final

    decifra = zi = D(k)(E(yi XOR RV))

    1. yi XOR RV representa a combinação do bloco cifrado com o vetor aleatório para obter o bloco intermediário.
    2. E(yi XOR RV) denota a operação de decifra (operação inversa da cifra) aplicada ao bloco intermediário.
    3. D(k) representa a operação de decifra com a chave k, que transforma o bloco intermediário de volta para o bloco de texto em claro original
    ```

    1.2. Compare este modo de operação com o modo CBC quanto a:
    - possibilidade de padrões no texto em claro serem evidentes no texto cifrado
    - capacidade de paralelizar a cifra

    ```
    Como funciona o modo CBC(Cipher Block Chaining)?
        Sob o mesmo k e sob o mesmo IV, duas mensagens implicam criptogramas iguais.
        A cifra de um bloco de texto em claro afeta a cifra dos blocos seguintes, isto pode dificultar padrões no texto em claro, mas há a possibilidade de que padrões repetitivos no texto em claro (por exemplo, sequência de zeros) possam resultar em blocos de cifra repetitivos.
        A cifra de cada bloco depende do bloco anterior, impedindo assim que blocos individuais sejam cifrados em paralelo, já que cada bloco dependo do resultado do bloco anterior.
    Como funciona o modo descrito?
        Cada bloco de texto em claro é combinado com um RV antes da cifra, ou seja, mesmo que os blocos seguintes de texto em claro sejam iguais, o resultado será diferente devido à variação do RV.
        Cada bloco é cifrado independentemente devido ao uso do RV.
    Portanto, o modo descrito é mais robusto contra padrões no texto cifrado e também oferece uma capacidade superior de paralelização da cifra em comparação com o modo CBC
    ```

---

- 2.O RFC 4880, "OpenPGP Message Format", especifica a cifra de mensagens (denominadas objetos) como uma combinação entre esquemas assimétricos e simétricos:

``` En
[...] first the object is encrypted using a symmetric encryption algorithm. Each symmetric key is used only once, for a single object. A new "session key" is generated as a random number for each object (sometimes referred to as a session). Since it is used only once, the "session key" is bound to the message and transmitted with it. To protect the key, it is encrypted with the receiver's public key. [...]
```

``` Pt
primeiro o objeto é cifrado utilizando um algoritmo de cifra simétrica. Cada chave simétrica é usada apenas uma vez, para um único objeto. Uma nova "session key" é gerada como um numero aleatório para cada objeto (por vezes referida como session). Desde que seja utilizado apenas uma vez, a "session key" é unida à mensagem e transmitida a partir dela. Para proteger a chave, ela é cifrada com a chave pública do recetor(o que envia a mensagem)
```

Justifique a utilização desta abordagem com dois tipos de chave e explique sucintamente o processo de decifra de uma mensagem (object).

```
A abordagem de combinação de criptografia assimétrica e simétrica, conforme descrita no RFC 4880 (OpenPGP Message Format), é uma estratégia comum em sistemas de segurança para combinar a eficiência da criptografia simétrica com a conveniência da criptografia assimétrica.

1. Criptografia simétrica: A criptografia simétrica é mais rápida e eficiente em termos de processamento para cifrar grandes volumes de dados. No entanto, ela requer a mesma chave para a cifra e para a decifra de mensagens, que torna o sistema inseguro se esta chave for comprometida.

2. Criptografia Assimétrica: A criptografia assimétrica resolve o problema da partilha de chaves da criptografia simétrica, permitindo que as partes possuam pares de chaves públicas e privadas. A chave pública é utilizada por todos para cifrar as mensagens, enquanto que a chave privada é mantida em segurança para a decifra. No entanto, a criptografia assimétrica é mais lenta em comparação com a simétrica.

Processo de decifra de uma mensagem (objeto)

Geração da "session key": Um novo "session key" é gerado como um número aleatório exclusivo para cada objeto a ser cifrado
Criptografia simétrica do objeto: O objeto é cifrado usando um algoritmo de criptografia simétrica (ex.: Advanced Encryption Standard), com a "session key". Isto garante eficiência na cifra do conteúdo do objeto.
Criptografia da "session key": Para proteger a chave de sessão, ela é cifrada com a chave pública do recetor. Isso permite que apenas o recetor (que possui a chave privada correspondente) possa decifrar a "session key"
Transmissão do objeto cifrado: O objeto cifrado simetricamente e a "session key" cifrada assimetricamente são enviadas ao recetor.
Decifra pelo recetor: O recetor decifra a "session key" com a chave privada. Com a "session key" ele decifra o objeto cifrado simetricamente com um algoritmo de decifra simétrica.

Esta abordagem garante tanto a eficiência da criptografia simétrica na cifra do objeto quanto a segurança da criptografia assimétrica na proteção da "session key"
```

- 3.A engine classe Signature da JCA contém, entre outros, os seguintes métodos:

  - _void initSign(PrivateKey privateKey)_
  - _void initVerify(PublicKey publicKey)_
  - _void update(byte[] data)_
  - _byte[] sign()_
  - _boolean verify(byte[] signature)_

- 3.1.Explique sucintamente o processamento realizado internamente no método __sign__ com o objetivo de fazer a assinatura. Pode usar na explicação os métodos referidos que entenda relevantes.

```
Retorna os bytes de assinatura de todos os dados atualizados. O formato da assinatura depende do esquema de assinatura.

Uma chamada a este método reinicia o objeto de assinatura para o estado em que estava anteriormente inicializado para assinar via uma chamada para o {@code initSign(PrivateKey)}. Isto é, o objeto é reiniciado e disponível para gerar outra assinatura pelo assinante, se desejado, via uma nova chamada para {@code update} e {@code sign}

Retorna os bytes de assinatura do resultado da operação de assinatura
```

- 3.2.Considere que é instanciado um objeto __Signature__ com a transformação "RSAwithMD5". Se em virtude de uma vulnerabilidade detetada na função de hash _MD5_ for computacionalmente fazível, dado x, obter x' __DIFERENTE__ x tal que MD5(x')=MD5(x), quais as implicações deste ataque para as assinaturas geradas/verificadas pelas transformação referida

```
Se em virtude de uma vulnerabilidade detetada na função de hash MD5 for computacionalmente fazível, dado x, obter x' DIFERENTE x tal que MD5(x')=MD5(x), isto possibilitava um ataque de segunda pré-imagem. Um ataque deste género possibilitava a partir de duas mensagens diferentes obter os mesmo valor de hash MD5. No contexto do RSA com a transformação "RSAwithMD5", a assinatura digital é criada primeiro ao calcular o seu hash MD5 da mensagem e, em seguida, assinar esse hash com a chave privada RSA. Portanto se for possível encontrar duas mensagens diferentes que tenham o mesmo hash MD5, isso permitiria que um atacante replique uma assinatura válida de uma mensagem através de uma outra mensagem.

Um atacante poderia criar uma mensagem maliciosa (mensagem B) e calcular uma assinatura válida para essa mensagem com a técnica de segunda pré-imagem. A assinatura seria baseada no hash MD5 da mensagem B, mas como o hash MD5 seria o mesmo de uma mensagem legítima (mensagem A), essa assinatura também seria válida para a mensagem A. Portanto, o atacante teria conseguido falsificar uma assinatura legítima para a mensagem A, fazendo parecer que a mensagem A foi assinada pelo remetente original.

As assinaturas digitais tem como objetivo garantir a autenticidade e integridade das mensagens. Uma pessoa que verificasse a assinatura da mensagem A usando a chave pública correspondente à chave privada usada para gerar a assinatura, acreditaria que a mensagem A é autêntica e não foi alterada, quando, na realidade, ela poderia ter sido substituída por outra mensagem
```

- 4.Considere os certificados digitais X.509 e as infraestruturas de chave pública:

- 4.1 Em que situações é que a chave necessária para validar a assinatura de um certificado não está presente nesse certificado?

```
A chave necessária para validar a assinatura de um certificado não está presente nesse certificado quando ocorre o uso de uma cadeia de certificação PKIX(Public Key Infrastructure for the Internet). A PKI és um sistema de confiança que permite a geração, distribuição, gestão e validação de certificados digitais.

Dentro do PKIX existem duas chaves principais associadas a cada entidade que utilizam certificados digitais: a chave privada e a chave pública. A chave privada é mantida em segredo e é usada para assinar digitalmente documentos ou outros certificados, enquanto a chave pública é distribuída amplamente para permitir a verificação das assinaturas digitais.

Todos os certificados não auto-assinados não tem a chave (folha, cadeia...) incorporada no certificado
```

- 4.2Porque motivo a proteção de integridade dos certificados X.509 não usa esquemas MAC(Message Authentication Code)?

Informação Extra
---

Esquema MAC(Message Authentication Code)

A criptografia ajuda a impedir que as pessoas não autorizadas leiam uma mensagem, mas não as impede de adulterá-las. A alteração de uma mensagem (ainda que resulte em prejuízos. O MAC(Message Authentication Code)) ajuda a impedir a adulteração de mensagens. Por exemplo, considere o seguinte cenário:

- Bob e Alice compartilham uma chave secreta e concordaram em usar uma função MAC.
- Bob cria uma mensagem e a insere, juntamente com a chave secreta, em uma função MAC para recuperar um valor MAC.
- Bob envia a mensagem [não criptografada] e o valor mac para Alice em uma rede
- Alice usa a chave secreta e a mensagem como entrada para a função MAC. Ela compara o valor MAC gerado com o valor MAC enviado por Bob. Se forem idênticos, significa que a mensagem não foi alterada em trânsito.

Eva que está secretamente atenta à conversa entre Bob e Alice, não pode manipular efetivamente a mensagem. Ela não tem acesso à chave privada, portanto, não pode criar uma valor MAC que faria a mensagem adulterada parecer legítima para Alice.

Criar um MAC ajuda a garantir apenas que a mensagem original não foi alterada. Juntamente com o uso de uma chave secreta compartilhada, garante também que o hash de mensagem foi assinado por alguém com acesso a essa chave privada.

---

```
As assinaturas digitais oferecem não-repúdio, o que significa que o emissor não pode negar ter assinado o documento. A utilização de chaves Pública/Privada aproveitam o par, onde chave a chave privada é mantida em sigilo pelo emissor do certificado e a chave pública é divulgada para permitir a verificação das assinaturas. Isso permite que qualquer pessoa verifique a autenticidade do certificado sem precisar de uma chave secreta compartilhada, como seria o caso em esquemas MAC. A utilização de uma Cadeia de certificação, onde há uma Autoridade de Certificação de nível superior que emite certificados para entidades de níveis inferiores. As assinaturas digitais permitem a validação do certificado sem necessidade de um degredo compartilhado entre todas as entidades da cadeia.
```

- 4.3Qual a diferença entre ficheiros .cer e ficheiros .pfx?

```
O Windows usa a extensão .cer para um certificado X.509. Estes podem ser em "binário" (ASN.1 DER), ou pode ser codificado com Base-64 e ter um cabeçalho e rodapé aplicado (PEM). O Windows reconhecerá também. Para verificar a integridade de um certificado, você deve verificar a sua assinatura usando a chave pública do emissor que é, por sua vez, outro certificado. Estes apenas contém a chave pública.

O Windows usa .pfx para um arquivo PKCS #12. Esse arquivo pode conter uma variedade de informações criptográficas, incluindo certificados, cadeias de certificados, certificados de autoridade raiz e chaves particulares. Seu conteúdo pode ser protegido criptograficamente (com senhas) para manter as chaves privadas privadas e preservar a integridade dos certificados raiz. Estes contém ambas as chaves públicas e privada para um certo certificado.
```

Usando a biblioteca JCA, realize em Java uma aplicação para geração de hashs criptográficos de ficheiros. A aplicação recebe na linha de comandos i) o nome da função de hash e ii) o ficheiro para o qual se quer obter o hash. O valor de hash é enviado para o standard output.

Teste a sua aplicação usando certificados (ficheiros .cer) presentes no arquivo certificates-and-keys.zip em anexo a este enunciado. Compare o resultado com os valores de hash apresentados pelo visualizador de certificados do sistema operativo (ou outro da sua confiança)
