# Funções HASH Criptográficas

## Resumo

Uma função hash processa uma mensagem de tamanho arbitrário (qualquer número de bytes) e cria a partir dela uma sequência de bytes de tamanho fixo.

Ela deve ser uma função unidirecional, ou seja, não deve ser possível (ao menos na prática) realizar sua inversa. Deve dar resultados iguais para mensagens iguais e resultados claramente diferentes para mensagens diferentes. Mesmo para mensagens parecidas (ao menos na prática) realizar sua inversa. Deve dar resultados iguais para mensagens diferentes. Mesmo para mensagens parecidas (trocando ou adicionando um bit ou uma letra) a diferença no resultado deve ser bem evidente.

Atualmente existem dois padrões de função hash considerados criptograficamente seguros: SHA2 e SHA3.

Ambos padrões definem hashes de diferentes tamanhos de saída e, consequentemente, diferentes níveis de segurança criptográficos: 224, 256, 384 e 512 bits.

Para uma aplicação que exige n bits de segurança criptográfica, usa-se uma hash com 2n bits de saída. Por exemplo, se eu preciso de 128 bits de segurança eu vou utilizar SHA-256 (SHA2) ou SHA3-256, que possuem o dobro de bits de saída.

Na dúvida ou se não estiver especificado, utilize 128 bits de segurança.

## Para que serve uma função Hash?

As funções hash serve, para ser utilizadas para diferentes propósitos

Integridade de dados. Pode ser utilizada para confirmar que uma mensagem (ou arquivo) foi enviado corretamente. Quem envia a mensagem manda junto o seu hash. Quem recebe a mensagem calcula a hash da mensagem e compara com a recebida.

Assinatura digital. Diretamente assinar digitalmente uma mensagem (ou arquivo) de tamanho arbitrário é complicado. Especialmente se muito grande exigiria chaves criptográficas tão grandes quanto as mensagens. A assinatura digital então é realizada sobre a hash da mensagem, que tem um comprimento fixo.

## Funções Hash Criptográficas

Funções hash criptográficas, além de associar uma saída de tamanho fixo com uma mensagem de tamanho arbitrário, tem objetivo de resistir a ataques criptográficos. Dessa forma elas podem ser utilizadas em conjunto com esquemas de criptografia

Pra isso ela deve resistir a três diferentes ataques: pré-imagem, segunda pré-imagem e colisão.

## Ataque Pré-imagem de Hash

Deve ser muito difícil (praticamente impossível) de encontrar uma mensagem x que gere uma hash pré-definida y. Ou seja, a função hash não deve ser invertível.

Por exemplo, o só génio da lâmpada poderia atender a este desejo:
"Eu quero encontrar uma mensagem cujo valor da SHA3.256 é e05dbb98c0c3665c1c95290a8c2245ba32ad7e366502f2a5fdb37b4001054692."
Talvez nem ele.

Resposta: Uma palavra, dez letras, sem acentos, tudo minúsculo. Se calcular SHA3-224 dá 80ab895e2f664ab13a76581f41e8226a85540d5d9617eab2c29a5792.
Quer tentar? Você tem 26^10

Alguém capaz de realizar a pré-imagem, pode descobrir qual a mensagem a partir de sua hash.

De onde vem esse nome "pré-imagem"? Vem do conteúdo de matemática chamado funções. Uma função y=f(x) tem seu domínio (valores de x) e sua imagem (valores de y). Para uma função hash, o algoritmo é f, o domínio são as mensagens x e a imagem são os valores das hashes y. Pré-imagem significa ter a imagem e, a partir dela, determinar, determinar o domínio correspondente (como uma função inversa).

## Ataque Segunda Pré-imagem de Hash

Se eu tenho uma mensagem x1 que tem uma hash y, deve ser muito difícil (praticamente impossível) de encontrar uma mensagem diferente x2 que dê a mesma hash y.

Mas este ataque considera que o atacante conhece a mensagem original e que descobrir uma segunda mensagem com a mesma hash. Ou seja, conhecer a mensagem não deve dar nenhuma vantagem adicional para um ataque.

Eis aqui mais um pedido para o génio da lâmpada:
"Eu quero uma mensagem diferente que dê a mesma SHA3-256 que 'Olá, banco! Envie 1,000,00$ para oscar. Obrigado!'"

Alguém capaz de realizar a segunda pré-imagem, pode forjar assinaturas digitais. Pode trocar a mensagem assinada por uma outra mensagem, sem que isso seja percebido.

De onde vem esse nome "segunda pré-imagem"? Já temos uma pré-imagem: a pré-imagem de y é x1. Mas queremos uma segunda pré-imagem x2.

## Ataque Colisão de Hash

Deve ser muito difícil (praticamente impossível) de encontrar duas mensagens diferentes x1 e x2 que dão uma mesma hash y.

Mas este ataque não faz nenhuma restrição com respeito as mensagens, nem ao valor da hash.

Eis aqui mais um pedido para o génio da lâmpada: 
"Eu quero duas mensagens diferentes que dão a mesma SHA3-256. Não importa qual valor final da hash"

Alguém capaz de realizar colisões pode gerar muita confusão e dor de cabeça em sistemas que dependem de hashes.

De onde vem esse nome "colisão"? Imagine que as mensagens são carros e o resultado da hash seja a vaga do estacionamento que devem usar. Mesmo quando da mesma marca, modelo, ano... são carros diferentes e vão estacionar em vagas diferentes. Dois carros querendo entrar na mesma vaga geram uma colisão.