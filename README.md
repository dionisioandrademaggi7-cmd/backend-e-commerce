 Backend de E-Commerce e Plataforma de Cursos

API RESTful desenvolvida para a gestão de plataformas de e-commerce e venda de conteúdos digitais protegidos. O projeto integra o gateway de pagamentos Stripe e implementa mecanismos de autenticação, autorização baseada em funções (RBAC) e restrição de acessos via paywall.

A aplicação foi submetida a auditorias práticas de segurança defensiva e ofensiva em ambiente de laboratório local (servidor Ubuntu vs. cliente de testes em Kali Linux), garantindo a proteção contra acessos não autorizados e a integridade do processo de pagamento.
Alem das ultimas auditorias de segurança foi feita a atualização do sistema de registro de produtos, antes o sistema de autenticação era todo baseado e montado unicamente para o unico produto que existia na pagina, apos essa alteração foi necessario alterar e adaptar o sistema de autenticação para os novos produtos
 Objetivo do Projeto

O objetivo deste projeto é fornecer uma solução de backend estruturada para a venda de produtos digitais, abordando duas necessidades centrais:

1. Controlo de Acesso e Monetização: Garantir que conteúdos restritos fiquem acessíveis exclusivamente a utilizadores autenticados e com transações ativas confirmadas via Stripe.
2. Segurança de APIs: Proteger os endpoints contra acessos anónimos, enumeração de recursos e manipulação de pedidos HTTP.
