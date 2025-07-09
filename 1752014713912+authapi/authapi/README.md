# API de Autenticação Segura

## Sobre o Projeto

Esta é uma API de autenticação segura construída com Spring Boot. Ela permite que usuários se cadastrem, façam login e acessem recursos protegidos com segurança. O projeto foi desenvolvido para ser simples, ideal para aprender a criar um sistema de login com várias camadas de proteção, como senhas criptografadas, verificação de dois fatores (OTP), tokens JWT e limpeza de entradas para evitar ataques. A API segue o padrão **Domain-Driven Design (DDD)**, com uma estrutura organizada para facilitar a manutenção e a compreensão do código.

A API oferece:

- Cadastro de usuários com senha criptografada usando BCrypt.
- Login com verificação de senha e envio de um código OTP (mostrado no console e registrado no log).
- Verificação de OTP para autenticação de dois fatores.
- Tokens JWT para proteger endpoints.
- Um endpoint protegido (`/api/protected/resource`) que exige um token JWT válido.
- Logs detalhados de todas as ações salvos em `logs/authapi.log`.
- Interface interativa via Swagger UI para testar os endpoints.

## Como Funciona

1. **Cadastro**: O usuário envia seus dados (nome, username, email, senha, perfil e IP autorizado) para o endpoint `/api/auth/register`. As entradas são limpas para evitar ataques, e a senha é criptografada com BCrypt antes de ser salva no banco MySQL.
2. **Login**: O usuário envia username e senha para `/api/auth/login`. Se corretos, um código OTP é gerado, mostrado no console e salvo no log. Um token JWT inicial é retornado.
3. **Verificação de OTP**: O usuário envia o OTP para `/api/auth/verify-otp`. Se válido, um novo token JWT é gerado para acessar endpoints protegidos.
4. **Acesso Protegido**: O endpoint `/api/protected/resource` só pode ser acessado com um token JWT válido no header `Authorization: Bearer <token>`.

## Ferramentas Utilizadas

- **Spring Boot Starter Web**: Permite criar endpoints REST, como `/api/auth/register` e `/api/protected/resource`.
- **Spring Boot Starter Data JPA**: Conecta a API ao banco MySQL, usando Hibernate para gerenciar a tabela de usuários.
- **Spring Boot Starter Security**: Adiciona segurança, protegendo endpoints com autenticação JWT.
- **MySQL Connector/J**: Driver para conectar ao banco MySQL, onde os dados dos usuários são salvos.
- **JJWT (JSON Web Token)**: Biblioteca para gerar e validar tokens JWT, garantindo segurança nos endpoints protegidos.
- **Logback**: Registra todas as ações (cadastro, login, OTP, acessos) em `logs/authapi.log`.
- **Springdoc OpenAPI Starter WebMVC UI**: Gera uma interface Swagger UI para testar a API em `http://localhost:8080/swagger-ui/index.html`.
- **Jsoup**: Usado no `SanitizationUtil` para limpar entradas do usuário, evitando ataques como XSS.

## Estrutura do Projeto (DDD)

O projeto segue o padrão **Domain-Driven Design (DDD)**, organizado em camadas para separar as responsabilidades:

- **Domain**: Contém a lógica principal do negócio.
  - `model/User.java`: Representa a entidade usuário, com dados como nome, username, email e senha.
  - `service/UserDomainService.java`: Define o contrato para a lógica de autenticação, como validar credenciais e gerar OTPs.
  - `service/impl/UserDomainServiceImpl.java`: Implementa a lógica de autenticação, chamando o `EmailService` para simular o envio de OTPs.
  - `service/EmailService.java`: Simula o envio de OTPs (mostrados no console e salvos em `logs/authapi.log`). Em um sistema real, enviaria emails.
- **Application**: Orquestra as chamadas aos serviços do domínio.
  - `useCase/AuthUseCase.java`: Gerencia o fluxo de cadastro, login e verificação de OTP, chamando os serviços do domínio.
- **Infrastructure**: Contém implementações técnicas.
  - `repository/UserRepository.java`: Acessa o banco MySQL para salvar e buscar usuários.
  - `util/JwtUtil.java`: Gera e valida tokens JWT para autenticação segura.
  - `util/SanitizationUtil.java`: Limpa as entradas do usuário (como username e email) usando Jsoup para evitar ataques como XSS.
  - `config/JwtAuthenticationFilter.java` e `SecurityConfig.java`: Configuram a segurança com autenticação JWT.
  - `security/UserDetailsServiceImpl.java`: Integra com o Spring Security para carregar dados do usuário.
- **Interfaces**: Contém os controladores REST e os DTOs.
  - `controllers/AuthController.java`: Endpoints de autenticação (`/api/auth/register`, `/api/auth/login`, `/api/auth/verify-otp`).
  - `controllers/ProtectedRouteController.java`: Endpoint protegido (`/api/protected/resource`) acessível com token JWT.