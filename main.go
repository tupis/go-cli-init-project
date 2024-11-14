package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// runCommand executa um comando de shell
func runCommand(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Erro ao executar o comando %s %v: %v", name, args, err)
	}
}

// getProjectName solicita o nome do projeto
func getProjectName() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Digite o nome do projeto: ")
	projectName, _ := reader.ReadString('\n')
	return strings.TrimSpace(projectName)
}

// askUserOptions permite que o usuário escolha quais funcionalidades configurar
func askUserOptions() map[string]bool {
	options := make(map[string]bool)
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Escolha as opções para configurar (digite 'y' para sim ou 'n' para não):")

	fmt.Print("1. TypeORM (banco de dados relacional)? ")
	typeORMChoice, _ := reader.ReadString('\n')
	options["typeorm"] = strings.ToLower(strings.TrimSpace(typeORMChoice)) == "y"

	fmt.Print("2. Conexão com MongoDB (não-relacional)? ")
	mongoChoice, _ := reader.ReadString('\n')
	options["mongodb"] = strings.ToLower(strings.TrimSpace(mongoChoice)) == "y"

	fmt.Print("3. Redis? ")
	redisChoice, _ := reader.ReadString('\n')
	options["redis"] = strings.ToLower(strings.TrimSpace(redisChoice)) == "y"

	fmt.Print("4. GraphQL? ")
	graphqlChoice, _ := reader.ReadString('\n')
	options["graphql"] = strings.ToLower(strings.TrimSpace(graphqlChoice)) == "y"

	fmt.Print("5. WebSocket? ")
	websocketChoice, _ := reader.ReadString('\n')
	options["websocket"] = strings.ToLower(strings.TrimSpace(websocketChoice)) == "y"

	fmt.Print("6. Mensageria (RabbitMQ/Kafka)? ")
	messagingChoice, _ := reader.ReadString('\n')
	options["messaging"] = strings.ToLower(strings.TrimSpace(messagingChoice)) == "y"

	return options
}

// setupProjectStructure cria a estrutura de pastas para Clean Architecture
func setupProjectStructure() {
	directories := []string{
		"src/domain",
		"src/modules",
		"src/http",
		"src/http/controllers",
		"src/http/routes",
		"src/config",
		"src/shared",
		"src/shared/database",
		"src/shared/logger",
		"src/shared/middleware",
		"src/main",
		"src/utils",
	}
	for _, dir := range directories {
		os.MkdirAll(dir, 0755)
	}
}

// createExampleController cria um controlador de exemplo
func createExampleController() {
	controllerContent := `import { Request, Response } from "express";
import { getUserService } from "@modules/user/UserServiceFactory";
import { UserService } from "@modules/user/services/UserService";

export class UserController {
  constructor(private readonly userService: UserService = getUserService()) {}

  async create(request: Request, response: Response): Promise<Response> {
    const user = await this.userService.createUser(request.body);
    return response.status(201).json(user);
  }

  async getAll(request: Request, response: Response): Promise<Response> {
    const users = await this.userService.getAllUsers();
    return response.status(200).json(users);
  }

  async login(request: Request, response: Response): Promise<Response> {
    const token = await this.userService.authenticateUser(request.body);
    return response.status(200).json({ token });
  }
}
`
	os.WriteFile("src/http/controllers/UserController.ts", []byte(controllerContent), 0644)
}

// createFactories configura os arquivos de fábrica
func createFactories() {
	userServiceFactory := `import { UserRepository } from "./repositories/UserRepository";
import { UserService } from "./services/UserService";

export function getUserService(): UserService {
  const userRepository = new UserRepository();
  return new UserService(userRepository);
}
`
	os.MkdirAll("src/modules/user", 0755)
	os.WriteFile("src/modules/user/UserServiceFactory.ts", []byte(userServiceFactory), 0644)
}

func setupBaseEntity() {

	baseEntityContent := `import {
  BaseEntity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
} from "typeorm";

export class BaseSchema extends BaseEntity {
  @PrimaryGeneratedColumn("increment")
  id: number;

  @Column({ type: "uuid", generated: "uuid" })
  uuid: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @DeleteDateColumn()
  deletedAt: Date | null;
}
`
	os.MkdirAll("src/shared/database/entities", 0755)
	os.WriteFile("src/shared/database/entities/BaseEntity.ts", []byte(baseEntityContent), 0644)
}

// createGitignore cria o arquivo .gitignore
func createGitignore() {
	gitignoreContent := `node_modules/
.env
dist/
`
	os.WriteFile(".gitignore", []byte(gitignoreContent), 0644)
}

// createEnvFile cria o arquivo .env com conteúdo de exemplo
func createEnvFile() {
	envContent := `PORT=3000
DB_HOST=localhost
DB_PORT=5432
DB_USER=your_username
DB_PASSWORD=your_password
DB_NAME=your_database
JWT_SECRET=your_jwt_secret
`
	os.WriteFile(".env", []byte(envContent), 0644)
}

// createEnvExampleFile cria o arquivo .env.example com placeholders
func createEnvExampleFile() {
	envExampleContent := `PORT=3000
DB_HOST=localhost
DB_PORT=5432
DB_USER=your_username
DB_PASSWORD=your_password
DB_NAME=your_database
JWT_SECRET=your_jwt_secret
`
	os.WriteFile(".env.example", []byte(envExampleContent), 0644)
}

// createMainFile gera o arquivo principal do servidor com Express e configuração básica
func createMainFile(useGraphQL bool, useWebSocket bool) {
	mainFileContent := `import "reflect-metadata";
import "dotenv/config";
import express from "express";
import { AppRouter } from "@http/routes";
import { AppDataSource } from "@shared/database/dataSource";
import { Logger } from "@shared/logger";
import { authMiddleware } from "@shared/middleware/auth";
`

	if useGraphQL {
		mainFileContent += `import { graphqlHTTP } from "express-graphql";
import { buildSchema } from "graphql";
`
	}

	if useWebSocket {
		mainFileContent += `import { Server } from "socket.io";
import http from "http";
`
	}

	mainFileContent += `

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(authMiddleware);
app.use("/api", AppRouter);
`

	if useGraphQL {
		mainFileContent += `
const schema = buildSchema(
  type Query {
    hello: String
  }
);

const root = {
  hello: () => {
    return "Hello world!";
  },
};

app.use("/graphql", graphqlHTTP({
  schema: schema,
  rootValue: root,
  graphiql: true,
}));
`
	}

	if useWebSocket {
		mainFileContent += `
const server = http.createServer(app);
const io = new Server(server);

io.on("connection", (socket) => {
  Logger.info("Novo cliente conectado");
  socket.on("disconnect", () => {
    Logger.info("Cliente desconectado");
  });
});
`
	}

	mainFileContent += `
AppDataSource.initialize()
  .then(() => {`

	if useWebSocket {
		mainFileContent += `
    server.listen(PORT, () => {
      Logger.info("Servidor rodando na porta " + PORT);
    });`
	} else {
		mainFileContent += `
    app.listen(PORT, () => {
      Logger.info("Servidor rodando na porta " + PORT);
    });`
	}

	mainFileContent += `
  })
  .catch((error) => {
    Logger.error("Erro ao conectar ao banco de dados", error);
  });
`

	os.WriteFile("src/main/main.ts", []byte(mainFileContent), 0644)
}

// setupTsConfig cria o arquivo de configuração do TypeScript
func setupTsConfig() {
	tsconfig := `{
  "compilerOptions": {
    "target": "ES6",
    "module": "commonjs",
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true,
	"strictPropertyInitialization": false,
    "baseUrl": "./",
    "paths": {
      "@domain/*": ["src/domain/*"],
      "@modules/*": ["src/modules/*"],
      "@http/*": ["src/http/*"],
      "@config/*": ["src/config/*"],
      "@shared/*": ["src/shared/*"],
      "@utils/*": ["src/utils/*"]
    }
  },
  "include": ["src/**/*.ts"],
  "exclude": ["node_modules"]
}`
	os.WriteFile("tsconfig.json", []byte(tsconfig), 0644)
}

// setupGit inicializa o git e configura o husky para o projeto
func setupGit() {
	runCommand("git", "init")
	runCommand("npm", "install", "husky", "--save-dev")

	// Habilita o Husky
	runCommand("npx", "husky", "install")

	// Criar o arquivo de hook pre-commit
	os.MkdirAll(".husky", 0755)
	preCommitHook := `#!/bin/sh
. "$(dirname "$0")/_/husky.sh"

npm run lint
`
	os.WriteFile(".husky/pre-commit", []byte(preCommitHook), 0755)

	fmt.Println("Husky configurado com sucesso.")
}

// setupLintingAndFormattingConfig configura ESLint, Prettier e Husky
func setupLintingAndFormattingConfig() {
	eslintConfig := `{
  "env": {
    "node": true,
    "es2021": true
  },
  "extends": [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "prettier"
  ],
  "parser": "@typescript-eslint/parser",
  "parserOptions": {
    "ecmaVersion": 12,
    "sourceType": "module",
    "project": "./tsconfig.json"
  },
  "plugins": ["@typescript-eslint", "prettier"],
  "rules": {
    "prettier/prettier": "error"
  }
}`
	os.WriteFile(".eslintrc.json", []byte(eslintConfig), 0644)

	prettierConfig := `{
  "semi": true,
  "singleQuote": false,
  "trailingComma": "all",
  "endOfLine": "auto"
}`
	os.WriteFile(".prettierrc", []byte(prettierConfig), 0644)


	eslintConfigMjs := `import typescriptEslint from "@typescript-eslint/eslint-plugin";
import prettier from "eslint-plugin-prettier";
import globals from "globals";
import tsParser from "@typescript-eslint/parser";
import path from "node:path";
import { fileURLToPath } from "node:url";
import js from "@eslint/js";
import { FlatCompat } from "@eslint/eslintrc";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const compat = new FlatCompat({
    baseDirectory: __dirname,
    recommendedConfig: js.configs.recommended,
    allConfig: js.configs.all
});

export default [
    ...compat.extends("eslint:recommended", "plugin:@typescript-eslint/recommended", "prettier"),
    {
        plugins: {
            "@typescript-eslint": typescriptEslint,
            prettier,
        },

        languageOptions: {
            globals: {
                ...globals.node,
            },

            parser: tsParser,
            ecmaVersion: 12,
            sourceType: "module",

            parserOptions: {
                project: "./tsconfig.json",
            },
        },

        rules: {
            "prettier/prettier": "error",
        },
    },
];`

	os.WriteFile("eslint.config.mjs", []byte(eslintConfigMjs), 0644)
}

// setupPackageJSONScripts atualiza os scripts do package.json para desenvolvimento e produção
func setupPackageJSONScripts() {
	packageJSONFile, err := os.ReadFile("package.json")
	if err != nil {
		log.Fatalf("Erro ao ler package.json: %v", err)
	}

	packageJSONContent := string(packageJSONFile)
	packageJSONContent = strings.Replace(packageJSONContent, `"test": "echo \"Error: no test specified\" && exit 1"`, `"dev": "tsx watch src/main/main.ts",
    "build": "tsc",
    "start": "node dist/main/main.js",
    "lint": "eslint 'src/**/*.ts'"`, 1)

	os.WriteFile("package.json", []byte(packageJSONContent), 0644)
}

// setupTypeORMConfig cria o dataSource.ts para TypeORM usando a nova API DataSource
func setupTypeORMConfig() {
	typeORMConfig := `import "reflect-metadata";
import { DataSource } from "typeorm";
import { User } from "@modules/user/entities/User";

export const AppDataSource = new DataSource({
  type: "postgres",
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || "5432", 10),
  username: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  synchronize: true,
  logging: false,
  entities: [User],
});
`
	os.MkdirAll("src/shared/database", 0755)
	os.WriteFile("src/shared/database/dataSource.ts", []byte(typeORMConfig), 0644)
}

// setupDatabaseConfigs configura opções de bancos de dados opcionais (MongoDB, Redis)
func setupDatabaseConfigs(options map[string]bool) {
	// Para Redis
	if options["redis"] {
		redisConfig := `import { createClient } from "redis";

export const redisClient = createClient();

redisClient.on("error", (err) => {
  console.error("Erro no cliente Redis", err);
});

redisClient.connect();
`
		os.WriteFile("src/shared/database/redis.ts", []byte(redisConfig), 0644)
	}

	// Para MongoDB (se selecionado)
	if options["mongodb"] {
		mongoConfig := `import { MongoClient } from "mongodb";

const url = "mongodb://localhost:27017";
const client = new MongoClient(url);

export const mongoClient = client.db("mydb");
`
		os.WriteFile("src/shared/database/mongodb.ts", []byte(mongoConfig), 0644)
	}
}

// setupLogger configura um logger básico usando Winston
func setupLogger() {
	loggerContent := `import { createLogger, format, transports } from "winston";

export const Logger = createLogger({
  level: "info",
  format: format.combine(
    format.colorize(),
    format.timestamp({
      format: "YYYY-MM-DD HH:mm:ss ",
    }),
    format.printf((info) => info.timestamp + info.level + ": " + info.message),
  ),
  transports: [new transports.Console()],
});
`
	os.WriteFile("src/shared/logger/index.ts", []byte(loggerContent), 0644)
}

// setupJWT cria utilitários para JWT
func setupJWT() {
	jwtContent := `import jwt from "jsonwebtoken";

export function generateToken(payload: object): string {
  return jwt.sign(payload, process.env.JWT_SECRET as string, { 
	expiresIn: "1h" 
  });
}

export function verifyToken(token: string): jwt.JwtPayload | string {
  try {
    return jwt.verify(token, process.env.JWT_SECRET as string);
  } catch (error) {
    throw new Error("Invalid Token: " + error);
  }
}
`
	os.WriteFile("src/utils/jwt.ts", []byte(jwtContent), 0644)
}

// setupAuthMiddleware cria o middleware de autenticação
func setupAuthMiddleware() {
	authMiddlewareContent := `/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unused-vars */
import { Request, Response, NextFunction } from "express";
import { verifyToken } from "@utils/jwt";

export function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    res.status(401).json({ message: "Token não fornecido" });
	return;
  }

  try {
    const decoded = verifyToken(token);
    (req as any).user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ message: "Token inválido" });
	return;
  }
}
`
	os.WriteFile("src/shared/middleware/auth.ts", []byte(authMiddlewareContent), 0644)
}

// setupExampleModules cria exemplos de entidades, repositórios, serviços e rotas com autenticação
func setupExampleModules() {
	// Entidade
	entityContent := `import { Entity, Column, BeforeInsert } from "typeorm";
import bcrypt from "bcryptjs";
import { BaseSchema } from "@shared/database/entities/BaseEntity";

@Entity()
export class User extends BaseSchema {
  @Column({ type: "varchar", length: 255 })
  name: string;

  @Column({ type: "varchar", length: 255, unique: true })
  email: string;

  @Column({ type: "varchar", length: 255 })
  password: string;

  @BeforeInsert()
  async hashPassword() {
    this.password = await bcrypt.hash(this.password, 10);
  }
}
`
	os.MkdirAll("src/modules/user/entities", 0755)
	os.WriteFile("src/modules/user/entities/User.ts", []byte(entityContent), 0644)

	// Repositório
	repositoryContent := `import { Repository } from "typeorm";
import { User } from "../entities/User";
import { AppDataSource } from "@shared/database/dataSource";

export class UserRepository extends Repository<User> {
  constructor() {
    super(User, AppDataSource.manager);
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.findOne({ where: { email } });
  }
}
`
	os.MkdirAll("src/modules/user/repositories", 0755)
	os.WriteFile("src/modules/user/repositories/UserRepository.ts", []byte(repositoryContent), 0644)

	// Serviço
	serviceContent := `import { UserRepository } from "../repositories/UserRepository";
import { User } from "../entities/User";
import bcrypt from "bcryptjs";
import { generateToken } from "@utils/jwt";

export class UserService {
  constructor(private userRepository: UserRepository) {}

  async createUser(data: Partial<User>): Promise<User> {
    const existingUser = await this.userRepository.findByEmail(
	  data.email as string
	);

    if (existingUser) {
      throw new Error("Usuário já existe com este email");
    }

    const user = this.userRepository.create(data);
    return await this.userRepository.save(user);
  }

  async getAllUsers(): Promise<User[]> {
    return await this.userRepository.find();
  }

  async authenticateUser(data: { 
	email: string; 
	password: string 
  }): Promise<string> {
    const user = await this.userRepository.findByEmail(data.email);
    if (!user) {
      throw new Error("Usuário não encontrado");
    }

    const isPasswordValid = await bcrypt.compare(data.password, user.password);
    if (!isPasswordValid) {
      throw new Error("Senha inválida");
    }

    const token = generateToken({ id: user.id, email: user.email });
    return token;
  }
}
`
	os.MkdirAll("src/modules/user/services", 0755)
	os.WriteFile("src/modules/user/services/UserService.ts", []byte(serviceContent), 0644)

	// Rotas
	routesContent := `import { Router } from "express";
import { UserController } from "@http/controllers/UserController";

const userController = new UserController();
const router = Router();

router.post("/register", (req, res) => {
  userController.create(req, res);
});
router.post("/login", (req, res) => {
  userController.login(req, res);
});
router.get("/", (req, res) => {
  userController.getAll(req, res);
});

export default router;
`
	os.WriteFile("src/http/routes/userRoutes.ts", []byte(routesContent), 0644)

	// Rotas principais
	indexRoutesContent := `import { Router } from "express";
import userRoutes from "./userRoutes";

export const AppRouter = Router();

AppRouter.use("/users", userRoutes);
`
	os.WriteFile("src/http/routes/index.ts", []byte(indexRoutesContent), 0644)
}

// installDependencies instala todas as dependências necessárias
func installDependencies(options map[string]bool) {
	// Dependências base
	runCommand("npm", "install", "express", "reflect-metadata", "winston", "dotenv", "bcryptjs", "jsonwebtoken")
	runCommand("npm", "install", "-D", "typescript", "ts-node", "ts-node-dev", "tsx" ,"@types/node", "@types/express", "@types/bcryptjs", "@types/jsonwebtoken", "eslint", "prettier", "husky", "@typescript-eslint/parser", "@typescript-eslint/eslint-plugin", "eslint-config-prettier", "eslint-plugin-prettier")

	// Instala dependências opcionais com base nas escolhas do usuário
	if options["typeorm"] {
		runCommand("npm", "install", "typeorm", "pg")
		setupTypeORMConfig()
	}
	if options["mongodb"] {
		runCommand("npm", "install", "mongodb")
	}
	if options["redis"] {
		runCommand("npm", "install", "redis")
	}
	if options["graphql"] {
		runCommand("npm", "install", "express-graphql", "graphql")
	}
	if options["websocket"] {
		runCommand("npm", "install", "socket.io", "http")
	}
}

// setupExpressProject inicializa o projeto Express com as opções escolhidas
func setupExpressProject(projectName string) {
	fmt.Printf("Configurando um novo projeto Express + TypeScript com Clean Architecture para '%s'...\n", projectName)

	// Passo 1: Inicializar projeto npm e instalar dependências
	os.MkdirAll(projectName, 0755)
	os.Chdir(projectName)
	runCommand("npm", "init", "-y")

	options := askUserOptions()

	installDependencies(options)

	// Passo 2: Configurar TypeScript com paths
	setupTsConfig()

	// Passo 3: Criar estrutura do projeto e arquivos de exemplo
	setupProjectStructure()
	createMainFile(options["graphql"], options["websocket"])
	setupLogger()
	setupDatabaseConfigs(options)
	createExampleController()
	createFactories()

	setupBaseEntity()

	setupExampleModules()

	// Adicionar JWT e Middleware de Autenticação
	setupJWT()
	setupAuthMiddleware()

	// Passo 4: Inicializar git e configurar linting
	setupGit()
	setupLintingAndFormattingConfig()

	// Passo 5: Atualizar scripts do package.json
	setupPackageJSONScripts()

	// Passo 6: Criar .gitignore, .env e .env.example
	createGitignore()
	createEnvFile()
	createEnvExampleFile()

	fmt.Printf("Projeto Express + TypeScript '%s' configurado com sucesso!\n", projectName)
}

func main() {
	projectName := getProjectName()
	fmt.Println("Escolha o tipo de projeto para configurar:")
	fmt.Println("1. NestJS")
	fmt.Println("2. Express + TypeScript (Clean Architecture)")

	var choice string
	fmt.Scanln(&choice)

	if choice == "1" {
		fmt.Println("Configuração do NestJS ainda não implementada.")
	} else if choice == "2" {
		setupExpressProject(projectName)
	} else {
		fmt.Println("Escolha inválida. Por favor, digite 1 para NestJS ou 2 para Express + TypeScript.")
	}
}
