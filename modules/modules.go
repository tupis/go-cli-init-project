package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

// getModuleName solicita ao usuário o nome da pasta/módulo a ser criado
func getModuleName() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Digite o nome do módulo: ")
	moduleName, _ := reader.ReadString('\n')
	return strings.TrimSpace(moduleName)
}

// createModuleStructure cria a estrutura básica de um módulo com base no nome da pasta
func createModuleStructure(moduleName string) {
	basePath := fmt.Sprintf("src/modules/%s", moduleName)
	os.MkdirAll(fmt.Sprintf("%s/entities", basePath), 0755)
	os.MkdirAll(fmt.Sprintf("%s/repositories", basePath), 0755)
	os.MkdirAll(fmt.Sprintf("%s/services", basePath), 0755)
	os.MkdirAll(fmt.Sprintf("%s/dto", basePath), 0755)

	// Criar pastas para HTTP
	os.MkdirAll(fmt.Sprintf("src/http/controllers"), 0755)
	os.MkdirAll(fmt.Sprintf("src/http/routes"), 0755)

	fmt.Printf("Estrutura do módulo '%s' criada com sucesso!\n", moduleName)
}

// createExampleFiles cria arquivos de exemplo para o módulo
func createExampleFiles(moduleName string) {
	basePath := fmt.Sprintf("src/modules/%s", moduleName)

	// Entidade
	entityContent := fmt.Sprintf(`import { Entity, Column } from "typeorm";
import { BaseSchema } from "@shared/database/entities/BaseEntity";

@Entity()
export class %s extends BaseSchema {
  @Column({ type: "varchar", length: 255 })
  exampleField: string;
}
`, strings.Title(moduleName))
	os.WriteFile(fmt.Sprintf("%s/entities/%s.ts", basePath, strings.Title(moduleName)), []byte(entityContent), 0644)

	// Repositório
	repositoryContent := fmt.Sprintf(`import { Repository } from "typeorm";
import { %s } from "../entities/%s";
import { AppDataSource } from "@shared/database/dataSource";

export class %sRepository extends Repository<%s> {
  constructor() {
    super(%s, AppDataSource.manager);
  }
}
`, strings.Title(moduleName), strings.Title(moduleName), strings.Title(moduleName), strings.Title(moduleName), strings.Title(moduleName))
	os.WriteFile(fmt.Sprintf("%s/repositories/%sRepository.ts", basePath, strings.Title(moduleName)), []byte(repositoryContent), 0644)

	// Serviço
	serviceContent := fmt.Sprintf(`import { %sRepository } from "../repositories/%sRepository";

export class %sService {
  constructor(private %sRepository: %sRepository) {}

  async exampleMethod() {
    return await this.%sRepository.find();
  }
}
`, strings.Title(moduleName), strings.Title(moduleName), strings.Title(moduleName), strings.ToLower(moduleName), strings.Title(moduleName), strings.ToLower(moduleName))
	os.WriteFile(fmt.Sprintf("%s/services/%sService.ts", basePath, strings.Title(moduleName)), []byte(serviceContent), 0644)

	// DTO
	dtoContent := fmt.Sprintf(`export class %sDto {
  exampleField: string;
}
`, strings.Title(moduleName))
	os.WriteFile(fmt.Sprintf("%s/dto/ExampleDto.ts", basePath), []byte(dtoContent), 0644)

	// Factory
	factoryContent := fmt.Sprintf(`import { %sRepository } from "./repositories/%sRepository";
import { %sService } from "./services/%sService";

export function get%sService(): %sService {
  const %sRepository = new %sRepository();
  return new %sService(%sRepository);
}
`, strings.Title(moduleName), strings.Title(moduleName), strings.Title(moduleName), strings.Title(moduleName), strings.Title(moduleName), strings.Title(moduleName), strings.ToLower(moduleName), strings.Title(moduleName), strings.Title(moduleName), strings.ToLower(moduleName))
	os.WriteFile(fmt.Sprintf("%s/%sFactory.ts", basePath, strings.Title(moduleName)), []byte(factoryContent), 0644)

	fmt.Printf("Arquivos de exemplo para o módulo '%s' criados com sucesso!\n", moduleName)
}

// createHTTPFiles cria arquivos HTTP (controller e rotas)
func createHTTPFiles(moduleName string) {
	// Controller
	controllerContent := fmt.Sprintf(`import { Request, Response } from "express";
import { get%sService } from "@modules/%s/%sFactory";
import { %sService } from "@modules/%s/services/%sService";

export class %sController {
  constructor(private readonly %sService: %sService = get%sService()) {}

  async exampleMethod(req: Request, res: Response): Promise<Response> {
    const result = await this.%sService.exampleMethod();
    return res.status(200).json(result);
  }
}
`, strings.Title(moduleName), moduleName, strings.Title(moduleName), strings.Title(moduleName), moduleName, strings.Title(moduleName), strings.Title(moduleName), strings.ToLower(moduleName), strings.Title(moduleName), strings.Title(moduleName), strings.ToLower(moduleName))
	os.WriteFile(fmt.Sprintf("src/http/controllers/%sController.ts", strings.Title(moduleName)), []byte(controllerContent), 0644)

	// Rotas
	routesContent := fmt.Sprintf(`import { Router } from "express";
import { %sController } from "@http/controllers/%sController";

const %sController = new %sController();
const router = Router();

router.get("/", (req, res) => {
	%sController.exampleMethod(req, res)
});

export default router;
`, strings.Title(moduleName), strings.Title(moduleName), strings.ToLower(moduleName), strings.Title(moduleName), strings.ToLower(moduleName))
	os.WriteFile(fmt.Sprintf("src/http/routes/%sRoutes.ts", moduleName), []byte(routesContent), 0644)

	// Atualizar rotas principais
	mainRoutesContent := fmt.Sprintf(`
import %sRoutes from "./%sRoutes";

router.use("/%s", %sRoutes);

`, moduleName, moduleName, moduleName, moduleName)

	file, err := os.OpenFile("src/http/routes/index.ts", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Erro ao atualizar rotas principais: %v", err)
	}
	defer file.Close()
	file.WriteString(mainRoutesContent)

	fmt.Printf("Arquivos HTTP para o módulo '%s' criados com sucesso!\n", moduleName)
}

func main() {
	moduleName := getModuleName()
	createModuleStructure(moduleName)
	createExampleFiles(moduleName)
	createHTTPFiles(moduleName)
}
