package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type SqlNoSqlInjectionRule struct{}

func NewSqlNoSqlInjectionRule() *SqlNoSqlInjectionRule {
	return &SqlNoSqlInjectionRule{}
}

func (*SqlNoSqlInjectionRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "sql-nosql-injection",
		Title: "Inyección SQL/NoSQL",
		Description: "Cuando se accede a una base de datos mediante protocolos de acceso a base de datos pueden " +
			"surgir riesgos de inyección SQL/NoSQL. La calificación depende de la sensibilidad de los " +
			"datos en el almacén.",
		Impact:     "Si este riesgo no se mitiga, los atacantes podrían modificar consultas SQL/NoSQL y acceder " +
			"o alterar datos.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
		Action:     "Prevención de Inyección SQL/NoSQL",
		Mitigation: "Intente usar parameter binding para evitar vulnerabilidades de inyección. Cuando se usa un " +
			"producto de terceros, verifique que no sea vulnerable a inyección.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
		DetectionLogic: "Database accessed via typical database access protocols by in-scope clients.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data stored inside the database.",
		FalsePositives: "Database accesses by queries not consisting of parts controllable by the caller can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        89,
	}
}

func (*SqlNoSqlInjectionRule) SupportedTags() []string {
	return []string{}
}

func (r *SqlNoSqlInjectionRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if technicalAsset.OutOfScope || technicalAsset.Type != types.Datastore {
			continue
		}

		incomingFlows := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			potentialDatabaseAccessProtocol := incomingFlow.Protocol.IsPotentialDatabaseAccessProtocol()
			isVulnerableToQueryInjection := technicalAsset.Technologies.GetAttribute(types.IsVulnerableToQueryInjection)
			potentialLaxDatabaseAccessProtocol := incomingFlow.Protocol.IsPotentialLaxDatabaseAccessProtocol()
			if potentialDatabaseAccessProtocol && isVulnerableToQueryInjection ||
				potentialLaxDatabaseAccessProtocol {
				risks = append(risks, r.createRisk(input, technicalAsset, incomingFlow))
			}
		}
	}
	return risks, nil
}

func (r *SqlNoSqlInjectionRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset, incomingFlow *types.CommunicationLink) *types.Risk {
	caller := input.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>SQL/NoSQL-Injection</b> risk at <b>" + caller.Title + "</b> against database <b>" + technicalAsset.Title + "</b>" +
		" via <b>" + incomingFlow.Title + "</b>"
	impact := types.MediumImpact
	if input.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential || input.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical {
		impact = types.HighImpact
	}
	likelihood := types.VeryLikely
	if incomingFlow.Usage == types.DevOps {
		likelihood = types.Likely
	}
	risk := &types.Risk{
		CategoryId:                      r.Category().ID,
		Severity:                        types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    caller.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           types.Probable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + caller.Id + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}
