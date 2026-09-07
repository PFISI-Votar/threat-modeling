package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type CrossSiteScriptingRule struct{}

func NewCrossSiteScriptingRule() *CrossSiteScriptingRule {
	return &CrossSiteScriptingRule{}
}

func (*CrossSiteScriptingRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "cross-site-scripting",
		Title: "Cross-Site Scripting (XSS)",
		Description: "En cada aplicación web pueden surgir riesgos de Cross-Site Scripting (XSS). En el nivel de " +
			"riesgo general, tenga en cuenta otras aplicaciones web del alcance.",
		Impact:     "Si este riesgo no se mitiga, los atacantes podrían acceder a sesiones individuales de " +
			"víctimas o ejecutar acciones en su nombre.",
		ASVS:       "V5 - Validation, Sanitization and Encoding Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
		Action:     "Prevención de XSS",
		Mitigation: "Intente codificar todos los valores enviados al navegador y manejar las manipulaciones del " +
			"DOM de forma segura para evitar XSS.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope web applications.",
		RiskAssessment: "The risk rating depends on the sensitivity of the data processed in the web application.",
		FalsePositives: "When the technical asset " +
			"is not accessed via a browser-like component (i.e not by a human user initiating the request that " +
			"gets passed through all components until it reaches the web application) this can be considered a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        79,
	}
}

func (*CrossSiteScriptingRule) SupportedTags() []string {
	return []string{}
}

func (r *CrossSiteScriptingRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if r.skipAsset(technicalAsset) {
			continue
		}
		risks = append(risks, r.createRisk(input, technicalAsset))
	}
	return risks, nil
}


func (asl CrossSiteScriptingRule) skipAsset(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.OutOfScope || !technicalAsset.Technologies.GetAttribute(types.WebApplication) // TODO: also mobile clients or rich-clients as long as they use web-view...
}

func (r *CrossSiteScriptingRule) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Cross-Site Scripting (XSS)</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := types.MediumImpact
	if parsedModel.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential || parsedModel.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical {
		impact = types.HighImpact
	}
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, impact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
