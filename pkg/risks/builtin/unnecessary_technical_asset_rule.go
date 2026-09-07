package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type UnnecessaryTechnicalAssetRule struct{}

func NewUnnecessaryTechnicalAssetRule() *UnnecessaryTechnicalAssetRule {
	return &UnnecessaryTechnicalAssetRule{}
}

func (*UnnecessaryTechnicalAssetRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "unnecessary-technical-asset",
		Title: "Activo Técnico Innecesario",
		Description: "Cuando un activo técnico no procesa ningún activo de datos, es un indicador de un activo " +
			"técnico innecesario (o de un modelo incompleto).",
		Impact:                     "Si este riesgo no se mitiga, los atacantes podrían apuntar a activos técnicos innecesarios " +
			"aumentando la superficie de ataque.",
		ASVS:                       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet:                 "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:                     "Reducción de Superficie de Ataque",
		Mitigation:                 "Intente evitar usar activos técnicos que no procesen ni almacenen nada.",
		Check:                      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:                   types.Architecture,
		STRIDE:                     types.ElevationOfPrivilege,
		DetectionLogic:             "Technical assets not processing or storing any data assets.",
		RiskAssessment:             types.LowSeverity.String(),
		FalsePositives:             "Usually no false positives as this looks like an incomplete model.",
		ModelFailurePossibleReason: true,
		CWE:                        1008,
	}
}

func (*UnnecessaryTechnicalAssetRule) SupportedTags() []string {
	return []string{}
}

func (r *UnnecessaryTechnicalAssetRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if len(technicalAsset.DataAssetsProcessed) == 0 && len(technicalAsset.DataAssetsStored) == 0 ||
			(len(technicalAsset.CommunicationLinks) == 0 && len(input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]) == 0) {
			risks = append(risks, r.createRisk(technicalAsset))
		}
	}
	return risks, nil
}

func (r *UnnecessaryTechnicalAssetRule) createRisk(technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Unnecessary Technical Asset</b> named <b>" + technicalAsset.Title + "</b>"
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Unlikely, types.LowImpact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           types.LowImpact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
