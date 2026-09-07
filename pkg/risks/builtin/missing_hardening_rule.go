package builtin

import (
	"strconv"

	"github.com/threagile/threagile/pkg/types"
)

type MissingHardeningRule struct {
	raaLimit        int
	raaLimitReduced int
}

func NewMissingHardeningRule() *MissingHardeningRule {
	return &MissingHardeningRule{raaLimit: 55, raaLimitReduced: 40}
}

func (r *MissingHardeningRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-hardening",
		Title: "Falta de Hardening",
		Description: "Los activos técnicos con un valor de Atractivo Relativo para el Atacante (RAA) de " + strconv.Itoa(r.raaLimit) + " % o superior deberían endurecerse explícitamente según mejores prácticas y guías del proveedor.",
		Impact:     "Si este riesgo no se mitiga, los atacantes podrían atacar con mayor facilidad objetivos de " +
			"alto valor.",
		ASVS:       "V14 - Configuration Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
		Action:     "Hardening del Sistema",
		Mitigation: "Intente aplicar todas las mejores prácticas de hardening (benchmarks CIS, recomendaciones " +
			"OWASP, del proveedor, DevSec Hardening Framework, DBSAT para Oracle, y otras).",
		Check:    "¿Se aplican las recomendaciones de la hoja de referencia y del capítulo ASVS enlazado?",
		Function: types.Operations,
		STRIDE:   types.Tampering,
		DetectionLogic: "Activos técnicos in-scope con RAA de " + strconv.Itoa(r.raaLimit) + " % o superior. En general, para objetivos de alto valor como almacenes de datos, servidores de aplicación, proveedores de identidad y ERP este límite se reduce a " + strconv.Itoa(r.raaLimitReduced) + " %",
		RiskAssessment:             "La calificación del riesgo depende de la sensibilidad de los datos procesados en el activo técnico.",
		FalsePositives:             "Por lo general no hay falsos positivos.",
		ModelFailurePossibleReason: false,
		CWE:                        16,
	}
}

func (*MissingHardeningRule) SupportedTags() []string {
	return []string{"tomcat"}
}

func (r *MissingHardeningRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if r.skipAsset(technicalAsset) {
			continue
		}
		if technicalAsset.RAA >= float64(r.raaLimit) ||
			(technicalAsset.RAA >= float64(r.raaLimitReduced) &&
				(technicalAsset.Type == types.Datastore || technicalAsset.Technologies.GetAttribute(types.IsHighValueTarget))) {
			risks = append(risks, r.createRisk(input, technicalAsset))
		}
	}
	return risks, nil
}

func (r *MissingHardeningRule) skipAsset(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.OutOfScope
}

func (r *MissingHardeningRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Falta de Hardening</b> en el activo <b>" + technicalAsset.Title + "</b>"
	impact := types.LowImpact
	if input.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential || input.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical {
		impact = types.MediumImpact
	}
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Likely, impact),
		ExploitationLikelihood:       types.Likely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
