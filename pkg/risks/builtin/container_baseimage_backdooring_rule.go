package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type ContainerBaseImageBackdooringRule struct{}

func NewContainerBaseImageBackdooringRule() *ContainerBaseImageBackdooringRule {
	return &ContainerBaseImageBackdooringRule{}
}

func (*ContainerBaseImageBackdooringRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "container-baseimage-backdooring",
		Title: "Backdooring de Imagen Base de Contenedor",
		Description: "Cuando un activo técnico se construye con tecnologías de contenedores, pueden surgir " +
			"riesgos de backdooring de la imagen base donde imágenes maliciosas o comprometidas " +
			"introducen puertas traseras.",
		Impact:     "Si este riesgo no se mitiga, los atacantes podrían persistir profundamente en el entorno " +
			"objetivo mediante imágenes base comprometidas.",
		ASVS:       "V10 - Malicious Code Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
		Action:     "Hardening de Infraestructura de Contenedores",
		Mitigation: "Aplique hardening a todas las infraestructuras de contenedores (véase por ejemplo los " +
			"<i>CIS-Benchmarks para Docker y Kubernetes</i>).",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS/CSVS applied?",
		Function:       types.Operations,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope technical assets running as containers.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets.",
		FalsePositives: "Fully trusted (i.e. reviewed and cryptographically signed or similar) base images of containers can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        912,
	}
}

func (*ContainerBaseImageBackdooringRule) SupportedTags() []string {
	return []string{}
}

func (r *ContainerBaseImageBackdooringRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Machine == types.Container {
			risks = append(risks, r.createRisk(parsedModel, technicalAsset))
		}
	}
	return risks, nil
}

func (r *ContainerBaseImageBackdooringRule) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Container Base Image Backdooring</b> risk at <b>" + technicalAsset.Title + "</b>"
	impact := types.MediumImpact
	if parsedModel.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential ||
		parsedModel.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical ||
		parsedModel.HighestProcessedAvailability(technicalAsset) == types.MissionCritical {
		impact = types.HighImpact
	}
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Probable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
