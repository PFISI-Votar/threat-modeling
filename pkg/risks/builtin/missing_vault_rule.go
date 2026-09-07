package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingVaultRule struct{}

func NewMissingVaultRule() *MissingVaultRule {
	return &MissingVaultRule{}
}

func (*MissingVaultRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-vault",
		Title: "Falta de Vault (Almacenamiento de Secretos)",
		Description: "Para evitar la fuga de secretos vía archivos de configuración (cuando se explotan " +
			"vulnerabilidades que permiten leer archivos, como Path-Traversal u otras), es buena " +
			"práctica usar un proceso separado y endurecido, con autenticación, autorización y registro " +
			"de auditoría adecuados, para acceder a secretos de configuración (credenciales, claves " +
			"privadas, certificados de cliente, etc.). Este componente suele ser algún tipo de Vault.",
		Impact: "Si este riesgo no se mitiga, los atacantes podrían robar con mayor facilidad secretos de " +
			"configuración (credenciales, claves privadas, certificados de cliente, etc.) una vez que " +
			"exista y se explote una vulnerabilidad de acceso a archivos.",
		ASVS:           "V6 - Stored Cryptography Verification Requirements",
		CheatSheet:     "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
		Action:         "Vault (Almacenamiento de Secretos)",
		Mitigation:     "Considere usar un Vault (Almacenamiento de Secretos) para guardar y acceder de forma " +
			"segura a secretos de configuración (credenciales, claves privadas, certificados de " +
			"cliente, etc.).",
		Check:          "¿Hay un Vault (Almacenamiento de Secretos) implementado?",
		Function:       types.Architecture,
		STRIDE:         types.InformationDisclosure,
		DetectionLogic: "Modelos sin un Vault (Almacenamiento de Secretos).",
		RiskAssessment: "La calificación del riesgo depende de la sensibilidad del activo técnico y de los activos " +
			"de datos procesados.",
		FalsePositives: "Modelos donde ningún activo técnico tiene datos de configuración sensibles que proteger " +
			"pueden considerarse falsos positivos tras una revisión individual.",
		ModelFailurePossibleReason: true,
		CWE:                        522,
	}
}

func (*MissingVaultRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingVaultRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	hasVault := false
	var mostRelevantAsset *types.TechnicalAsset
	impact := types.LowImpact
	for _, id := range input.SortedTechnicalAssetIDs() { // use the sorted one to always get the same tech asset with the highest sensitivity as example asset
		techAsset := input.TechnicalAssets[id]
		if techAsset.Technologies.GetAttribute(types.Vault) {
			hasVault = true
			break
		}
		if input.HighestProcessedConfidentiality(techAsset) >= types.Confidential ||
			input.HighestProcessedIntegrity(techAsset) >= types.Critical ||
			input.HighestProcessedAvailability(techAsset) >= types.Critical {
			impact = types.MediumImpact
		}
		if techAsset.Confidentiality >= types.Confidential ||
			techAsset.Integrity >= types.Critical ||
			techAsset.Availability >= types.Critical {
			impact = types.MediumImpact
		}
		// just for referencing the most interesting asset
		if mostRelevantAsset == nil || techAsset.HighestSensitivityScore() > mostRelevantAsset.HighestSensitivityScore() {
			mostRelevantAsset = techAsset
		}
	}
	if !hasVault {
		risks = append(risks, r.createRisk(mostRelevantAsset, impact))
	}
	return risks, nil
}

func (r *MissingVaultRule) createRisk(technicalAsset *types.TechnicalAsset, impact types.RiskExploitationImpact) *types.Risk {
	title := "<b>Falta de Vault (Almacenamiento de Secretos)</b> en el modelo de amenazas"
	id := "no-components"
	if technicalAsset != nil {
		title += " (referenciando el activo <b>" + technicalAsset.Title + "</b> como ejemplo)"
		id = technicalAsset.Id
	}
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood:       types.Unlikely,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{},
	}
	risk.SyntheticId = risk.CategoryId + "@" + id
	return risk
}
