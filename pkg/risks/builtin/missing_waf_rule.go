package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingWafRule struct{}

func NewMissingWafRule() *MissingWafRule {
	return &MissingWafRule{}
}

func (*MissingWafRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-waf",
		Title: "Falta de Web Application Firewall (WAF)",
		Description: "Para contar con una primera línea de defensa por filtrado, las arquitecturas de seguridad " +
			"con web-services o aplicaciones web deberían incluir un Web Application Firewall (WAF).",
		Impact:     "Si este riesgo no se mitiga, los atacantes podrían aplicar patrones de ataque estándar " +
			"contra las aplicaciones o servicios web.",
		ASVS:       "V1 - Architecture, Design and Threat Modeling Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Virtual_Patching_Cheat_Sheet.html",
		Action:     "Web Application Firewall (WAF)",
		Mitigation: "Considere colocar un Web Application Firewall (WAF) delante de los web-services y/o " +
			"aplicaciones web.",
		Check:          "¿Hay un WAF implementado?",
		Function:       types.Operations,
		STRIDE:         types.Tampering,
		DetectionLogic: "In-scope web-services and/or web-applications accessed across a network trust boundary not having a Web Application Firewall (WAF) in front of them.",
		RiskAssessment: "The risk rating depends on the sensitivity of the technical asset itself and of the data assets processed.",
		FalsePositives: "Targets only accessible via WAFs or reverse proxies containing a WAF component (like ModSecurity) can be considered " +
			"as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        1008,
	}
}

func (*MissingWafRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingWafRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, technicalAsset := range input.TechnicalAssets {
		if technicalAsset.OutOfScope {
			continue
		}
		if !technicalAsset.Technologies.GetAttribute(types.WebApplication) &&
			!technicalAsset.Technologies.GetAttribute(types.IsWebService) {
			continue
		}
		for _, incomingAccess := range input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id] {
			if isAcrossTrustBoundaryNetworkOnly(input, incomingAccess) &&
				incomingAccess.Protocol.IsPotentialWebAccessProtocol() &&
				!input.TechnicalAssets[incomingAccess.SourceId].Technologies.GetAttribute(types.WAF) {
				risks = append(risks, r.createRisk(input, technicalAsset))
				break
			}
		}
	}
	return risks, nil
}

func (r *MissingWafRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset) *types.Risk {
	title := "<b>Missing Web Application Firewall (WAF)</b> risk at <b>" + technicalAsset.Title + "</b>"
	likelihood := types.Unlikely
	impact := types.LowImpact
	if input.HighestProcessedConfidentiality(technicalAsset) == types.StrictlyConfidential ||
		input.HighestProcessedIntegrity(technicalAsset) == types.MissionCritical ||
		input.HighestProcessedAvailability(technicalAsset) == types.MissionCritical {
		impact = types.MediumImpact
	}
	risk := &types.Risk{
		CategoryId:                   r.Category().ID,
		Severity:                     types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:       likelihood,
		ExploitationImpact:           impact,
		Title:                        title,
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        types.Improbable,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id
	return risk
}
