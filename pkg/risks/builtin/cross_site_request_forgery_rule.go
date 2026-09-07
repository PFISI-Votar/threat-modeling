package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type CrossSiteRequestForgeryRule struct{}

func NewCrossSiteRequestForgeryRule() *CrossSiteRequestForgeryRule {
	return &CrossSiteRequestForgeryRule{}
}

func (*CrossSiteRequestForgeryRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:          "cross-site-request-forgery",
		Title:       "Cross-Site Request Forgery (CSRF)",
		Description: "Cuando una aplicación web se accede vía protocolos web pueden surgir riesgos de Cross-Site " +
			"Request Forgery (CSRF).",
		Impact: "Si este riesgo no se mitiga, los atacantes podrían engañar a víctimas autenticadas para " +
			"ejecutar acciones no deseadas.",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
		Action:     "Prevención de CSRF",
		Mitigation: "Intente usar tokens anti-CSRF o el patrón double-submit (al menos para solicitudes autenticadas).",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       types.Development,
		STRIDE:         types.Spoofing,
		DetectionLogic: "In-scope web applications accessed via typical web access protocols.",
		RiskAssessment: "The risk rating depends on the integrity rating of the data sent across the communication link.",
		FalsePositives: "Web applications passing the authentication state via custom headers instead of cookies can " +
			"eventually be false positives. Also when the web application " +
			"is not accessed via a browser-like component (i.e not by a human user initiating the request that " +
			"gets passed through all components until it reaches the web application) this can be considered a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        352,
	}
}

func (*CrossSiteRequestForgeryRule) SupportedTags() []string {
	return []string{}
}

func (r *CrossSiteRequestForgeryRule) GenerateRisks(parsedModel *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range parsedModel.SortedTechnicalAssetIDs() {
		technicalAsset := parsedModel.TechnicalAssets[id]
		if r.skipAsset(technicalAsset) {
			continue
		}
		incomingFlows := parsedModel.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, incomingFlow := range incomingFlows {
			if !incomingFlow.Protocol.IsPotentialWebAccessProtocol() {
				continue
			}
			risks = append(risks, r.createRisk(parsedModel, technicalAsset, incomingFlow))
		}
	}
	return risks, nil
}

func (csrf CrossSiteRequestForgeryRule) skipAsset(technicalAsset *types.TechnicalAsset) bool {
	return technicalAsset.OutOfScope || !technicalAsset.Technologies.GetAttribute(types.WebApplication)
}

func (r *CrossSiteRequestForgeryRule) createRisk(parsedModel *types.Model, technicalAsset *types.TechnicalAsset, incomingFlow *types.CommunicationLink) *types.Risk {
	sourceAsset := parsedModel.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Cross-Site Request Forgery (CSRF)</b> risk at <b>" + technicalAsset.Title + "</b> via <b>" + incomingFlow.Title + "</b> from <b>" + sourceAsset.Title + "</b>"
	impact := types.LowImpact
	if parsedModel.HighestCommunicationLinkIntegrity(incomingFlow) == types.MissionCritical {
		impact = types.MediumImpact
	}
	likelihood := r.likelihoodFromUsage(incomingFlow)
	risk := &types.Risk{
		CategoryId:                      r.Category().ID,
		Severity:                        types.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + technicalAsset.Id + "@" + incomingFlow.Id
	return risk
}

func (*CrossSiteRequestForgeryRule) likelihoodFromUsage(cl *types.CommunicationLink) types.RiskExploitationLikelihood {
	if cl.Usage == types.DevOps {
		return types.Likely
	}
	return types.VeryLikely
}
