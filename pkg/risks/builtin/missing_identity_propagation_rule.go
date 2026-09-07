package builtin

import (
	"github.com/threagile/threagile/pkg/types"
)

type MissingIdentityPropagationRule struct{}

func NewMissingIdentityPropagationRule() *MissingIdentityPropagationRule {
	return &MissingIdentityPropagationRule{}
}

func (*MissingIdentityPropagationRule) Category() *types.RiskCategory {
	return &types.RiskCategory{
		ID:    "missing-identity-propagation",
		Title: "Falta de Propagación de Identidad",
		Description: "Los activos técnicos (especialmente sistemas multi-tenant) que suelen procesar datos de " +
			"usuarios finales deberían autorizar cada solicitud contra la identidad propagada del " +
			"usuario final.",
		Impact: "Si este riesgo no se mitiga, los atacantes podrían acceder o modificar datos ajenos por " +
			"una autorización insuficiente en el backend.",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
		Action:     "Propagación de Identidad y Autorización Basada en Recursos",
		Mitigation: "Al procesar solicitudes de usuarios finales, si es posible autorice en el backend contra " +
			"la identidad de usuario final propagada (y no solo contra una identidad técnica del " +
			"llamador).",
		Check:    "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function: types.Architecture,
		STRIDE:   types.ElevationOfPrivilege,
		DetectionLogic: "In-scope service-like technical assets which usually process data based on end user requests, if authenticated " +
			"(i.e. non-public), should authorize incoming requests based on the propagated end user identity when their rating is sensitive. " +
			"This is especially the case for all multi-tenant assets (there even less-sensitive rated ones). " +
			"DevOps usages are exempted from this risk.",
		RiskAssessment: "The risk rating (medium or high) " +
			"depends on the confidentiality, integrity, and availability rating of the technical asset.",
		FalsePositives: "Technical assets which do not process requests regarding functionality or data linked to end-users (customers) " +
			"can be considered as false positives after individual review.",
		ModelFailurePossibleReason: false,
		CWE:                        284,
	}
}

func (*MissingIdentityPropagationRule) SupportedTags() []string {
	return []string{}
}

func (r *MissingIdentityPropagationRule) GenerateRisks(input *types.Model) ([]*types.Risk, error) {
	risks := make([]*types.Risk, 0)
	for _, id := range input.SortedTechnicalAssetIDs() {
		technicalAsset := input.TechnicalAssets[id]
		if r.skipAsset(technicalAsset) {
			continue
		}

		// check each incoming authenticated data flow
		commLinks := input.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
		for _, commLink := range commLinks {
			caller := input.TechnicalAssets[commLink.SourceId]
			if r.skipCommunicationLinkAsset(caller, commLink) {
				continue
			}

			highRisk := technicalAsset.Confidentiality == types.StrictlyConfidential ||
				technicalAsset.Integrity == types.MissionCritical ||
				technicalAsset.Availability == types.MissionCritical
			risks = append(risks, r.createRisk(input, technicalAsset, commLink, highRisk))
		}
	}
	return risks, nil
}

func (r *MissingIdentityPropagationRule) skipCommunicationLinkAsset(caller *types.TechnicalAsset, commLink *types.CommunicationLink) bool {
	if !caller.Technologies.GetAttribute(types.IsUsuallyAbleToPropagateIdentityToOutgoingTargets) || caller.Type == types.Datastore {
		return true
	}
	if commLink.Authentication == types.NoneAuthentication || commLink.Authorization == types.EndUserIdentityPropagation {
		return true
	}
	if commLink.Usage == types.DevOps && commLink.Authorization != types.NoneAuthorization {
		return true
	}
	return false
}

func (r *MissingIdentityPropagationRule) skipAsset(technicalAsset *types.TechnicalAsset) bool {
	if technicalAsset.OutOfScope {
		return true
	}
	if !technicalAsset.Technologies.GetAttribute(types.IsUsuallyProcessingEndUserRequests) {
		return true
	}
	if technicalAsset.MultiTenant && technicalAsset.Confidentiality < types.Restricted && technicalAsset.Integrity < types.Important && technicalAsset.Availability < types.Important {
		return true
	}
	if !technicalAsset.MultiTenant && technicalAsset.Confidentiality < types.Confidential && technicalAsset.Integrity < types.Critical && technicalAsset.Availability < types.Critical {
		return true
	}
	return false
}

func (r *MissingIdentityPropagationRule) createRisk(input *types.Model, technicalAsset *types.TechnicalAsset, incomingAccess *types.CommunicationLink, moreRisky bool) *types.Risk {
	impact := types.LowImpact
	if moreRisky {
		impact = types.MediumImpact
	}
	risk := &types.Risk{
		CategoryId:             r.Category().ID,
		Severity:               types.CalculateSeverity(types.Unlikely, impact),
		ExploitationLikelihood: types.Unlikely,
		ExploitationImpact:     impact,
		Title: "<b>Missing End User Identity Propagation</b> over communication link <b>" + incomingAccess.Title + "</b> " +
			"from <b>" + input.TechnicalAssets[incomingAccess.SourceId].Title + "</b> " +
			"to <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingAccess.Id,
		DataBreachProbability:           types.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.CategoryId + "@" + incomingAccess.Id + "@" + input.TechnicalAssets[incomingAccess.SourceId].Id + "@" + technicalAsset.Id
	return risk
}
