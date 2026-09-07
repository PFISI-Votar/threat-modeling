package report

type ChaptersToShowHide string

const (
	RiskRulesCheckedByThreagile ChaptersToShowHide = "RiskRulesCheckedByThreagile"
	AssetRegister               ChaptersToShowHide = "AssetRegister"
	TagListing                  ChaptersToShowHide = "TagListing"
	SharedRuntimes              ChaptersToShowHide = "SharedRuntimes"
	RisksByTechnicalAsset       ChaptersToShowHide = "RisksByTechnicalAsset"
	DataBreachProbabilities     ChaptersToShowHide = "DataBreachProbabilities"
	STRIDEClassification        ChaptersToShowHide = "STRIDEClassification"
	AssignmentByFunction        ChaptersToShowHide = "AssignmentByFunction"
	RAAAnalysis                 ChaptersToShowHide = "RAAAnalysis"
	DataMapping                 ChaptersToShowHide = "DataMapping"
	ImpactRemainingRisks        ChaptersToShowHide = "ImpactRemainingRisks"
)

type ReportConfiguation struct {
	HideChapter map[ChaptersToShowHide]bool `yaml:"HideChapter,omitempty" json:"HideChapter,omitempty"`
}
