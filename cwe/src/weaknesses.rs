use serde::{Deserialize, Serialize};
use crate::content_history::ContentHistory;
use crate::notes::Notes;
use crate::structured_text::{StructuredCode, StructuredText};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Weaknesses {
    #[serde(rename = "Weakness")]
    pub weaknesses: Vec<Weakness>,
}
#[derive(Debug, Deserialize)]
#[serde(rename = "Weakness")]
#[serde(deny_unknown_fields)]
pub struct Weakness {
    #[serde(rename = "@ID")]
    pub id: i64,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Abstraction")]
    pub abstraction: String,
    #[serde(rename = "@Structure")]
    pub structure: String,
    #[serde(rename = "@Status")]
    pub status: String,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "Extended_Description")]
    pub extended_description: Option<StructuredText>,
    #[serde(rename = "Related_Weaknesses")]
    pub related_weaknesses: Option<RelatedWeaknesses>,
    #[serde(rename = "Demonstrative_Examples")]
    pub demonstrative_examples: Option<DemonstrativeExamples>,
    #[serde(rename = "Weakness_Ordinalities")]
    pub weakness_ordinalities: Option<WeaknessOrdinalities>,
    #[serde(rename = "Applicable_Platforms")]
    pub applicable_platforms: Option<ApplicablePlatforms>,
    #[serde(rename = "Background_Details")]
    pub background_details: Option<BackgroundDetails>,
    #[serde(rename = "Modes_Of_Introduction")]
    pub modes_of_introduction: Option<ModesOfIntroduction>,
    #[serde(rename = "Likelihood_Of_Exploit")]
    pub likelihood_of_exploit: Option<String>,
    #[serde(rename = "Alternate_Terms")]
    pub alternate_terms: Option<AlternateTerms>,
    #[serde(rename = "Common_Consequences")]
    pub common_consequences: Option<CommonConsequences>,
    #[serde(rename = "Detection_Methods")]
    pub detection_methods: Option<DetectionMethods>,
    #[serde(rename = "Potential_Mitigations")]
    pub potential_mitigations: Option<PotentialMitigations>,
    #[serde(rename = "Observed_Examples")]
    pub observed_examples: Option<ObservedExamples>,
    #[serde(rename = "Related_Attack_Patterns")]
    pub related_attack_patterns: Option<RelatedAttackPatterns>,
    #[serde(rename = "References")]
    pub references: Option<References>,
    #[serde(rename = "Content_History")]
    pub content_history: ContentHistory,
    #[serde(rename = "Exploitation_Factors")]
    pub exploitation_factors: Option<ExploitationFactors>,
    #[serde(rename = "Functional_Areas")]
    pub functional_areas: Option<FunctionalAreas>,
    #[serde(rename = "Affected_Resources")]
    pub affected_resources: Option<AffectedResources>,
    #[serde(rename = "Taxonomy_Mappings")]
    pub taxonomy_mappings: Option<TaxonomyMappings>,
    #[serde(rename = "Notes")]
    pub notes: Option<Notes>,
}
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum RelatedNature {
    ChildOf,
    ParentOf,
    StartsWith,
    CanFollow,
    CanPrecede,
    RequiredBy,
    Requires,
    CanAlsoBe,
    PeerOf,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeaknessOrdinalities {
    #[serde(rename = "$value")]
    pub weakness_ordinalities: Vec<WeaknessOrdinality>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeaknessOrdinality {
    #[serde(rename = "Ordinality")]
    pub ordinality: Option<String>,
    #[serde(rename = "Description")]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "Related_Weaknesses")]
#[serde(deny_unknown_fields)]
pub struct RelatedWeaknesses {
    #[serde(rename = "Related_Weakness", default)]
    pub related_weaknesses: Vec<RelatedWeakness>,
}
#[derive(Debug, Deserialize)]
#[serde(rename = "Related_Weakness")]
#[serde(deny_unknown_fields)]
pub struct RelatedWeakness {
    #[serde(rename = "@Nature")]
    pub nature: RelatedNature,
    #[serde(rename = "@CWE_ID")]
    pub cwe_id: i64,
    #[serde(rename = "@View_ID")]
    pub view_id: i64,
    #[serde(rename = "@Chain_ID")]
    pub chain_id: Option<i64>,
    #[serde(rename = "@Ordinal")]
    pub ordinal: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyMappings {
    #[serde(rename = "$value")]
    pub taxonomy_mappings: Vec<TaxonomyMapping>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyMapping {
    #[serde(rename = "@Taxonomy_Name")]
    pub taxonomy_name: String,
    #[serde(rename = "Entry_ID")]
    pub entry_id: Option<String>,
    #[serde(rename = "Entry_Name")]
    pub entry_name: Option<String>,
    #[serde(rename = "Mapping_Fit")]
    pub mapping_fit: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionalAreas {
    #[serde(rename = "$value")]
    pub functional_areas: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffectedResources {
    #[serde(rename = "$value")]
    pub affected_resources: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct References {
    #[serde(rename = "$value")]
    pub references: Vec<Reference>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    #[serde(rename = "@External_Reference_ID")]
    pub external_reference_id: String,
    #[serde(rename = "@Section")]
    pub section: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedAttackPatterns {
    #[serde(rename = "$value")]
    pub related_attack_patterns: Vec<RelatedAttackPattern>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedAttackPattern {
    #[serde(rename = "@CAPEC_ID")]
    pub caped_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedExamples {
    #[serde(rename = "$value")]
    pub observed_examples: Vec<ObservedExample>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedExample {
    #[serde(rename = "Reference")]
    pub reference: String,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "Link")]
    pub link: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemonstrativeExamples {
    #[serde(rename = "Demonstrative_Example")]
    pub examples: Vec<DemonstrativeExample>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemonstrativeExample {
    #[serde(rename = "@Demonstrative_Example_ID")]
    pub demonstrative_example_id: Option<String>,
    #[serde(rename = "$value")]
    pub children: Vec<DemonstrativeExampleChild>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DemonstrativeExampleChild {
    #[serde(rename = "Title_Text")]
    TitleText(String),
    #[serde(rename = "Intro_Text")]
    IntroText(StructuredText),
    #[serde(rename = "Body_Text")]
    BodyText(StructuredText),
    #[serde(rename = "Example_Code")]
    ExampleCode(StructuredCode),
    #[serde(rename = "References")]
    References {
        #[serde(rename = "$value")]
        children: Vec<Reference>,
    },
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PotentialMitigations {
    #[serde(rename = "$value")]
    pub potential_mitigations: Vec<PotentialMitigation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PotentialMitigation {
    #[serde(rename = "@Mitigation_ID")]
    pub mitigation_id: Option<String>,
    #[serde(rename = "$value")]
    pub children: Vec<PotentialMitigationChild>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PotentialMitigationChild {
    #[serde(rename = "Phase")]
    Phase(String),
    #[serde(rename = "Strategy")]
    Strategy(String),
    #[serde(rename = "Description")]
    Description(StructuredText),
    #[serde(rename = "Effectiveness")]
    Effectiveness(String),
    #[serde(rename = "Effectiveness_Notes")]
    EffectivenessNotes(StructuredText),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionMethods {
    #[serde(rename = "$value")]
    pub detection_methods: Vec<DetectionMethod>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionMethod {
    #[serde(rename = "@Detection_Method_ID")]
    pub detection_method_id: Option<String>,
    #[serde(rename = "$value")]
    pub children: Vec<DetectionMethodChild>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DetectionMethodChild {
    #[serde(rename = "Method")]
    Method(String),
    #[serde(rename = "Description")]
    Description(StructuredText),
    #[serde(rename = "Effectiveness")]
    Effectiveness(String),
    #[serde(rename = "Effectiveness_Notes")]
    EffectivenessNotes(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonConsequences {
    #[serde(rename = "$value")]
    pub common_consequences: Vec<Consequence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consequence {
    #[serde(rename = "$value")]
    pub children: Vec<ConsequenceChild>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ConsequenceChild {
    #[serde(rename = "Scope")]
    Scope(String),
    #[serde(rename = "Impact")]
    Impact(String),
    #[serde(rename = "Note")]
    Note(String),
    #[serde(rename = "Likelihood")]
    Likelihood(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlternateTerms {
    #[serde(rename = "$value")]
    pub alternate_terms: Vec<AlternateTerm>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExploitationFactors {
    #[serde(rename = "$value")]
    pub children: Vec<StructuredText>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlternateTerm {
    #[serde(rename = "Term")]
    pub term: String,
    #[serde(rename = "Description")]
    pub description: Option<StructuredText>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModesOfIntroduction {
    #[serde(rename = "$value")]
    pub introductions: Vec<Introduction>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Introduction {
    #[serde(rename = "Phase")]
    pub phase: String,
    #[serde(rename = "Note")]
    pub note: Option<StructuredText>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackgroundDetails {
    #[serde(rename = "$value", default)]
    pub background_details: Vec<StructuredText>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicablePlatforms {
    #[serde(rename = "$value")]
    pub applicable_platforms: Vec<ApplicablePlatform>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ApplicablePlatform {
    Language {
        #[serde(rename = "@Class")]
        class: Option<String>,
        #[serde(rename = "@Name")]
        name: Option<String>,
        #[serde(rename = "@Prevalence")]
        prevalence: String,
    },
    Technology {
        #[serde(rename = "@Name")]
        name: Option<String>,
        #[serde(rename = "@Class")]
        class: Option<String>,
        #[serde(rename = "@Prevalence")]
        prevalence: String,
    },
    #[serde(rename = "Operating_System")]
    OperatingSystem {
        #[serde(rename = "@Name")]
        name: Option<String>,
        #[serde(rename = "@Version")]
        version: Option<String>,
        #[serde(rename = "@CPE_ID")]
        cpe_id: Option<String>,
        #[serde(rename = "@Class")]
        class: Option<String>,
        #[serde(rename = "@Prevalence")]
        prevalence: String,
    },
    #[serde(rename = "Architecture")]
    Architecture {
        #[serde(rename = "@Name")]
        name: Option<String>,
        #[serde(rename = "@Class")]
        class: Option<String>,
        #[serde(rename = "@Prevalence")]
        prevalence: String,
    },
}