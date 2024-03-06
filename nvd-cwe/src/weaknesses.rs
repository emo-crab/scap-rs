//! A weakness is a mistake or condition that, if left unaddressed, could under the proper
//! conditions contribute to a cyber-enabled capability being vulnerable to attack, allowing an
//! adversary to make items function in unintended ways. This complexType is used to describe a
//! specific type of weakness and provide a variety of information related to it.
//!
//! The required Description should be short and limited to the key points that define this
//! weakness. The optional Extended_Description element provides a place for additional details
//! important to this weakness, but that are not necessary to convey the fundamental concept behind
//! the weakness. A number of other optional elements are available, each of which is described in
//! more detail within the corresponding complexType that it references.
//!
//! The required ID attribute provides a unique identifier for the entry. It is considered static
//! for the lifetime of the entry. If this entry becomes deprecated, the identifier will not be
//! reused. The required Name attribute is a string that identifies the entry. The name should
//! focus on the weakness being described and should avoid mentioning the attack that exploits the
//! weakness or the consequences of exploiting the weakness. All words in the entry name should be
//! capitalized except for articles and prepositions, unless they begin or end the name. Subsequent
//! words in a hyphenated chain are also not capitalized. The required Abstraction attribute defines
//! the abstraction level for this weakness. The required Structure attribute defines the structural
//! nature of the weakness. The required Status attribute defines the maturity of the information
//! for this weakness.
//!
use serde::{Deserialize, Serialize};

use crate::content_history::ContentHistory;
use crate::mapping_notes::MappingNotes;
use crate::notes::Notes;
use crate::structured_text::{StructuredCode, StructuredText};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Weaknesses {
  #[serde(rename(deserialize = "Weakness"))]
  pub weaknesses: Vec<Weakness>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename(deserialize = "Weakness"))]
#[serde(deny_unknown_fields)]
pub struct Weakness {
  #[serde(rename(deserialize = "@ID"))]
  pub id: i32,
  #[serde(rename(deserialize = "@Name"))]
  pub name: String,
  #[serde(rename(deserialize = "@Abstraction"))]
  pub abstraction: String,
  #[serde(rename(deserialize = "@Structure"))]
  pub structure: String,
  #[serde(rename(deserialize = "@Status"))]
  pub status: Status,
  #[serde(rename(deserialize = "Description"))]
  pub description: String,
  #[serde(rename(deserialize = "Extended_Description"))]
  pub extended_description: Option<StructuredText>,
  #[serde(rename(deserialize = "Related_Weaknesses"))]
  pub related_weaknesses: Option<RelatedWeaknesses>,
  #[serde(rename(deserialize = "Demonstrative_Examples"))]
  pub demonstrative_examples: Option<DemonstrativeExamples>,
  #[serde(rename(deserialize = "Weakness_Ordinalities"))]
  pub weakness_ordinalities: Option<WeaknessOrdinalities>,
  #[serde(rename(deserialize = "Applicable_Platforms"))]
  pub applicable_platforms: Option<ApplicablePlatforms>,
  #[serde(rename(deserialize = "Background_Details"))]
  pub background_details: Option<BackgroundDetails>,
  #[serde(rename(deserialize = "Modes_Of_Introduction"))]
  pub modes_of_introduction: Option<ModesOfIntroduction>,
  #[serde(rename(deserialize = "Likelihood_Of_Exploit"))]
  pub likelihood_of_exploit: Option<String>,
  #[serde(rename(deserialize = "Alternate_Terms"))]
  pub alternate_terms: Option<AlternateTerms>,
  #[serde(rename(deserialize = "Common_Consequences"))]
  pub common_consequences: Option<CommonConsequences>,
  #[serde(rename(deserialize = "Detection_Methods"))]
  pub detection_methods: Option<DetectionMethods>,
  #[serde(rename(deserialize = "Potential_Mitigations"))]
  pub potential_mitigations: Option<PotentialMitigations>,
  #[serde(rename(deserialize = "Observed_Examples"))]
  pub observed_examples: Option<ObservedExamples>,
  #[serde(rename(deserialize = "Related_Attack_Patterns"))]
  pub related_attack_patterns: Option<RelatedAttackPatterns>,
  #[serde(rename(deserialize = "References"))]
  pub references: Option<References>,
  #[serde(rename(deserialize = "Content_History"))]
  pub content_history: ContentHistory,
  #[serde(rename(deserialize = "Exploitation_Factors"))]
  pub exploitation_factors: Option<ExploitationFactors>,
  #[serde(rename(deserialize = "Functional_Areas"))]
  pub functional_areas: Option<FunctionalAreas>,
  #[serde(rename(deserialize = "Affected_Resources"))]
  pub affected_resources: Option<AffectedResources>,
  #[serde(rename(deserialize = "Taxonomy_Mappings"))]
  pub taxonomy_mappings: Option<TaxonomyMappings>,
  #[serde(rename(deserialize = "Notes"))]
  pub notes: Option<Notes>,
  #[serde(rename(deserialize = "Mapping_Notes"))]
  pub mapping_notes: MappingNotes,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum Status {
  Deprecated,
  Draft,
  Incomplete,
  Obsolete,
  Stable,
}
#[derive(Debug, Deserialize, Serialize, PartialEq)]
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
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WeaknessOrdinalities {
  #[serde(rename(deserialize = "$value"))]
  pub weakness_ordinalities: Vec<WeaknessOrdinality>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WeaknessOrdinality {
  #[serde(rename(deserialize = "Ordinality"))]
  pub ordinality: Option<String>,
  #[serde(rename(deserialize = "Description"))]
  pub description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename(deserialize = "Related_Weaknesses"))]
#[serde(deny_unknown_fields)]
pub struct RelatedWeaknesses {
  #[serde(rename(deserialize = "Related_Weakness"), default)]
  pub related_weaknesses: Vec<RelatedWeakness>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename(deserialize = "Related_Weakness"))]
#[serde(deny_unknown_fields)]
pub struct RelatedWeakness {
  #[serde(rename(deserialize = "@Nature"))]
  pub nature: RelatedNature,
  #[serde(rename(deserialize = "@CWE_ID"))]
  pub cwe_id: i64,
  #[serde(rename(deserialize = "@View_ID"))]
  pub view_id: i64,
  #[serde(rename(deserialize = "@Chain_ID"))]
  pub chain_id: Option<i64>,
  #[serde(rename(deserialize = "@Ordinal"))]
  pub ordinal: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyMappings {
  #[serde(rename(deserialize = "$value"))]
  pub taxonomy_mappings: Vec<TaxonomyMapping>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyMapping {
  #[serde(rename(deserialize = "@Taxonomy_Name"))]
  pub taxonomy_name: String,
  #[serde(rename(deserialize = "Entry_ID"))]
  pub entry_id: Option<String>,
  #[serde(rename(deserialize = "Entry_Name"))]
  pub entry_name: Option<String>,
  #[serde(rename(deserialize = "Mapping_Fit"))]
  pub mapping_fit: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionalAreas {
  #[serde(rename(deserialize = "$value"))]
  pub functional_areas: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AffectedResources {
  #[serde(rename(deserialize = "$value"))]
  pub affected_resources: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct References {
  #[serde(rename(deserialize = "$value"))]
  pub references: Vec<Reference>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
  #[serde(rename(deserialize = "@External_Reference_ID"))]
  pub external_reference_id: String,
  #[serde(rename(deserialize = "@Section"))]
  pub section: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedAttackPatterns {
  #[serde(rename(deserialize = "$value"))]
  pub related_attack_patterns: Vec<RelatedAttackPattern>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedAttackPattern {
  #[serde(rename(deserialize = "@CAPEC_ID"))]
  pub caped_id: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedExamples {
  #[serde(rename(deserialize = "$value"))]
  pub observed_examples: Vec<ObservedExample>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedExample {
  #[serde(rename(deserialize = "Reference"))]
  pub reference: String,
  #[serde(rename(deserialize = "Description"))]
  pub description: String,
  #[serde(rename(deserialize = "Link"))]
  pub link: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DemonstrativeExamples {
  #[serde(rename(deserialize = "Demonstrative_Example"))]
  pub examples: Vec<DemonstrativeExample>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DemonstrativeExample {
  #[serde(rename(deserialize = "@Demonstrative_Example_ID"))]
  pub demonstrative_example_id: Option<String>,
  #[serde(rename(deserialize = "$value"))]
  pub children: Vec<DemonstrativeExampleChild>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all(serialize = "snake_case"))]
pub enum DemonstrativeExampleChild {
  #[serde(rename(deserialize = "Title_Text"))]
  TitleText(String),
  #[serde(rename(deserialize = "Intro_Text"))]
  IntroText(StructuredText),
  #[serde(rename(deserialize = "Body_Text"))]
  BodyText(StructuredText),
  #[serde(rename(deserialize = "Example_Code"))]
  ExampleCode(StructuredCode),
  #[serde(rename(deserialize = "References"))]
  References {
    #[serde(rename(deserialize = "$value"))]
    children: Vec<Reference>,
  },
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PotentialMitigations {
  #[serde(rename(deserialize = "$value"))]
  pub potential_mitigations: Vec<PotentialMitigation>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PotentialMitigation {
  #[serde(rename(deserialize = "@Mitigation_ID"))]
  pub mitigation_id: Option<String>,
  #[serde(rename(deserialize = "$value"))]
  pub children: Vec<PotentialMitigationChild>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all(serialize = "snake_case"))]
pub enum PotentialMitigationChild {
  #[serde(rename(deserialize = "Phase"))]
  Phase(String),
  #[serde(rename(deserialize = "Strategy"))]
  Strategy(String),
  #[serde(rename(deserialize = "Description"))]
  Description(StructuredText),
  #[serde(rename(deserialize = "Effectiveness"))]
  Effectiveness(String),
  #[serde(rename(deserialize = "Effectiveness_Notes"))]
  EffectivenessNotes(StructuredText),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionMethods {
  #[serde(rename(deserialize = "$value"))]
  pub detection_methods: Vec<DetectionMethod>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionMethod {
  #[serde(rename(deserialize = "@Detection_Method_ID"))]
  pub detection_method_id: Option<String>,
  #[serde(rename(deserialize = "$value"))]
  pub children: Vec<DetectionMethodChild>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all(serialize = "snake_case"))]
pub enum DetectionMethodChild {
  #[serde(rename(deserialize = "Method"))]
  Method(String),
  #[serde(rename(deserialize = "Description"))]
  Description(StructuredText),
  #[serde(rename(deserialize = "Effectiveness"))]
  Effectiveness(String),
  #[serde(rename(deserialize = "Effectiveness_Notes"))]
  EffectivenessNotes(String),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommonConsequences {
  #[serde(rename(deserialize = "$value"))]
  pub common_consequences: Vec<Consequence>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Consequence {
  #[serde(rename(deserialize = "$value"))]
  pub children: Vec<ConsequenceChild>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all(deserialize = "PascalCase"))]
pub enum ConsequenceChild {
  #[serde(rename(deserialize = "Scope"))]
  Scope(String),
  #[serde(rename(deserialize = "Impact"))]
  Impact(String),
  #[serde(rename(deserialize = "Note"))]
  Note(String),
  #[serde(rename(deserialize = "Likelihood"))]
  Likelihood(String),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AlternateTerms {
  #[serde(rename(deserialize = "$value"))]
  pub alternate_terms: Vec<AlternateTerm>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExploitationFactors {
  #[serde(rename(deserialize = "$value"))]
  pub children: Vec<StructuredText>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AlternateTerm {
  #[serde(rename(deserialize = "Term"))]
  pub term: String,
  #[serde(rename(deserialize = "Description"))]
  pub description: Option<StructuredText>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModesOfIntroduction {
  #[serde(rename(deserialize = "$value"))]
  pub introductions: Vec<Introduction>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Introduction {
  #[serde(rename(deserialize = "Phase"))]
  pub phase: String,
  #[serde(rename(deserialize = "Note"))]
  pub note: Option<StructuredText>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackgroundDetails {
  #[serde(rename(deserialize = "$value"), default)]
  pub background_details: Vec<StructuredText>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicablePlatforms {
  #[serde(rename(deserialize = "$value"))]
  pub applicable_platforms: Vec<ApplicablePlatform>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all(serialize = "snake_case"))]
pub enum ApplicablePlatform {
  Language {
    #[serde(rename(deserialize = "@Class"))]
    class: Option<String>,
    #[serde(rename(deserialize = "@Name"))]
    name: Option<String>,
    #[serde(rename(deserialize = "@Prevalence"))]
    prevalence: String,
  },
  Technology {
    #[serde(rename(deserialize = "@Name"))]
    name: Option<String>,
    #[serde(rename(deserialize = "@Class"))]
    class: Option<String>,
    #[serde(rename(deserialize = "@Prevalence"))]
    prevalence: String,
  },
  #[serde(rename(deserialize = "Operating_System"))]
  OperatingSystem {
    #[serde(rename(deserialize = "@Name"))]
    name: Option<String>,
    #[serde(rename(deserialize = "@Version"))]
    version: Option<String>,
    #[serde(rename(deserialize = "@CPE_ID"))]
    cpe_id: Option<String>,
    #[serde(rename(deserialize = "@Class"))]
    class: Option<String>,
    #[serde(rename(deserialize = "@Prevalence"))]
    prevalence: String,
  },
  #[serde(rename(deserialize = "Architecture"))]
  Architecture {
    #[serde(rename(deserialize = "@Name"))]
    name: Option<String>,
    #[serde(rename(deserialize = "@Class"))]
    class: Option<String>,
    #[serde(rename(deserialize = "@Prevalence"))]
    prevalence: String,
  },
}
