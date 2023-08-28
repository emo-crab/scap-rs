// @generated automatically by Diesel CLI.

diesel::table! {
    cve_product (cve_id, product_id) {
        #[max_length = 16]
        cve_id -> Varchar,
        #[max_length = 16]
        product_id -> Binary,
    }
}

diesel::table! {
    cves (id) {
        #[max_length = 32]
        id -> Varchar,
        year -> Integer,
        official -> Unsigned<Tinyint>,
        #[max_length = 64]
        assigner -> Varchar,
        references -> Json,
        description -> Json,
        problem_type -> Json,
        #[max_length = 16]
        cvss3_id -> Nullable<Binary>,
        #[max_length = 16]
        cvss2_id -> Nullable<Binary>,
        configurations -> Json,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    cvss2 (id) {
        #[max_length = 16]
        id -> Binary,
        #[max_length = 36]
        version -> Varchar,
        #[max_length = 256]
        vector_string -> Varchar,
        #[max_length = 36]
        access_vector -> Varchar,
        #[max_length = 36]
        access_complexity -> Varchar,
        #[max_length = 36]
        authentication -> Varchar,
        #[max_length = 36]
        confidentiality_impact -> Varchar,
        #[max_length = 36]
        integrity_impact -> Varchar,
        #[max_length = 36]
        availability_impact -> Varchar,
        base_score -> Float,
        exploitability_score -> Float,
        impact_score -> Float,
        #[max_length = 36]
        severity -> Varchar,
        ac_insuf_info -> Nullable<Unsigned<Tinyint>>,
        obtain_all_privilege -> Unsigned<Tinyint>,
        obtain_user_privilege -> Unsigned<Tinyint>,
        obtain_other_privilege -> Unsigned<Tinyint>,
        user_interaction_required -> Nullable<Unsigned<Tinyint>>,
    }
}

diesel::table! {
    cvss3 (id) {
        #[max_length = 16]
        id -> Binary,
        #[max_length = 36]
        version -> Varchar,
        #[max_length = 256]
        vector_string -> Varchar,
        #[max_length = 36]
        attack_vector -> Varchar,
        #[max_length = 36]
        attack_complexity -> Varchar,
        #[max_length = 36]
        privileges_required -> Varchar,
        #[max_length = 36]
        user_interaction -> Varchar,
        #[max_length = 36]
        scope -> Varchar,
        #[max_length = 36]
        confidentiality_impact -> Varchar,
        #[max_length = 36]
        integrity_impact -> Varchar,
        #[max_length = 36]
        availability_impact -> Varchar,
        base_score -> Float,
        #[max_length = 36]
        base_severity -> Varchar,
        exploitability_score -> Float,
        impact_score -> Float,
    }
}

diesel::table! {
    cwes (id) {
        id -> Integer,
        #[max_length = 256]
        name -> Varchar,
        description -> Text,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    products (id) {
        #[max_length = 16]
        id -> Binary,
        #[max_length = 16]
        vendor_id -> Binary,
        official -> Unsigned<Tinyint>,
        #[max_length = 1]
        part -> Char,
        #[max_length = 128]
        name -> Varchar,
        description -> Nullable<Text>,
        #[max_length = 256]
        homepage -> Nullable<Varchar>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    vendors (id) {
        #[max_length = 16]
        id -> Binary,
        official -> Unsigned<Tinyint>,
        #[max_length = 128]
        name -> Varchar,
        description -> Nullable<Text>,
        #[max_length = 256]
        homepage -> Nullable<Varchar>,
        updated_at -> Timestamp,
        created_at -> Timestamp,
    }
}

diesel::joinable!(cve_product -> cves (cve_id));
diesel::joinable!(cve_product -> products (product_id));
diesel::joinable!(cves -> cvss2 (cvss2_id));
diesel::joinable!(cves -> cvss3 (cvss3_id));
diesel::joinable!(products -> vendors (vendor_id));

diesel::allow_tables_to_appear_in_same_query!(
  cve_product,
  cves,
  cvss2,
  cvss3,
  cwes,
  products,
  vendors,
);
