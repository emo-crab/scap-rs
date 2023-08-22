// @generated automatically by Diesel CLI.

diesel::table! {
    cves (id) {
        #[max_length = 16]
        id -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        references -> Json,
        description -> Json,
        cwe -> Json,
        #[max_length = 16]
        cvss3_id -> Nullable<Binary>,
        #[max_length = 16]
        cvss2_id -> Nullable<Binary>,
        raw -> Json,
        #[max_length = 64]
        assigner -> Varchar,
        #[max_length = 16]
        product_id -> Binary,
        configurations -> Json,
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
        #[max_length = 36]
        ac_insuf_info -> Nullable<Varchar>,
        obtain_all_privilege -> Tinyint,
        obtain_user_privilege -> Tinyint,
        obtain_other_privilege -> Tinyint,
        user_interaction_required -> Nullable<Tinyint>,
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
    products (id) {
        #[max_length = 16]
        id -> Binary,
        #[max_length = 16]
        vendor_id -> Binary,
        #[max_length = 128]
        name -> Varchar,
        description -> Nullable<Text>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        #[max_length = 256]
        homepage -> Nullable<Varchar>,
        official -> Unsigned<Tinyint>,
        #[max_length = 1]
        part -> Char,
    }
}

diesel::table! {
    vendors (id) {
        #[max_length = 16]
        id -> Binary,
        #[max_length = 128]
        name -> Varchar,
        description -> Nullable<Text>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        #[max_length = 256]
        homepage -> Nullable<Varchar>,
        official -> Unsigned<Tinyint>,
    }
}

diesel::joinable!(cves -> cvss2 (cvss2_id));
diesel::joinable!(cves -> cvss3 (cvss3_id));
diesel::joinable!(cves -> products (product_id));
diesel::joinable!(products -> vendors (vendor_id));

diesel::allow_tables_to_appear_in_same_query!(
    cves,
    cvss2,
    cvss3,
    products,
    vendors,
);
