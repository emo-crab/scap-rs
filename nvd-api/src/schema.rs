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
        #[max_length = 64]
        cvss3_vector -> Varchar,
        cvss3_score -> Float,
        #[max_length = 64]
        cvss2_vector -> Varchar,
        cvss2_score -> Float,
        configurations -> Json,
        created_at -> Timestamp,
        updated_at -> Timestamp,
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
diesel::joinable!(products -> vendors (vendor_id));

diesel::allow_tables_to_appear_in_same_query!(
    cve_product,
    cves,
    cwes,
    products,
    vendors,
);
