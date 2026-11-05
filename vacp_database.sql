-- =====================================================================
--  VACP Database
--  Volunteer Management and Activity Coordination System
--  Volunteerism and Active Citizenship Program (VACP), City of Cagayan de Oro
--
--
--
--  CONVENTIONS
--    * Ids are CHAR(36) UUIDs generated with UUID().
--    * Business records are never hard-deleted. Use the status columns
--      (archived, revoked, deactivated ...). Foreign keys are RESTRICT.
--    * Every table has created_at and updated_at, except the append-only
--      logs audit_log and sensitive_access_log.
--    * Columns marked [S] in their comment are required before a
--      registration is submitted, but stay NULL while it is a draft.
--      The application enforces that rule.
--    * Medical, food and emergency contact values are encrypted by the
--      application before they are stored. The database never sees plain text.
-- =====================================================================

SET NAMES utf8mb4;
CREATE DATABASE IF NOT EXISTS vacp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE vacp;

SET FOREIGN_KEY_CHECKS = 0;


-- ---------------------------------------------------------------------
--  GROUP 1. IDENTITY AND ACCESS
-- ---------------------------------------------------------------------

CREATE TABLE user_account (
    user_id             CHAR(36)                                                        NOT NULL COMMENT 'Unique id the system generates for the account, for example 3f2b9c1e-....',
    email               VARCHAR(150)                                                    NOT NULL COMMENT 'The email address the person signs in with, for example maria.santos@gmail.com.',
    email_verified_at   DATETIME                                                        NULL COMMENT 'Date and time the person confirmed their email by clicking the link.',
    username            VARCHAR(60)                                                     NULL COMMENT 'Optional short name for people who do not use Google sign-in, for example msantos.',
    password_hash       VARCHAR(255)                                                    NULL COMMENT 'The password after secure one-way hashing.',
    google_subject_id   VARCHAR(100)                                                    NULL COMMENT 'The permanent identifier Google gives this person, used to recognize a returning Google sign-in even if the Gmail address changes.',
    display_name        VARCHAR(120)                                                    NOT NULL COMMENT 'The name shown in the app header and greetings, for example Maria Santos.',
    mobile_number       VARCHAR(20)                                                     NULL COMMENT 'Philippine mobile number in the form 09123456789, used for contact and optional SMS notices.',
    account_status      ENUM('invited', 'active', 'locked', 'deactivated', 'archived')  NOT NULL DEFAULT 'invited' COMMENT 'Whether the account can log in: invited (created by an admin, not yet activated), active, locked (too many failed attempts or blocked for security)...',
    failed_login_count  INT                                                             NOT NULL DEFAULT 0 COMMENT 'How many wrong passwords were entered in a row.',
    locked_until        DATETIME                                                        NULL COMMENT 'If the account is temporarily locked, the date and time it unlocks.',
    last_login_at       DATETIME                                                        NULL COMMENT 'Date and time of the most recent successful login.',
    force_logout_at     DATETIME                                                        NULL COMMENT 'If set, every session started before this moment becomes invalid.',
    created_at          DATETIME                                                        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME                                                        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    UNIQUE KEY uq_user_account_email (email),
    UNIQUE KEY uq_user_account_username (username),
    UNIQUE KEY uq_user_account_google_subject_id (google_subject_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The sign-in account of every person who uses the system, for all eight roles.';

CREATE TABLE email_verification_token (
    token_id       CHAR(36)      NOT NULL COMMENT 'Unique id of this verification request.',
    user_id        CHAR(36)      NOT NULL COMMENT 'The account whose email is being confirmed.',
    token_hash     VARCHAR(255)  NOT NULL COMMENT 'Secure hash of the one-time code inside the emailed link.',
    sent_to_email  VARCHAR(150)  NOT NULL COMMENT 'The email address the link was sent to, kept in case the person changes email later.',
    expires_at     DATETIME      NOT NULL COMMENT 'When the link stops working, for example 24 hours after it was sent.',
    used_at        DATETIME      NULL COMMENT 'When the person clicked the link.',
    created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (token_id),
    CONSTRAINT fk_email_verification_token_user_id FOREIGN KEY (user_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='One-time links sent to confirm an email address after sign-up.';

CREATE TABLE `role` (
    role_id            CHAR(36)      NOT NULL COMMENT 'Unique id of the role.',
    role_code          VARCHAR(30)   NOT NULL COMMENT 'Short machine code: ADMIN, PROGRAM_COORDINATOR, ACTIVITY_COORDINATOR, BARANGAY_FOCAL, ORG_REP, VOLUNTEER, TEAM_LEADER, ATTENDANCE_STAFF.',
    role_name          VARCHAR(80)   NOT NULL COMMENT 'Readable name shown in screens, for example VACP Program Coordinator.',
    is_temporary_duty  BOOLEAN       NOT NULL DEFAULT FALSE COMMENT 'True for Team Leader and Attendance Staff, which are only given for one activity or session.',
    description        VARCHAR(300)  NULL COMMENT 'One or two sentences explaining what this role is for.',
    created_at         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id),
    UNIQUE KEY uq_role_role_code (role_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The eight functional roles of the system.';

CREATE TABLE permission (
    permission_id    CHAR(36)      NOT NULL COMMENT 'Unique id of the permission.',
    permission_code  VARCHAR(80)   NOT NULL COMMENT 'Short code the program checks, for example ACTIVITY_APPROVE, ATTENDANCE_VERIFY, VOLUNTEER_APPLY.',
    module           VARCHAR(60)   NOT NULL COMMENT 'The part of the system this permission belongs to, for example Activities, Attendance, Certificates.',
    description      VARCHAR(300)  NULL COMMENT 'Plain-language explanation of what the permission allows.',
    created_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (permission_id),
    UNIQUE KEY uq_permission_permission_code (permission_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='One specific action a role can be allowed to do, such as approving an activity or verifying attendance.';

CREATE TABLE role_permission (
    role_id        CHAR(36)                                                                      NOT NULL COMMENT 'The role receiving the permission.',
    permission_id  CHAR(36)                                                                      NOT NULL COMMENT 'The permission being given to the role.',
    scope_type     ENUM('all', 'own_affiliation', 'assigned_activity', 'session', 'own_record')  NOT NULL COMMENT 'How far the permission reaches: all records, own_affiliation (only their barangay or organization), assigned_activity, session (only the session on...',
    created_at     DATETIME                                                                      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME                                                                      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_role_permission_role_id FOREIGN KEY (role_id) REFERENCES `role` (role_id),
    CONSTRAINT fk_role_permission_permission_id FOREIGN KEY (permission_id) REFERENCES permission (permission_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The permission matrix.';

CREATE TABLE user_role (
    user_role_id      CHAR(36)                          NOT NULL COMMENT 'Unique id of this role grant.',
    user_id           CHAR(36)                          NOT NULL COMMENT 'The account that holds the role.',
    role_id           CHAR(36)                          NOT NULL COMMENT 'The permanent role given, for example VOLUNTEER or BARANGAY_FOCAL.',
    affiliation_type  ENUM('barangay', 'organization')  NULL COMMENT 'For barangay and organization users: barangay or organization.',
    barangay_id       CHAR(36)                          NULL COMMENT 'The barangay this user represents.',
    org_id            CHAR(36)                          NULL COMMENT 'The organization this user represents.',
    granted_by        CHAR(36)                          NOT NULL COMMENT 'The administrator who gave this role.',
    granted_at        DATETIME                          NOT NULL COMMENT 'Date and time the role was granted.',
    revoked_by        CHAR(36)                          NULL COMMENT 'The administrator who removed the role, if it was removed.',
    revoked_at        DATETIME                          NULL COMMENT 'Date and time the role was removed.',
    revoke_reason     VARCHAR(300)                      NULL COMMENT 'Why the role was removed.',
    created_at        DATETIME                          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME                          NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (user_role_id),
    CONSTRAINT fk_user_role_user_id FOREIGN KEY (user_id) REFERENCES user_account (user_id),
    CONSTRAINT fk_user_role_role_id FOREIGN KEY (role_id) REFERENCES `role` (role_id),
    CONSTRAINT fk_user_role_barangay_id FOREIGN KEY (barangay_id) REFERENCES barangay (barangay_id),
    CONSTRAINT fk_user_role_org_id FOREIGN KEY (org_id) REFERENCES partner_organization (org_id),
    CONSTRAINT fk_user_role_granted_by FOREIGN KEY (granted_by) REFERENCES user_account (user_id),
    CONSTRAINT fk_user_role_revoked_by FOREIGN KEY (revoked_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Records which permanent role an account holds, who granted it and when.';

CREATE TABLE user_session (
    session_id    CHAR(36)                                       NOT NULL COMMENT 'Unique id of the session.',
    user_id       CHAR(36)                                       NOT NULL COMMENT 'The account that signed in.',
    device_info   VARCHAR(200)                                   NULL COMMENT 'Description of the browser or phone, for example Chrome on Android.',
    ip_address    VARCHAR(45)                                    NULL COMMENT 'Internet address the sign-in came from, kept for security review.',
    started_at    DATETIME                                       NOT NULL COMMENT 'Date and time the person signed in.',
    last_seen_at  DATETIME                                       NULL COMMENT 'Date and time of the last action in this session.',
    ended_at      DATETIME                                       NULL COMMENT 'Date and time the session ended.',
    end_reason    ENUM('logout', 'timeout', 'forced', 'locked')  NULL COMMENT 'How it ended: logout (person signed out), timeout, forced (admin), locked.',
    created_at    DATETIME                                       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME                                       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (session_id),
    CONSTRAINT fk_user_session_user_id FOREIGN KEY (user_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Each time someone signs in on a browser or phone.';

CREATE TABLE account_recovery (
    recovery_id   CHAR(36)                                               NOT NULL COMMENT 'Unique id of the recovery request.',
    user_id       CHAR(36)                                               NOT NULL COMMENT 'The account being recovered.',
    initiated_by  CHAR(36)                                               NULL COMMENT 'The administrator who started the reset, if it was not started by the person themselves.',
    method        ENUM('email_link', 'admin_reset', 'support_verified')  NOT NULL COMMENT 'How access is restored: email_link (self-service), admin_reset, or support_verified (identity checked through a support ticket).',
    token_hash    VARCHAR(255)                                           NULL COMMENT 'Secure hash of the one-time reset code.',
    requested_at  DATETIME                                               NOT NULL COMMENT 'Date and time the recovery was requested.',
    expires_at    DATETIME                                               NOT NULL COMMENT 'Date and time the reset code stops working.',
    used_at       DATETIME                                               NULL COMMENT 'Date and time the code was used.',
    status        ENUM('pending', 'completed', 'expired', 'cancelled')   NOT NULL DEFAULT 'pending' COMMENT 'pending, completed, expired or cancelled.',
    created_at    DATETIME                                               NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME                                               NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (recovery_id),
    CONSTRAINT fk_account_recovery_user_id FOREIGN KEY (user_id) REFERENCES user_account (user_id),
    CONSTRAINT fk_account_recovery_initiated_by FOREIGN KEY (initiated_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Requests to reset a password or recover access to an account.';


-- ---------------------------------------------------------------------
--  GROUP 2. REFERENCE DATA AND NOTICES
-- ---------------------------------------------------------------------

CREATE TABLE reference_option (
    option_id           CHAR(36)      NOT NULL COMMENT 'Unique id of the choice.',
    list_code           VARCHAR(40)   NOT NULL COMMENT 'Which list the choice belongs to: SEX, CIVIL_STATUS, EDUCATION_LEVEL, AVAILABILITY, SUFFIX, FOOD_RESTRICTION, REFERRAL or PROGRAM_RESPONSE.',
    option_code         VARCHAR(40)   NOT NULL COMMENT 'Short stable code for the choice inside its list, for example PORK or SOCIAL_MEDIA.',
    label               VARCHAR(150)  NOT NULL COMMENT 'The text people see, for example Pork or Friend / Relative.',
    sort_order          INT           NULL COMMENT 'Position when the list is displayed.',
    is_client_approved  BOOLEAN       NOT NULL DEFAULT FALSE COMMENT 'False until the client confirms this choice.',
    is_active           BOOLEAN       NOT NULL DEFAULT TRUE COMMENT 'True if volunteers can still pick it.',
    created_at          DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (option_id),
    UNIQUE KEY uq_reference_option_list_code_option_code (list_code, option_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='One shared table for small approved choice lists: Sex, Civil Status, Education level, Availability, Suffix, Food restrictions, Referral source and program responses.';

CREATE TABLE skill (
    skill_id    CHAR(36)      NOT NULL COMMENT 'Unique id of the skill.',
    skill_code  VARCHAR(40)   NOT NULL COMMENT 'Short stable code, for example PHOTO_VIDEO.',
    name        VARCHAR(120)  NOT NULL COMMENT 'Readable name shown to volunteers, for example Software / Web / Mobile Programming.',
    category    VARCHAR(60)   NULL COMMENT 'Optional group, for example Media or Administration, to make long lists easier to browse.',
    is_active   BOOLEAN       NOT NULL DEFAULT TRUE COMMENT 'True if it can still be chosen.',
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (skill_id),
    UNIQUE KEY uq_skill_skill_code (skill_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The approved list of skills a volunteer can say they have, such as Photography and Video or Logistics.';

CREATE TABLE interest_field (
    interest_id     CHAR(36)      NOT NULL COMMENT 'Unique id of the interest field.',
    name            VARCHAR(120)  NOT NULL COMMENT 'Readable name, for example Disaster Risk Reduction & Management.',
    category        VARCHAR(60)   NULL COMMENT 'Optional group, for example Environment or Health.',
    merged_into_id  CHAR(36)      NULL COMMENT 'If this entry duplicates another (for example the repeated Peer Counseling), this points to the entry that is kept.',
    is_active       BOOLEAN       NOT NULL DEFAULT TRUE COMMENT 'True if it can still be chosen.',
    created_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (interest_id),
    UNIQUE KEY uq_interest_field_name (name),
    CONSTRAINT fk_interest_field_merged_into_id FOREIGN KEY (merged_into_id) REFERENCES interest_field (interest_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The approved list of causes or fields a volunteer cares about, such as Solid Waste Management or Senior Citizens.';

CREATE TABLE sdg (
    sdg_id       CHAR(36)      NOT NULL COMMENT 'Unique id of the goal.',
    sdg_no       INT           NOT NULL COMMENT 'The official goal number from 1 to 17.',
    title        VARCHAR(120)  NOT NULL COMMENT 'Official goal name, for example Clean Water and Sanitation.',
    description  VARCHAR(300)  NULL COMMENT 'A short plain-language explanation of the goal shown on help text.',
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (sdg_id),
    UNIQUE KEY uq_sdg_sdg_no (sdg_no),
    CONSTRAINT chk_sdg_sdg_no_range CHECK (sdg_no BETWEEN 1 AND 17)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The 17 United Nations Sustainable Development Goals.';

CREATE TABLE sector (
    sector_id                CHAR(36)      NOT NULL COMMENT 'Unique id of the sector.',
    name                     VARCHAR(120)  NOT NULL COMMENT 'Sector name shown to volunteers.',
    requires_school_details  BOOLEAN       NOT NULL DEFAULT FALSE COMMENT 'True for In-School Youth, which makes the school name and address fields appear in the registration.',
    is_active                BOOLEAN       NOT NULL DEFAULT TRUE COMMENT 'True if it can still be chosen.',
    created_at               DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (sector_id),
    UNIQUE KEY uq_sector_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The community sector a volunteer belongs to, such as In-School Youth, Person with Disability or Farmer / Fisherfolk.';

CREATE TABLE registration_route (
    route_id             CHAR(36)      NOT NULL COMMENT 'Unique id of the route.',
    route_code           VARCHAR(40)   NOT NULL COMMENT 'Short stable code, for example NEW_REGISTRATION or UPDATE_PAST_ENTRY.',
    label                VARCHAR(120)  NOT NULL COMMENT 'Text shown to the volunteer.',
    is_enabled           BOOLEAN       NOT NULL DEFAULT TRUE COMMENT 'If false, the route cannot be chosen yet.',
    is_client_confirmed  BOOLEAN       NOT NULL DEFAULT FALSE COMMENT 'EVO-only routes stay false and disabled until the client confirms they apply.',
    created_at           DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (route_id),
    UNIQUE KEY uq_registration_route_route_code (route_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The way a person entered the system, such as New Registration, Update Past Entry or a village volunteer route.';

CREATE TABLE legacy_label_mapping (
    mapping_id    CHAR(36)      NOT NULL COMMENT 'Unique id of the mapping.',
    source_field  VARCHAR(80)   NOT NULL COMMENT 'The old form question the label came from, for example SKILLS.',
    legacy_label  VARCHAR(200)  NOT NULL COMMENT 'The exact old label text, for example Human Rights and Advocacy.',
    target_table  VARCHAR(60)   NOT NULL COMMENT 'The new list it maps to, for example interest_field.',
    target_id     CHAR(36)      NOT NULL COMMENT 'The row in the new list that replaces the old label.',
    mapped_by     CHAR(36)      NOT NULL COMMENT 'The administrator who made the mapping.',
    created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (mapping_id),
    CONSTRAINT fk_legacy_label_mapping_mapped_by FOREIGN KEY (mapped_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Connects labels from the old Google Form to the new approved lists, so old answers can be moved over correctly.';

CREATE TABLE consent_document (
    consent_id      CHAR(36)                               NOT NULL COMMENT 'Unique id of this document version.',
    doc_type        ENUM('terms', 'privacy', 'notice')     NOT NULL COMMENT 'terms, privacy or notice.',
    version_no      INT                                    NOT NULL DEFAULT 1 COMMENT 'Version number, starting at 1.',
    title           VARCHAR(200)                           NOT NULL COMMENT 'Document title, for example Volunteer Terms and Conditions.',
    body_text       TEXT                                   NOT NULL COMMENT 'The full approved text people read and accept.',
    status          ENUM('draft', 'published', 'retired')  NOT NULL DEFAULT 'draft' COMMENT 'draft (still being edited), published (in use) or retired (replaced by a newer version).',
    effective_from  DATE                                   NULL COMMENT 'Date this version starts to apply.',
    published_by    CHAR(36)                               NULL COMMENT 'The administrator who published it.',
    published_at    DATETIME                               NULL COMMENT 'Date and time it was published.',
    created_at      DATETIME                               NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME                               NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (consent_id),
    UNIQUE KEY uq_consent_document_doc_type_version_no (doc_type, version_no),
    CONSTRAINT fk_consent_document_published_by FOREIGN KEY (published_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Versioned Terms and Conditions, Privacy notice and other notices.';


-- ---------------------------------------------------------------------
--  GROUP 3. BARANGAYS AND ORGANIZATIONS
-- ---------------------------------------------------------------------

CREATE TABLE barangay (
    barangay_id              CHAR(36)                                               NOT NULL COMMENT 'Unique id of the barangay.',
    name                     VARCHAR(100)                                           NOT NULL COMMENT 'Official barangay name, for example Carmen.',
    city_municipality        VARCHAR(80)                                            NOT NULL COMMENT 'City the barangay belongs to.',
    official_contact_number  VARCHAR(20)                                            NULL COMMENT 'The barangay hall phone number.',
    official_email           VARCHAR(150)                                           NULL COMMENT 'The barangay official email address.',
    address                  VARCHAR(250)                                           NULL COMMENT 'Street address of the barangay hall.',
    latitude                 DECIMAL(9,6)                                           NULL COMMENT 'Latitude of the barangay centre, for example 8.454200.',
    longitude                DECIMAL(9,6)                                           NULL COMMENT 'Longitude of the barangay centre, for example 124.631900.',
    verification_status      ENUM('unverified', 'pending', 'verified', 'rejected')  NOT NULL DEFAULT 'unverified' COMMENT 'unverified, pending, verified or rejected.',
    verified_by              CHAR(36)                                               NULL COMMENT 'The staff member who verified the barangay.',
    verified_at              DATETIME                                               NULL COMMENT 'Date and time of verification.',
    is_active                BOOLEAN                                                NOT NULL DEFAULT TRUE COMMENT 'False if the record is archived.',
    created_at               DATETIME                                               NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               DATETIME                                               NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (barangay_id),
    UNIQUE KEY uq_barangay_name (name),
    CONSTRAINT fk_barangay_verified_by FOREIGN KEY (verified_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The list of barangays in Cagayan de Oro City.';

CREATE TABLE partner_organization (
    org_id               CHAR(36)                                               NOT NULL COMMENT 'Unique id of the organization.',
    name                 VARCHAR(200)                                           NOT NULL COMMENT 'Official organization name.',
    org_type             VARCHAR(60)                                            NULL COMMENT 'Kind of organization, for example School, NGO, Company or Civic group.',
    purpose              TEXT                                                   NULL COMMENT 'What the organization does, in its own words.',
    contact_number       VARCHAR(20)                                            NULL COMMENT 'Official phone number.',
    email                VARCHAR(150)                                           NULL COMMENT 'Official email address.',
    address              VARCHAR(250)                                           NULL COMMENT 'Office address.',
    barangay_id          CHAR(36)                                               NULL COMMENT 'The barangay where the organization is based.',
    verification_status  ENUM('unverified', 'pending', 'verified', 'rejected')  NOT NULL DEFAULT 'unverified' COMMENT 'unverified, pending, verified or rejected.',
    verified_by          CHAR(36)                                               NULL COMMENT 'The staff member who verified the organization.',
    verified_at          DATETIME                                               NULL COMMENT 'Date and time of verification.',
    is_active            BOOLEAN                                                NOT NULL DEFAULT TRUE COMMENT 'False if the record is archived.',
    created_at           DATETIME                                               NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME                                               NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (org_id),
    CONSTRAINT fk_partner_organization_barangay_id FOREIGN KEY (barangay_id) REFERENCES barangay (barangay_id),
    CONSTRAINT fk_partner_organization_verified_by FOREIGN KEY (verified_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Schools, NGOs, companies and civic groups that propose activities and bring their own members.';

CREATE TABLE representative (
    representative_id  CHAR(36)                                        NOT NULL COMMENT 'Unique id of this link.',
    user_id            CHAR(36)                                        NOT NULL COMMENT 'The representative''s account.',
    affiliation_type   ENUM('barangay', 'organization')                NOT NULL COMMENT 'barangay or organization.',
    barangay_id        CHAR(36)                                        NULL COMMENT 'Filled for barangay representatives.',
    org_id             CHAR(36)                                        NULL COMMENT 'Filled for organization representatives.',
    position_title     VARCHAR(100)                                    NULL COMMENT 'Their position, for example Barangay Secretary or Program Officer.',
    is_authorized      BOOLEAN                                         NOT NULL DEFAULT FALSE COMMENT 'True if they are an officially authorized representative who may submit requests.',
    start_date         DATE                                            NOT NULL COMMENT 'Date they started representing the group.',
    end_date           DATE                                            NULL COMMENT 'Date they stopped.',
    status             ENUM('pending', 'active', 'ended', 'rejected')  NOT NULL DEFAULT 'pending' COMMENT 'pending (awaiting verification), active, ended or rejected.',
    created_at         DATETIME                                        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME                                        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (representative_id),
    CONSTRAINT fk_representative_user_id FOREIGN KEY (user_id) REFERENCES user_account (user_id),
    CONSTRAINT fk_representative_barangay_id FOREIGN KEY (barangay_id) REFERENCES barangay (barangay_id),
    CONSTRAINT fk_representative_org_id FOREIGN KEY (org_id) REFERENCES partner_organization (org_id),
    CONSTRAINT chk_representative_affiliation_match CHECK (((affiliation_type = 'barangay' AND barangay_id IS NOT NULL) OR (affiliation_type = 'organization' AND org_id IS NOT NULL)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Connects a user account to the barangay or organization they officially speak for.';

CREATE TABLE verification_record (
    verification_id  CHAR(36)                                            NOT NULL COMMENT 'Unique id of this decision.',
    subject_type     ENUM('barangay', 'organization', 'representative')  NOT NULL COMMENT 'What was verified: barangay, organization or representative.',
    subject_id       CHAR(36)                                            NOT NULL COMMENT 'The id of that barangay, organization or representative.',
    decision         ENUM('verified', 'rejected', 'needs_info')          NOT NULL COMMENT 'verified, rejected or needs_info (more documents requested).',
    reviewer_id      CHAR(36)                                            NOT NULL COMMENT 'The staff member who decided.',
    remarks          TEXT                                                NULL COMMENT 'The reviewer''s explanation, for example Letter of authorization missing.',
    decided_at       DATETIME                                            NOT NULL COMMENT 'Date and time of the decision.',
    created_at       DATETIME                                            NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME                                            NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (verification_id),
    CONSTRAINT fk_verification_record_reviewer_id FOREIGN KEY (reviewer_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The history of every verification decision about a barangay, an organization or a representative.';

CREATE TABLE affiliation_history (
    history_id       CHAR(36)      NOT NULL COMMENT 'Unique id of this change.',
    user_id          CHAR(36)      NOT NULL COMMENT 'The person whose affiliation changed.',
    old_affiliation  JSON          NULL COMMENT 'What it was before, for example the old barangay and organization.',
    new_affiliation  JSON          NULL COMMENT 'What it is now.',
    changed_by       CHAR(36)      NOT NULL COMMENT 'The staff member who made the change.',
    reason           VARCHAR(300)  NOT NULL COMMENT 'Why it was changed, for example Moved to a new barangay.',
    changed_at       DATETIME      NOT NULL COMMENT 'Date and time of the change.',
    created_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (history_id),
    CONSTRAINT fk_affiliation_history_user_id FOREIGN KEY (user_id) REFERENCES user_account (user_id),
    CONSTRAINT fk_affiliation_history_changed_by FOREIGN KEY (changed_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Keeps every change or correction of someone''s barangay or organization link, so the past is never lost.';


-- ---------------------------------------------------------------------
--  GROUP 4. VOLUNTEER PROFILE
-- ---------------------------------------------------------------------

CREATE TABLE volunteer (
    volunteer_id             CHAR(36)                                                                                                                        NOT NULL COMMENT 'Unique id of the volunteer profile.',
    volunteer_code           VARCHAR(20)                                                                                                                     NOT NULL COMMENT 'Short readable volunteer ID shown in tables and on certificates, for example VOL-2026-00123.',
    user_id                  CHAR(36)                                                                                                                        NOT NULL COMMENT 'The login account that owns this profile.',
    last_name                VARCHAR(80)                                                                                                                     NULL COMMENT '[S] Family name, for example Santos.',
    first_name               VARCHAR(80)                                                                                                                     NULL COMMENT '[S] Given name, for example Maria.',
    middle_name              VARCHAR(80)                                                                                                                     NULL COMMENT 'Middle name, for example Dela Cruz.',
    no_middle_name           BOOLEAN                                                                                                                         NOT NULL DEFAULT FALSE COMMENT 'True when the volunteer has no middle name, which replaces the old No Middle Name choice.',
    suffix_option_id         CHAR(36)                                                                                                                        NULL COMMENT 'Name suffix such as Jr., Sr., II or III.',
    nickname                 VARCHAR(60)                                                                                                                     NULL COMMENT '[S] The name the volunteer likes to be called, for example Mia.',
    sex_option_id            CHAR(36)                                                                                                                        NULL COMMENT '[S] The volunteer''s sex from the client-approved list.',
    civil_status_option_id   CHAR(36)                                                                                                                        NULL COMMENT '[S] Civil status from the client-approved list, for example Single or Married.',
    date_of_birth            DATE                                                                                                                            NULL COMMENT '[S] Birth date.',
    barangay_id              CHAR(36)                                                                                                                        NULL COMMENT '[S] The barangay in Cagayan de Oro City where the volunteer lives.',
    contact_number           VARCHAR(20)                                                                                                                     NULL COMMENT '[S] Volunteer''s mobile number, for example 09123456789.',
    email                    VARCHAR(150)                                                                                                                    NULL COMMENT '[S] The volunteer''s working email address.',
    sector_id                CHAR(36)                                                                                                                        NULL COMMENT '[S] The community sector the volunteer belongs to, for example In-School Youth.',
    school_name              VARCHAR(150)                                                                                                                    NULL COMMENT 'For In-School Youth only: the abbreviated school name, for example CCS.',
    school_address           VARCHAR(200)                                                                                                                    NULL COMMENT 'For In-School Youth only: the school location, for example CDO.',
    education_option_id      CHAR(36)                                                                                                                        NULL COMMENT '[S] Highest educational attainment from the client-approved list.',
    course_major             VARCHAR(150)                                                                                                                    NULL COMMENT '[S] Course, major, specialization or tech-voc training, for example BS Information Technology.',
    sdg_id                   CHAR(36)                                                                                                                        NULL COMMENT '[S] The one Sustainable Development Goal the volunteer cares about most.',
    other_interests          VARCHAR(300)                                                                                                                    NULL COMMENT 'Optional interests the volunteer typed that are not in the list, separated by commas.',
    profile_status           ENUM('draft', 'submitted', 'under_review', 'needs_correction', 'approved', 'declined', 'suspended', 'deactivated', 'archived')  NOT NULL DEFAULT 'draft' COMMENT 'Where the volunteer is in verification: draft (still filling in), submitted, under_review, needs_correction, approved (verified volunteer), decline...',
    status_reason            VARCHAR(300)                                                                                                                    NULL COMMENT 'The message shown to the volunteer for the current status, for example Registration approved or Account suspended: please contact support.',
    approved_by              CHAR(36)                                                                                                                        NULL COMMENT 'The reviewer who approved the registration and made the person a verified volunteer.',
    approved_at              DATETIME                                                                                                                        NULL COMMENT 'Date and time the person became a verified volunteer.',
    approval_notice_seen_at  DATETIME                                                                                                                        NULL COMMENT 'When the volunteer saw the one-time approval congratulations on Home.',
    created_at               DATETIME                                                                                                                        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               DATETIME                                                                                                                        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (volunteer_id),
    UNIQUE KEY uq_volunteer_volunteer_code (volunteer_code),
    UNIQUE KEY uq_volunteer_user_id (user_id),
    CONSTRAINT fk_volunteer_user_id FOREIGN KEY (user_id) REFERENCES user_account (user_id),
    CONSTRAINT fk_volunteer_suffix_option_id FOREIGN KEY (suffix_option_id) REFERENCES reference_option (option_id),
    CONSTRAINT fk_volunteer_sex_option_id FOREIGN KEY (sex_option_id) REFERENCES reference_option (option_id),
    CONSTRAINT fk_volunteer_civil_status_option_id FOREIGN KEY (civil_status_option_id) REFERENCES reference_option (option_id),
    CONSTRAINT fk_volunteer_barangay_id FOREIGN KEY (barangay_id) REFERENCES barangay (barangay_id),
    CONSTRAINT fk_volunteer_sector_id FOREIGN KEY (sector_id) REFERENCES sector (sector_id),
    CONSTRAINT fk_volunteer_education_option_id FOREIGN KEY (education_option_id) REFERENCES reference_option (option_id),
    CONSTRAINT fk_volunteer_sdg_id FOREIGN KEY (sdg_id) REFERENCES sdg (sdg_id),
    CONSTRAINT fk_volunteer_approved_by FOREIGN KEY (approved_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The core volunteer profile.';

CREATE TABLE volunteer_restricted_safety (
    safety_id                 CHAR(36)      NOT NULL COMMENT 'Unique id of this record.',
    volunteer_id              CHAR(36)      NOT NULL COMMENT 'The volunteer this information belongs to.',
    medical_considerations    TEXT          NULL COMMENT '[S] Medical conditions or allergies that may affect volunteering, written by the volunteer, for example Asthma, carries an inhaler.',
    food_restriction_other    VARCHAR(200)  NULL COMMENT 'A food restriction that is not in the list, for example Allergic to mango.',
    emergency_contact_number  VARCHAR(20)   NULL COMMENT '[S] Phone number to call in an emergency, for example 09987654321.',
    updated_by                CHAR(36)      NULL COMMENT 'The last person who changed this record.',
    created_at                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (safety_id),
    UNIQUE KEY uq_volunteer_restricted_safety_volunteer_id (volunteer_id),
    CONSTRAINT fk_volunteer_restricted_safety_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_volunteer_restricted_safety_updated_by FOREIGN KEY (updated_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Sensitive safety information kept in its own table and shown in its own clearly labeled Restricted Safety section on the profile.';

CREATE TABLE volunteer_food_restriction (
    volunteer_id  CHAR(36)  NOT NULL COMMENT 'The volunteer.',
    option_id     CHAR(36)  NOT NULL COMMENT 'One restricted food from the approved list, for example Pork or Peanut.',
    created_at    DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (volunteer_id, option_id),
    CONSTRAINT fk_volunteer_food_restriction_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_volunteer_food_restriction_option_id FOREIGN KEY (option_id) REFERENCES reference_option (option_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The foods the volunteer cannot eat for diet, health or religious reasons.';

CREATE TABLE volunteer_skill (
    volunteer_id      CHAR(36)      NOT NULL COMMENT 'The volunteer.',
    skill_id          CHAR(36)      NOT NULL COMMENT 'A chosen skill from the approved list, for example Events Management.',
    priority          INT           NOT NULL COMMENT '1, 2 or 3, showing which skill the volunteer considers strongest.',
    other_skill_text  VARCHAR(100)  NULL COMMENT 'Used only when the volunteer chose Other and typed their own skill.',
    created_at        DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (volunteer_id, skill_id),
    CONSTRAINT fk_volunteer_skill_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_volunteer_skill_skill_id FOREIGN KEY (skill_id) REFERENCES skill (skill_id),
    CONSTRAINT chk_volunteer_skill_priority_range CHECK (priority BETWEEN 1 AND 3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The skills a volunteer says they can offer.';

CREATE TABLE volunteer_interest (
    volunteer_id  CHAR(36)                      NOT NULL COMMENT 'The volunteer.',
    interest_id   CHAR(36)                      NOT NULL COMMENT 'The chosen field, for example Education and Literacy.',
    `rank`        ENUM('primary', 'secondary')  NOT NULL COMMENT 'primary (what they are really good at or most interested in) or secondary (a field they are familiar with).',
    created_at    DATETIME                      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME                      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (volunteer_id, `rank`),
    CONSTRAINT fk_volunteer_interest_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_volunteer_interest_interest_id FOREIGN KEY (interest_id) REFERENCES interest_field (interest_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The cause areas the volunteer is most and second-most interested in.';

CREATE TABLE volunteer_availability (
    availability_id         CHAR(36)      NOT NULL COMMENT 'Unique id of this answer.',
    volunteer_id            CHAR(36)      NOT NULL COMMENT 'The volunteer.',
    availability_option_id  CHAR(36)      NULL COMMENT 'A choice from the client-approved availability list, if the client defines one.',
    hours_per_week          DECIMAL(5,1)  NULL COMMENT 'Number of hours per week the volunteer can give, for example 6.0.',
    days_per_week           INT           NULL COMMENT 'Number of days per week the volunteer can give, for example 2.',
    effective_from          DATE          NOT NULL COMMENT 'The date this availability applies from.',
    created_at              DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (availability_id),
    CONSTRAINT fk_volunteer_availability_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_volunteer_availability_availability_option_id FOREIGN KEY (availability_option_id) REFERENCES reference_option (option_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='How much time the volunteer can give each week.';

CREATE TABLE volunteer_preferred_day (
    volunteer_id  CHAR(36)  NOT NULL COMMENT 'The volunteer.',
    day_of_week   INT       NOT NULL COMMENT '1 for Monday up to 7 for Sunday.',
    created_at    DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (volunteer_id, day_of_week),
    CONSTRAINT fk_volunteer_preferred_day_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT chk_volunteer_preferred_day_day_range CHECK (day_of_week BETWEEN 1 AND 7)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The days of the week the volunteer prefers to volunteer.';

CREATE TABLE volunteer_experience (
    experience_id         CHAR(36)  NOT NULL COMMENT 'Unique id of this record.',
    volunteer_id          CHAR(36)  NOT NULL COMMENT 'The volunteer.',
    has_participated      BOOLEAN   NULL COMMENT '[S] True if the volunteer has joined a volunteer event before, such as a clean-up drive or blood drive.',
    has_organized         BOOLEAN   NULL COMMENT '[S] True if the volunteer has organized a volunteer program, project or activity.',
    willing_to_be_called  BOOLEAN   NULL COMMENT '[S] True if the volunteer agrees to be contacted for events, trainings or seminars as participant or organizer.',
    description           TEXT      NULL COMMENT 'Optional details of what they did, for example Led a tree planting in Barangay Carmen in 2024.',
    created_at            DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (experience_id),
    UNIQUE KEY uq_volunteer_experience_volunteer_id (volunteer_id),
    CONSTRAINT fk_volunteer_experience_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The volunteer''s own account of past volunteering.';

CREATE TABLE volunteer_program_interest (
    interest_id         CHAR(36)                                  NOT NULL COMMENT 'Unique id of this answer.',
    volunteer_id        CHAR(36)                                  NOT NULL COMMENT 'The volunteer.',
    program_type        ENUM('training', 'formation', 'chapter')  NOT NULL COMMENT 'training, formation or chapter.',
    response_option_id  CHAR(36)                                  NOT NULL COMMENT 'The answer chosen from the approved list, for example Yes, definitely or Undecided.',
    other_text          VARCHAR(200)                              NULL COMMENT 'The volunteer''s own words when they pick Other.',
    created_at          DATETIME                                  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME                                  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (interest_id),
    CONSTRAINT fk_volunteer_program_interest_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_volunteer_program_interest_response_option_id FOREIGN KEY (response_option_id) REFERENCES reference_option (option_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The volunteer''s interest in extra programs such as the training program, the formation program and chapter organizing.';

CREATE TABLE volunteer_referral (
    volunteer_id        CHAR(36)  NOT NULL COMMENT 'The volunteer.',
    referral_option_id  CHAR(36)  NOT NULL COMMENT 'One source such as Friend / Relative, Social Media or Radio.',
    created_at          DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (volunteer_id, referral_option_id),
    CONSTRAINT fk_volunteer_referral_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_volunteer_referral_referral_option_id FOREIGN KEY (referral_option_id) REFERENCES reference_option (option_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='How the volunteer found out about the system.';

CREATE TABLE volunteer_qualification (
    qualification_id     CHAR(36)                                            NOT NULL COMMENT 'Unique id of the qualification.',
    volunteer_id         CHAR(36)                                            NOT NULL COMMENT 'The volunteer who holds it.',
    qualification_type   VARCHAR(80)                                         NOT NULL COMMENT 'Kind of credential, for example Training, License or Certification.',
    title                VARCHAR(200)                                        NOT NULL COMMENT 'Name of the credential, for example Basic Life Support.',
    issuing_body         VARCHAR(150)                                        NULL COMMENT 'Who issued it, for example Philippine Red Cross.',
    date_earned          DATE                                                NULL COMMENT 'Date the credential was earned.',
    expiry_date          DATE                                                NULL COMMENT 'Date it expires, if it expires.',
    evidence_file_id     CHAR(36)                                            NULL COMMENT 'The uploaded proof, for example a scan of the certificate.',
    verification_status  ENUM('pending', 'verified', 'rejected', 'expired')  NOT NULL DEFAULT 'pending' COMMENT 'pending, verified, rejected or expired.',
    verified_by          CHAR(36)                                            NULL COMMENT 'The staff member who checked it.',
    verified_at          DATETIME                                            NULL COMMENT 'Date and time it was checked.',
    created_at           DATETIME                                            NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME                                            NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (qualification_id),
    CONSTRAINT fk_volunteer_qualification_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_volunteer_qualification_evidence_file_id FOREIGN KEY (evidence_file_id) REFERENCES file_attachment (file_id),
    CONSTRAINT fk_volunteer_qualification_verified_by FOREIGN KEY (verified_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Credentials that the office has checked, such as first aid training or a license.';

CREATE TABLE volunteer_registration (
    registration_id       CHAR(36)                                                                                NOT NULL COMMENT 'Unique id of this submission.',
    volunteer_id          CHAR(36)                                                                                NOT NULL COMMENT 'The volunteer who is registering.',
    registration_type     ENUM('new', 'update')                                                                   NOT NULL COMMENT 'new (first registration) or update (Update Past Entry).',
    route_id              CHAR(36)                                                                                NOT NULL COMMENT 'The route the person entered through.',
    current_step          ENUM('BASIC_PROFILE', 'SECTOR_EDUCATION', 'SKILLS_INTERESTS_SDG', 'TERMS_SUBMIT')       NULL COMMENT 'The last step the volunteer was on: BASIC_PROFILE, SECTOR_EDUCATION, SKILLS_INTERESTS_SDG or TERMS_SUBMIT.',
    draft_data            JSON                                                                                    NULL COMMENT 'Autosaved answers while the registration is still a draft.',
    last_saved_at         DATETIME                                                                                NULL COMMENT 'Date and time of the last autosave.',
    consent_id            CHAR(36)                                                                                NULL COMMENT 'The exact version of the Terms and Conditions the volunteer accepted.',
    consent_accepted_at   DATETIME                                                                                NULL COMMENT 'Date and time the volunteer pressed agree.',
    status                ENUM('draft', 'submitted', 'under_review', 'needs_correction', 'approved', 'declined')  NOT NULL DEFAULT 'draft' COMMENT 'draft, submitted, under_review, needs_correction, approved or declined.',
    submitted_at          DATETIME                                                                                NULL COMMENT 'Date and time of submission.',
    assigned_reviewer_id  CHAR(36)                                                                                NULL COMMENT 'The coordinator the registration was assigned to for review.',
    review_due_at         DATETIME                                                                                NULL COMMENT 'The date by which the registration should be reviewed.',
    decided_by            CHAR(36)                                                                                NULL COMMENT 'The reviewer who made the final approve, decline or return decision.',
    reviewed_at           DATETIME                                                                                NULL COMMENT 'Date and time of the decision.',
    decision_reason       TEXT                                                                                    NULL COMMENT 'The reviewer''s explanation shown to the volunteer, for example Approved or Please confirm your barangay.',
    correction_round      INT                                                                                     NOT NULL DEFAULT 0 COMMENT 'How many times the registration has been returned for correction.',
    created_at            DATETIME                                                                                NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME                                                                                NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (registration_id),
    CONSTRAINT fk_volunteer_registration_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_volunteer_registration_route_id FOREIGN KEY (route_id) REFERENCES registration_route (route_id),
    CONSTRAINT fk_volunteer_registration_consent_id FOREIGN KEY (consent_id) REFERENCES consent_document (consent_id),
    CONSTRAINT fk_volunteer_registration_assigned_reviewer_id FOREIGN KEY (assigned_reviewer_id) REFERENCES user_account (user_id),
    CONSTRAINT fk_volunteer_registration_decided_by FOREIGN KEY (decided_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='One row each time a volunteer submits a registration or an update.';

CREATE TABLE registration_step_progress (
    progress_id      CHAR(36)                                                                           NOT NULL COMMENT 'Unique id of this progress row.',
    registration_id  CHAR(36)                                                                           NOT NULL COMMENT 'The registration this progress belongs to.',
    step_code        ENUM('BASIC_PROFILE', 'SECTOR_EDUCATION', 'SKILLS_INTERESTS_SDG', 'TERMS_SUBMIT')  NOT NULL COMMENT 'BASIC_PROFILE, SECTOR_EDUCATION, SKILLS_INTERESTS_SDG or TERMS_SUBMIT.',
    status           ENUM('not_started', 'in_progress', 'completed', 'needs_fix')                       NOT NULL DEFAULT 'not_started' COMMENT 'not_started, in_progress, completed or needs_fix (the reviewer sent it back).',
    completed_at     DATETIME                                                                           NULL COMMENT 'Date and time the step was completed.',
    last_saved_at    DATETIME                                                                           NULL COMMENT 'Date and time the volunteer last saved something in this step.',
    created_at       DATETIME                                                                           NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME                                                                           NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (progress_id),
    UNIQUE KEY uq_registration_step_progress_registration_id_step_code (registration_id, step_code),
    CONSTRAINT fk_registration_step_progress_registration_id FOREIGN KEY (registration_id) REFERENCES volunteer_registration (registration_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Tracks which registration steps the volunteer has finished.';

CREATE TABLE registration_correction_item (
    item_id          CHAR(36)                                                                           NOT NULL COMMENT 'Unique id of the correction item.',
    registration_id  CHAR(36)                                                                           NOT NULL COMMENT 'The registration that was returned.',
    step_code        ENUM('BASIC_PROFILE', 'SECTOR_EDUCATION', 'SKILLS_INTERESTS_SDG', 'TERMS_SUBMIT')  NOT NULL COMMENT 'The step the item belongs to, so the app can jump straight to it.',
    field_name       VARCHAR(80)                                                                        NULL COMMENT 'The specific field to fix, for example contact_number.',
    reviewer_note    VARCHAR(300)                                                                       NOT NULL COMMENT 'What the reviewer wrote, for example Please confirm your barangay and contact number.',
    status           ENUM('open', 'fixed', 'waived')                                                    NOT NULL DEFAULT 'open' COMMENT 'open, fixed or waived (the reviewer decided it was not needed).',
    raised_by        CHAR(36)                                                                           NOT NULL COMMENT 'The reviewer who raised it.',
    raised_at        DATETIME                                                                           NOT NULL COMMENT 'Date and time it was raised.',
    fixed_at         DATETIME                                                                           NULL COMMENT 'Date and time the volunteer fixed it.',
    created_at       DATETIME                                                                           NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME                                                                           NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (item_id),
    CONSTRAINT fk_registration_correction_item_registration_id FOREIGN KEY (registration_id) REFERENCES volunteer_registration (registration_id),
    CONSTRAINT fk_registration_correction_item_raised_by FOREIGN KEY (raised_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Individual items the reviewer asked the volunteer to fix when returning a registration.';

CREATE TABLE profile_update_request (
    update_id        CHAR(36)                                            NOT NULL COMMENT 'Unique id of the request.',
    volunteer_id     CHAR(36)                                            NOT NULL COMMENT 'The volunteer asking for the change.',
    field_name       VARCHAR(80)                                         NOT NULL COMMENT 'The field to change, for example date_of_birth or barangay_id.',
    old_value        TEXT                                                NULL COMMENT 'The value before the change.',
    new_value        TEXT                                                NOT NULL COMMENT 'The value the volunteer wants.',
    is_protected     BOOLEAN                                             NOT NULL DEFAULT FALSE COMMENT 'True if the field is protected and needs reviewer approval.',
    status           ENUM('pending', 'approved', 'rejected', 'applied')  NOT NULL DEFAULT 'pending' COMMENT 'pending, approved, rejected or applied.',
    reviewer_id      CHAR(36)                                            NULL COMMENT 'The reviewer who decided.',
    decided_at       DATETIME                                            NULL COMMENT 'Date and time of the decision.',
    decision_reason  VARCHAR(300)                                        NULL COMMENT 'The reviewer''s reason.',
    created_at       DATETIME                                            NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME                                            NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (update_id),
    CONSTRAINT fk_profile_update_request_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_profile_update_request_reviewer_id FOREIGN KEY (reviewer_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A change a verified volunteer wants to make to an important profile field.';

CREATE TABLE duplicate_review (
    duplicate_id            CHAR(36)                             NOT NULL COMMENT 'Unique id of the case.',
    primary_volunteer_id    CHAR(36)                             NOT NULL COMMENT 'The profile that will be kept.',
    candidate_volunteer_id  CHAR(36)                             NOT NULL COMMENT 'The profile that may be a duplicate.',
    match_basis             VARCHAR(200)                         NOT NULL COMMENT 'Why the system thinks they match, for example Same name, birth date and contact number.',
    status                  ENUM('open', 'merged', 'dismissed')  NOT NULL DEFAULT 'open' COMMENT 'open, merged (combined into one) or dismissed (confirmed to be different people).',
    reviewed_by             CHAR(36)                             NULL COMMENT 'The coordinator who reviewed the case.',
    resolution_note         VARCHAR(300)                         NULL COMMENT 'What was decided and why.',
    created_at              DATETIME                             NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME                             NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (duplicate_id),
    CONSTRAINT fk_duplicate_review_primary_volunteer_id FOREIGN KEY (primary_volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_duplicate_review_candidate_volunteer_id FOREIGN KEY (candidate_volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_duplicate_review_reviewed_by FOREIGN KEY (reviewed_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Cases where two profiles may belong to the same person.';

CREATE TABLE volunteer_status_history (
    history_id    CHAR(36)      NOT NULL COMMENT 'Unique id of this entry.',
    volunteer_id  CHAR(36)      NOT NULL COMMENT 'The volunteer.',
    old_status    VARCHAR(30)   NULL COMMENT 'The status before the change.',
    new_status    VARCHAR(30)   NOT NULL COMMENT 'The status after the change.',
    reason        VARCHAR(300)  NULL COMMENT 'Why it changed.',
    changed_by    CHAR(36)      NOT NULL COMMENT 'Who made the change.',
    changed_at    DATETIME      NOT NULL COMMENT 'Date and time of the change.',
    created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (history_id),
    CONSTRAINT fk_volunteer_status_history_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_volunteer_status_history_changed_by FOREIGN KEY (changed_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A log of every change to a volunteer''s profile status, such as submitted, approved or suspended.';

CREATE TABLE volunteer_affiliation (
    affiliation_id    CHAR(36)                          NOT NULL COMMENT 'Unique id of the link.',
    volunteer_id      CHAR(36)                          NOT NULL COMMENT 'The volunteer.',
    affiliation_type  ENUM('barangay', 'organization')  NOT NULL COMMENT 'barangay or organization.',
    barangay_id       CHAR(36)                          NULL COMMENT 'The barangay, when the type is barangay.',
    org_id            CHAR(36)                          NULL COMMENT 'The organization, when the type is organization.',
    opted_in_at       DATETIME                          NOT NULL COMMENT 'Date and time the volunteer agreed to the link.',
    removed_at        DATETIME                          NULL COMMENT 'Date and time the volunteer left.',
    created_at        DATETIME                          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME                          NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (affiliation_id),
    CONSTRAINT fk_volunteer_affiliation_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_volunteer_affiliation_barangay_id FOREIGN KEY (barangay_id) REFERENCES barangay (barangay_id),
    CONSTRAINT fk_volunteer_affiliation_org_id FOREIGN KEY (org_id) REFERENCES partner_organization (org_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A volunteer''s own choice to be linked to a barangay or organization, so that group can see and invite them.';


-- ---------------------------------------------------------------------
--  GROUP 5. ACTIVITY REQUESTS AND ACTIVITIES
-- ---------------------------------------------------------------------

CREATE TABLE activity_request (
    request_id          CHAR(36)                                                                                     NOT NULL COMMENT 'Unique id of the request.',
    request_code        VARCHAR(20)                                                                                  NOT NULL COMMENT 'Short readable number shown in lists, for example REQ-2026-0045.',
    requester_type      ENUM('barangay', 'organization', 'internal')                                                 NOT NULL COMMENT 'Who is asking: barangay, organization, or internal (created by program staff).',
    requested_by        CHAR(36)                                                                                     NOT NULL COMMENT 'The user who submitted the request.',
    barangay_id         CHAR(36)                                                                                     NULL COMMENT 'The requesting barangay, when the requester is a barangay.',
    org_id              CHAR(36)                                                                                     NULL COMMENT 'The proposing organization, when the requester is an organization.',
    current_version_no  INT                                                                                          NOT NULL DEFAULT 1 COMMENT 'The number of the latest version, for example 2 after one revision.',
    status              ENUM('draft', 'submitted', 'under_review', 'returned', 'approved', 'rejected', 'withdrawn')  NOT NULL DEFAULT 'draft' COMMENT 'draft, submitted, under_review, returned (sent back for changes), approved, rejected or withdrawn.',
    submitted_at        DATETIME                                                                                     NULL COMMENT 'Date and time it was first submitted.',
    reviewer_id         CHAR(36)                                                                                     NULL COMMENT 'The coordinator assigned to review it.',
    activity_id         CHAR(36)                                                                                     NULL COMMENT 'The activity created once the request is approved.',
    created_at          DATETIME                                                                                     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME                                                                                     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (request_id),
    UNIQUE KEY uq_activity_request_request_code (request_code),
    CONSTRAINT fk_activity_request_requested_by FOREIGN KEY (requested_by) REFERENCES user_account (user_id),
    CONSTRAINT fk_activity_request_barangay_id FOREIGN KEY (barangay_id) REFERENCES barangay (barangay_id),
    CONSTRAINT fk_activity_request_org_id FOREIGN KEY (org_id) REFERENCES partner_organization (org_id),
    CONSTRAINT fk_activity_request_reviewer_id FOREIGN KEY (reviewer_id) REFERENCES user_account (user_id),
    CONSTRAINT fk_activity_request_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A request from a barangay or a proposal from an organization asking the program to hold an activity.';

CREATE TABLE activity_request_version (
    version_id        CHAR(36)      NOT NULL COMMENT 'Unique id of the version.',
    request_id        CHAR(36)      NOT NULL COMMENT 'The request this version belongs to.',
    version_no        INT           NOT NULL DEFAULT 1 COMMENT 'Version number starting at 1.',
    title             VARCHAR(200)  NOT NULL COMMENT 'Proposed activity title, for example Coastal Clean-up Drive.',
    activity_type     VARCHAR(80)   NOT NULL COMMENT 'Kind of activity, for example Clean-up, Training or Feeding program.',
    community_need    TEXT          NOT NULL COMMENT 'The problem or need in the community that the activity answers.',
    objective         TEXT          NOT NULL COMMENT 'What the activity wants to achieve, written as a goal.',
    target_community  VARCHAR(200)  NULL COMMENT 'Who benefits, for example Residents of Purok 3.',
    proposed_start    DATETIME      NOT NULL COMMENT 'Proposed start date and time.',
    proposed_end      DATETIME      NOT NULL COMMENT 'Proposed end date and time.',
    venue_text        VARCHAR(250)  NOT NULL COMMENT 'The proposed place written as text, for example Carmen Riverside.',
    volunteer_count   INT           NOT NULL DEFAULT 0 COMMENT 'How many volunteers are needed.',
    materials_text    TEXT          NULL COMMENT 'Materials, equipment or supplies needed, for example Trash bags, gloves, 20 shovels.',
    created_at        DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (version_id),
    UNIQUE KEY uq_activity_request_version_request_id_version_no (request_id, version_no),
    CONSTRAINT fk_activity_request_version_request_id FOREIGN KEY (request_id) REFERENCES activity_request (request_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Each saved version of a request.';

CREATE TABLE activity_request_skill (
    version_id  CHAR(36)  NOT NULL COMMENT 'The request version.',
    skill_id    CHAR(36)  NOT NULL COMMENT 'A skill needed from the approved list.',
    created_at  DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (version_id, skill_id),
    CONSTRAINT fk_activity_request_skill_version_id FOREIGN KEY (version_id) REFERENCES activity_request_version (version_id),
    CONSTRAINT fk_activity_request_skill_skill_id FOREIGN KEY (skill_id) REFERENCES skill (skill_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The skills a request asks volunteers to have.';

CREATE TABLE request_decision (
    decision_id            CHAR(36)                             NOT NULL COMMENT 'Unique id of the decision.',
    request_id             CHAR(36)                             NOT NULL COMMENT 'The request that was decided.',
    version_id             CHAR(36)                             NOT NULL COMMENT 'The version the decision was about.',
    decision               ENUM('approve', 'reject', 'return')  NOT NULL COMMENT 'approve, reject or return (ask for revision).',
    reason                 TEXT                                 NOT NULL COMMENT 'The reviewer''s explanation, for example Venue not confirmed.',
    requirements_returned  TEXT                                 NULL COMMENT 'What the requester must change before resubmitting.',
    decided_by             CHAR(36)                             NOT NULL COMMENT 'The reviewer.',
    decided_at             DATETIME                             NOT NULL COMMENT 'Date and time of the decision.',
    created_at             DATETIME                             NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME                             NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (decision_id),
    CONSTRAINT fk_request_decision_request_id FOREIGN KEY (request_id) REFERENCES activity_request (request_id),
    CONSTRAINT fk_request_decision_version_id FOREIGN KEY (version_id) REFERENCES activity_request_version (version_id),
    CONSTRAINT fk_request_decision_decided_by FOREIGN KEY (decided_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Every decision made on a request, kept forever so it is clear who decided what and why.';

CREATE TABLE activity (
    activity_id                CHAR(36)                                                                                              NOT NULL COMMENT 'Unique id of the activity.',
    activity_code              VARCHAR(20)                                                                                           NOT NULL COMMENT 'Short readable number, for example ACT-2026-0012.',
    request_id                 CHAR(36)                                                                                              NULL COMMENT 'The request it came from, if any.',
    title                      VARCHAR(200)                                                                                          NOT NULL COMMENT 'Public title shown on cards, for example Cagayan River cleanup drive.',
    activity_type              VARCHAR(80)                                                                                           NOT NULL COMMENT 'Kind of activity.',
    purpose                    TEXT                                                                                                  NOT NULL COMMENT 'The approved purpose of the activity.',
    public_summary             TEXT                                                                                                  NOT NULL COMMENT 'Short public description shown to every logged-in user, including unverified volunteers.',
    participant_instructions   TEXT                                                                                                  NULL COMMENT 'Detailed instructions such as what to bring and where to meet.',
    organizer_type             ENUM('program', 'barangay', 'organization')                                                           NOT NULL COMMENT 'Who organizes it: program, barangay or organization.',
    barangay_id                CHAR(36)                                                                                              NULL COMMENT 'The organizing barangay.',
    org_id                     CHAR(36)                                                                                              NULL COMMENT 'The organizing organization.',
    venue_id                   CHAR(36)                                                                                              NULL COMMENT 'The main venue.',
    start_date                 DATE                                                                                                  NOT NULL COMMENT 'First day of the activity.',
    end_date                   DATE                                                                                                  NOT NULL COMMENT 'Last day of the activity.',
    capacity                   INT                                                                                                   NOT NULL COMMENT 'Maximum number of participants.',
    registration_open_at       DATETIME                                                                                              NULL COMMENT 'When volunteers can start applying.',
    registration_close_at      DATETIME                                                                                              NULL COMMENT 'When applications close.',
    auto_accept                BOOLEAN                                                                                               NOT NULL DEFAULT FALSE COMMENT 'If true, applications are accepted automatically when the volunteer has the required skills and the activity is under capacity, and waitlisted auto...',
    min_hours_for_certificate  DECIMAL(5,1)                                                                                          NULL COMMENT 'Verified hours a volunteer needs to qualify for a certificate, for example 4.0.',
    status                     ENUM('draft', 'approved', 'published', 'ongoing', 'completed', 'closed', 'cancelled', 'unpublished')  NOT NULL DEFAULT 'draft' COMMENT 'draft, approved, published (visible), ongoing, completed, closed, cancelled or unpublished.',
    published_by               CHAR(36)                                                                                              NULL COMMENT 'Who published it.',
    published_at               DATETIME                                                                                              NULL COMMENT 'Date and time it became visible.',
    cancel_reason              VARCHAR(300)                                                                                          NULL COMMENT 'Reason, if it was cancelled.',
    closed_by                  CHAR(36)                                                                                              NULL COMMENT 'Who closed it after completion.',
    closed_at                  DATETIME                                                                                              NULL COMMENT 'Date and time it was closed.',
    created_at                 DATETIME                                                                                              NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                 DATETIME                                                                                              NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (activity_id),
    UNIQUE KEY uq_activity_activity_code (activity_code),
    CONSTRAINT fk_activity_request_id FOREIGN KEY (request_id) REFERENCES activity_request (request_id),
    CONSTRAINT fk_activity_barangay_id FOREIGN KEY (barangay_id) REFERENCES barangay (barangay_id),
    CONSTRAINT fk_activity_org_id FOREIGN KEY (org_id) REFERENCES partner_organization (org_id),
    CONSTRAINT fk_activity_venue_id FOREIGN KEY (venue_id) REFERENCES venue (venue_id),
    CONSTRAINT fk_activity_published_by FOREIGN KEY (published_by) REFERENCES user_account (user_id),
    CONSTRAINT fk_activity_closed_by FOREIGN KEY (closed_by) REFERENCES user_account (user_id),
    CONSTRAINT chk_activity_dates_order CHECK (end_date >= start_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The official activity record.';

CREATE TABLE activity_change_request (
    change_id                 CHAR(36)                                                    NOT NULL COMMENT 'Unique id of the change request.',
    activity_id               CHAR(36)                                                    NOT NULL COMMENT 'The activity to change.',
    change_type               ENUM('reschedule', 'venue', 'scope', 'capacity', 'cancel')  NOT NULL COMMENT 'reschedule, venue, scope, capacity or cancel.',
    old_value                 JSON                                                        NOT NULL COMMENT 'The current value, for example the old date.',
    new_value                 JSON                                                        NOT NULL COMMENT 'The requested value, for example the new date.',
    reason                    TEXT                                                        NOT NULL COMMENT 'Why the change is needed.',
    requested_by              CHAR(36)                                                    NOT NULL COMMENT 'Who asked.',
    status                    ENUM('pending', 'approved', 'rejected', 'applied')          NOT NULL DEFAULT 'pending' COMMENT 'pending, approved, rejected or applied.',
    reviewer_id               CHAR(36)                                                    NULL COMMENT 'The reviewer.',
    participants_notified_at  DATETIME                                                    NULL COMMENT 'When participants were told about the change.',
    created_at                DATETIME                                                    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                DATETIME                                                    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (change_id),
    CONSTRAINT fk_activity_change_request_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_activity_change_request_requested_by FOREIGN KEY (requested_by) REFERENCES user_account (user_id),
    CONSTRAINT fk_activity_change_request_reviewer_id FOREIGN KEY (reviewer_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A request to change an approved activity, such as a new date or venue.';

CREATE TABLE activity_session (
    session_id         CHAR(36)                                          NOT NULL COMMENT 'Unique id of the session.',
    activity_id        CHAR(36)                                          NOT NULL COMMENT 'The activity it belongs to.',
    session_name       VARCHAR(120)                                      NOT NULL COMMENT 'Name shown to volunteers, for example Day 1 - Morning.',
    session_date       DATE                                              NOT NULL COMMENT 'The date of the session.',
    start_time         TIME                                              NOT NULL COMMENT 'Start time, for example 07:00.',
    end_time           TIME                                              NOT NULL COMMENT 'End time, for example 11:00.',
    checkin_opens_at   TIME                                              NULL COMMENT 'Time check-in begins, for example 06:30.',
    checkin_closes_at  TIME                                              NULL COMMENT 'Time check-in ends.',
    venue_id           CHAR(36)                                          NULL COMMENT 'The venue for this session if different from the main venue.',
    meeting_point      VARCHAR(200)                                      NULL COMMENT 'Exact meeting place, for example Gate 2 of the barangay hall.',
    capacity           INT                                               NULL COMMENT 'Maximum people in this session.',
    instructions       TEXT                                              NULL COMMENT 'Session-specific instructions.',
    status             ENUM('scheduled', 'open', 'closed', 'cancelled')  NOT NULL DEFAULT 'scheduled' COMMENT 'scheduled, open, closed or cancelled.',
    created_at         DATETIME                                          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME                                          NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (session_id),
    CONSTRAINT fk_activity_session_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_activity_session_venue_id FOREIGN KEY (venue_id) REFERENCES venue (venue_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='One dated session inside an activity, for example Day 1 morning.';

CREATE TABLE venue (
    venue_id        CHAR(36)      NOT NULL COMMENT 'Unique id of the venue.',
    name            VARCHAR(150)  NOT NULL COMMENT 'Venue name, for example Carmen Barangay Hall.',
    address         VARCHAR(250)  NULL COMMENT 'Street address.',
    barangay_id     CHAR(36)      NULL COMMENT 'The barangay it is in.',
    contact_person  VARCHAR(100)  NULL COMMENT 'Person to contact about the venue.',
    contact_number  VARCHAR(20)   NULL COMMENT 'Their phone number.',
    capacity        INT           NULL COMMENT 'How many people it can hold.',
    is_active       BOOLEAN       NOT NULL DEFAULT TRUE COMMENT 'False if no longer used.',
    created_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (venue_id),
    CONSTRAINT fk_venue_barangay_id FOREIGN KEY (barangay_id) REFERENCES barangay (barangay_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Places where activities happen.';

CREATE TABLE activity_required_skill (
    activity_id        CHAR(36)  NOT NULL COMMENT 'The activity.',
    skill_id           CHAR(36)  NOT NULL COMMENT 'A required skill.',
    volunteers_needed  INT       NULL COMMENT 'How many volunteers with this skill are needed.',
    created_at         DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (activity_id, skill_id),
    CONSTRAINT fk_activity_required_skill_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_activity_required_skill_skill_id FOREIGN KEY (skill_id) REFERENCES skill (skill_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The skills an activity needs.';

CREATE TABLE activity_sdg (
    activity_id  CHAR(36)  NOT NULL COMMENT 'The activity.',
    sdg_id       CHAR(36)  NOT NULL COMMENT 'A goal the activity supports.',
    is_primary   BOOLEAN   NOT NULL DEFAULT FALSE COMMENT 'True for the main goal of the activity.',
    created_at   DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (activity_id, sdg_id),
    CONSTRAINT fk_activity_sdg_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_activity_sdg_sdg_id FOREIGN KEY (sdg_id) REFERENCES sdg (sdg_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The Sustainable Development Goals an activity supports, used for reports.';

CREATE TABLE activity_coordinator (
    assignment_id  CHAR(36)  NOT NULL COMMENT 'Unique id of the assignment.',
    activity_id    CHAR(36)  NOT NULL COMMENT 'The activity.',
    user_id        CHAR(36)  NOT NULL COMMENT 'The coordinator.',
    assigned_by    CHAR(36)  NOT NULL COMMENT 'The program coordinator who assigned them.',
    assigned_at    DATETIME  NOT NULL COMMENT 'Date and time assigned.',
    ended_at       DATETIME  NULL COMMENT 'Date and time they stopped.',
    created_at     DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (assignment_id),
    CONSTRAINT fk_activity_coordinator_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_activity_coordinator_user_id FOREIGN KEY (user_id) REFERENCES user_account (user_id),
    CONSTRAINT fk_activity_coordinator_assigned_by FOREIGN KEY (assigned_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The event coordinators who are in charge of an activity.';

CREATE TABLE activity_note (
    note_id      CHAR(36)                                 NOT NULL COMMENT 'Unique id of the note.',
    activity_id  CHAR(36)                                 NOT NULL COMMENT 'The activity.',
    author_id    CHAR(36)                                 NOT NULL COMMENT 'Who wrote it.',
    note_type    ENUM('coordination', 'issue', 'change')  NOT NULL COMMENT 'coordination, issue or change.',
    body         TEXT                                     NOT NULL COMMENT 'The note text.',
    created_at   DATETIME                                 NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME                                 NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (note_id),
    CONSTRAINT fk_activity_note_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_activity_note_author_id FOREIGN KEY (author_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Notes on an activity from coordinators, barangays and organizations, such as coordination notes or issues.';

CREATE TABLE activity_task (
    task_id           CHAR(36)                                             NOT NULL COMMENT 'Unique id of the task.',
    activity_id       CHAR(36)                                             NOT NULL COMMENT 'The activity.',
    title             VARCHAR(200)                                         NOT NULL COMMENT 'Short task name, for example Confirm venue with barangay.',
    description       TEXT                                                 NULL COMMENT 'More detail.',
    assigned_user_id  CHAR(36)                                             NULL COMMENT 'The person responsible.',
    assigned_org_id   CHAR(36)                                             NULL COMMENT 'The organization responsible.',
    due_date          DATE                                                 NULL COMMENT 'Date it is due.',
    status            ENUM('open', 'acknowledged', 'in_progress', 'done')  NOT NULL DEFAULT 'open' COMMENT 'open, acknowledged, in_progress or done.',
    acknowledged_at   DATETIME                                             NULL COMMENT 'When the assignee confirmed they will do it.',
    created_at        DATETIME                                             NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME                                             NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (task_id),
    CONSTRAINT fk_activity_task_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_activity_task_assigned_user_id FOREIGN KEY (assigned_user_id) REFERENCES user_account (user_id),
    CONSTRAINT fk_activity_task_assigned_org_id FOREIGN KEY (assigned_org_id) REFERENCES partner_organization (org_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Preparation and coordination tasks, such as booking the venue or confirming snacks.';

CREATE TABLE activity_resource (
    resource_id    CHAR(36)                                                 NOT NULL COMMENT 'Unique id of the resource.',
    activity_id    CHAR(36)                                                 NOT NULL COMMENT 'The activity.',
    resource_type  ENUM('material', 'transport', 'venue_need', 'staffing')  NOT NULL COMMENT 'material, transport, venue_need or staffing.',
    name           VARCHAR(150)                                             NOT NULL COMMENT 'What is needed, for example Water jugs or Attendance Staff.',
    quantity       INT                                                      NULL COMMENT 'How many are needed.',
    unit           VARCHAR(30)                                              NULL COMMENT 'Unit of measure, for example pcs or vehicles.',
    provided_by    VARCHAR(150)                                             NULL COMMENT 'Who will provide it.',
    status         ENUM('needed', 'arranged', 'delivered')                  NOT NULL DEFAULT 'needed' COMMENT 'needed, arranged or delivered.',
    created_at     DATETIME                                                 NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME                                                 NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (resource_id),
    CONSTRAINT fk_activity_resource_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Materials, transport, venue needs and staff roles an activity needs.';


-- ---------------------------------------------------------------------
--  GROUP 6. PARTICIPATION AND MATCHING
-- ---------------------------------------------------------------------

CREATE TABLE activity_application (
    application_id          CHAR(36)                                                            NOT NULL COMMENT 'Unique id of the application.',
    activity_id             CHAR(36)                                                            NOT NULL COMMENT 'The activity applied for.',
    volunteer_id            CHAR(36)                                                            NOT NULL COMMENT 'The applicant.',
    source                  ENUM('self', 'invitation', 'manual')                                NOT NULL COMMENT 'How it started: self (volunteer applied), invitation (they accepted an invite) or manual (staff added them).',
    status                  ENUM('applied', 'waitlisted', 'accepted', 'declined', 'withdrawn')  NOT NULL DEFAULT 'applied' COMMENT 'applied, waitlisted, accepted, declined or withdrawn.',
    waitlist_position       INT                                                                 NULL COMMENT 'Place in line when waitlisted, for example 3.',
    applied_at              DATETIME                                                            NOT NULL COMMENT 'Date and time they applied.',
    decided_by              CHAR(36)                                                            NULL COMMENT 'The staff member who accepted, waitlisted or declined.',
    decided_at              DATETIME                                                            NULL COMMENT 'Date and time of the decision.',
    decision_reason         VARCHAR(300)                                                        NULL COMMENT 'Reason given, mostly for declines.',
    decided_automatically   BOOLEAN                                                             NOT NULL DEFAULT FALSE COMMENT 'True when the system accepted or waitlisted the application under the activity auto_accept rule, false when a person decided.',
    over_capacity_override  BOOLEAN                                                             NOT NULL DEFAULT FALSE COMMENT 'True when the Program Coordinator accepted the volunteer even though the activity was already at capacity.',
    created_at              DATETIME                                                            NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME                                                            NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (application_id),
    UNIQUE KEY uq_activity_application_activity_id_volunteer_id (activity_id, volunteer_id),
    CONSTRAINT fk_activity_application_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_activity_application_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_activity_application_decided_by FOREIGN KEY (decided_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A verified volunteer''s application to join an activity.';

CREATE TABLE invitation (
    invitation_id  CHAR(36)                                            NOT NULL COMMENT 'Unique id of the invitation.',
    activity_id    CHAR(36)                                            NOT NULL COMMENT 'The activity.',
    volunteer_id   CHAR(36)                                            NOT NULL COMMENT 'The invited volunteer.',
    invited_by     CHAR(36)                                            NOT NULL COMMENT 'The staff member who sent it.',
    suggestion_id  CHAR(36)                                            NULL COMMENT 'The match suggestion that led to it, if any.',
    sent_at        DATETIME                                            NOT NULL COMMENT 'Date and time it was sent.',
    expires_at     DATETIME                                            NULL COMMENT 'Reply deadline.',
    response       ENUM('pending', 'accepted', 'declined', 'expired')  NOT NULL COMMENT 'pending, accepted, declined or expired.',
    responded_at   DATETIME                                            NULL COMMENT 'Date and time the volunteer replied.',
    created_at     DATETIME                                            NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME                                            NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (invitation_id),
    CONSTRAINT fk_invitation_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_invitation_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_invitation_invited_by FOREIGN KEY (invited_by) REFERENCES user_account (user_id),
    CONSTRAINT fk_invitation_suggestion_id FOREIGN KEY (suggestion_id) REFERENCES match_suggestion (suggestion_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='An invitation sent to a volunteer to join an activity.';

CREATE TABLE match_suggestion (
    suggestion_id        CHAR(36)                                 NOT NULL COMMENT 'Unique id of the suggestion.',
    activity_id          CHAR(36)                                 NOT NULL COMMENT 'The activity.',
    volunteer_id         CHAR(36)                                 NOT NULL COMMENT 'The suggested volunteer.',
    skill_match_count    INT                                      NOT NULL DEFAULT 0 COMMENT 'How many of the activity''s required skills the volunteer has.',
    interest_match       BOOLEAN                                  NOT NULL DEFAULT FALSE COMMENT 'True if the volunteer''s interests fit the activity.',
    availability_match   BOOLEAN                                  NOT NULL DEFAULT FALSE COMMENT 'True if they are available on the activity dates.',
    location_match       BOOLEAN                                  NOT NULL DEFAULT FALSE COMMENT 'True if they live near the venue.',
    qualification_match  BOOLEAN                                  NOT NULL DEFAULT FALSE COMMENT 'True if they have a verified qualification the activity needs.',
    conflict_note        VARCHAR(250)                             NULL COMMENT 'A warning such as Already assigned to another activity that day.',
    explanation          TEXT                                     NOT NULL COMMENT 'Reason shown to the reviewer, for example Has Logistics and Events Management skills and is available on Saturdays.',
    reviewer_id          CHAR(36)                                 NULL COMMENT 'The staff member who reviewed it.',
    reviewer_decision    ENUM('invite', 'skip', 'manual_select')  NULL COMMENT 'invite, skip or manual_select.',
    created_at           DATETIME                                 NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME                                 NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (suggestion_id),
    CONSTRAINT fk_match_suggestion_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_match_suggestion_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_match_suggestion_reviewer_id FOREIGN KEY (reviewer_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A suggested volunteer for an activity, with a plain-language reason.';

CREATE TABLE activity_participant (
    participant_id     CHAR(36)                                               NOT NULL COMMENT 'Unique id of the roster entry.',
    activity_id        CHAR(36)                                               NOT NULL COMMENT 'The activity.',
    session_id         CHAR(36)                                               NULL COMMENT 'The session.',
    volunteer_id       CHAR(36)                                               NOT NULL COMMENT 'The participant.',
    application_id     CHAR(36)                                               NOT NULL COMMENT 'The accepted application it came from.',
    team_id            CHAR(36)                                               NULL COMMENT 'The team they are placed in.',
    assignment_status  ENUM('assigned', 'reassigned', 'replaced', 'removed')  NOT NULL DEFAULT 'assigned' COMMENT 'assigned, reassigned, replaced or removed.',
    assigned_by        CHAR(36)                                               NOT NULL COMMENT 'Who placed them.',
    assigned_at        DATETIME                                               NOT NULL COMMENT 'Date and time placed.',
    acknowledged_at    DATETIME                                               NULL COMMENT 'When the volunteer confirmed they saw their schedule.',
    created_at         DATETIME                                               NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME                                               NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (participant_id),
    CONSTRAINT fk_activity_participant_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_activity_participant_session_id FOREIGN KEY (session_id) REFERENCES activity_session (session_id),
    CONSTRAINT fk_activity_participant_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_activity_participant_application_id FOREIGN KEY (application_id) REFERENCES activity_application (application_id),
    CONSTRAINT fk_activity_participant_team_id FOREIGN KEY (team_id) REFERENCES team (team_id),
    CONSTRAINT fk_activity_participant_assigned_by FOREIGN KEY (assigned_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The roster of accepted volunteers for an activity, with their session and team.';

CREATE TABLE volunteer_suggestion (
    suggestion_id     CHAR(36)                                        NOT NULL COMMENT 'Unique id of the suggestion.',
    suggested_by      CHAR(36)                                        NOT NULL COMMENT 'The barangay or organization user who made it.',
    suggestion_type   ENUM('refer_to_intake', 'suggest_volunteer')    NOT NULL COMMENT 'refer_to_intake (send a resident to register) or suggest_volunteer.',
    barangay_id       CHAR(36)                                        NULL COMMENT 'The barangay it came from.',
    org_id            CHAR(36)                                        NULL COMMENT 'The organization it came from.',
    activity_id       CHAR(36)                                        NULL COMMENT 'The activity the volunteer is suggested for.',
    volunteer_id      CHAR(36)                                        NULL COMMENT 'The existing volunteer being suggested.',
    referral_contact  VARCHAR(150)                                    NULL COMMENT 'Contact detail of a resident being referred, for example a phone number.',
    status            ENUM('sent', 'accepted', 'declined', 'closed')  NOT NULL DEFAULT 'sent' COMMENT 'sent, accepted, declined or closed.',
    created_at        DATETIME                                        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME                                        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (suggestion_id),
    CONSTRAINT fk_volunteer_suggestion_suggested_by FOREIGN KEY (suggested_by) REFERENCES user_account (user_id),
    CONSTRAINT fk_volunteer_suggestion_barangay_id FOREIGN KEY (barangay_id) REFERENCES barangay (barangay_id),
    CONSTRAINT fk_volunteer_suggestion_org_id FOREIGN KEY (org_id) REFERENCES partner_organization (org_id),
    CONSTRAINT fk_volunteer_suggestion_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_volunteer_suggestion_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Suggestions and referrals from barangays and organizations, such as recommending a resident to register or suggesting an existing volunteer.';


-- ---------------------------------------------------------------------
--  GROUP 7. TEAMS AND DUTY APPOINTMENTS
-- ---------------------------------------------------------------------

CREATE TABLE team (
    team_id      CHAR(36)      NOT NULL COMMENT 'Unique id of the team.',
    activity_id  CHAR(36)      NOT NULL COMMENT 'The activity.',
    session_id   CHAR(36)      NULL COMMENT 'The session, if the team is for one session only.',
    name         VARCHAR(100)  NOT NULL COMMENT 'Team name, for example Registration Team.',
    purpose      VARCHAR(250)  NULL COMMENT 'What the team does.',
    max_size     INT           NULL COMMENT 'Maximum number of members.',
    created_by   CHAR(36)      NOT NULL COMMENT 'Who created the team.',
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (team_id),
    CONSTRAINT fk_team_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_team_session_id FOREIGN KEY (session_id) REFERENCES activity_session (session_id),
    CONSTRAINT fk_team_created_by FOREIGN KEY (created_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A group of volunteers working together in an activity or session.';

CREATE TABLE team_member (
    team_member_id  CHAR(36)     NOT NULL COMMENT 'Unique id of the membership.',
    team_id         CHAR(36)     NOT NULL COMMENT 'The team.',
    participant_id  CHAR(36)     NOT NULL COMMENT 'The rostered volunteer.',
    team_role       VARCHAR(80)  NULL COMMENT 'Job inside the team, for example Registration desk.',
    joined_at       DATETIME     NOT NULL COMMENT 'Date and time they joined.',
    left_at         DATETIME     NULL COMMENT 'Date and time they left.',
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (team_member_id),
    CONSTRAINT fk_team_member_team_id FOREIGN KEY (team_id) REFERENCES team (team_id),
    CONSTRAINT fk_team_member_participant_id FOREIGN KEY (participant_id) REFERENCES activity_participant (participant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A volunteer''s membership in a team.';

CREATE TABLE team_task (
    task_id                  CHAR(36)                                        NOT NULL COMMENT 'Unique id of the task.',
    team_id                  CHAR(36)                                        NOT NULL COMMENT 'The team.',
    title                    VARCHAR(200)                                    NOT NULL COMMENT 'Task name, for example Set up the registration table.',
    assignee_participant_id  CHAR(36)                                        NULL COMMENT 'The team member responsible.',
    location                 VARCHAR(200)                                    NULL COMMENT 'Where the task is done.',
    expected_result          VARCHAR(300)                                    NULL COMMENT 'What a finished task looks like.',
    progress_pct             INT                                             NOT NULL DEFAULT 0 COMMENT 'Progress from 0 to 100.',
    status                   ENUM('todo', 'in_progress', 'done', 'blocked')  NOT NULL DEFAULT 'todo' COMMENT 'todo, in_progress, done or blocked.',
    created_by               CHAR(36)                                        NOT NULL COMMENT 'Who created the task.',
    created_at               DATETIME                                        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               DATETIME                                        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (task_id),
    CONSTRAINT fk_team_task_team_id FOREIGN KEY (team_id) REFERENCES team (team_id),
    CONSTRAINT fk_team_task_assignee_participant_id FOREIGN KEY (assignee_participant_id) REFERENCES activity_participant (participant_id),
    CONSTRAINT fk_team_task_created_by FOREIGN KEY (created_by) REFERENCES user_account (user_id),
    CONSTRAINT chk_team_task_progress_range CHECK (progress_pct BETWEEN 0 AND 100)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The team''s task board.';

CREATE TABLE task_update (
    update_id         CHAR(36)  NOT NULL COMMENT 'Unique id of the update.',
    task_id           CHAR(36)  NOT NULL COMMENT 'The task.',
    progress_pct      INT       NOT NULL DEFAULT 0 COMMENT 'Progress after this update.',
    note              TEXT      NULL COMMENT 'What was done or what is blocking it.',
    evidence_file_id  CHAR(36)  NULL COMMENT 'A photo or file as proof.',
    updated_by        CHAR(36)  NOT NULL COMMENT 'Who wrote the update.',
    created_at        DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (update_id),
    CONSTRAINT fk_task_update_task_id FOREIGN KEY (task_id) REFERENCES team_task (task_id),
    CONSTRAINT fk_task_update_evidence_file_id FOREIGN KEY (evidence_file_id) REFERENCES file_attachment (file_id),
    CONSTRAINT fk_task_update_updated_by FOREIGN KEY (updated_by) REFERENCES user_account (user_id),
    CONSTRAINT chk_task_update_progress_range CHECK (progress_pct BETWEEN 0 AND 100)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Field updates added to a task as work progresses.';

CREATE TABLE duty_appointment (
    duty_id              CHAR(36)                                                                     NOT NULL COMMENT 'Unique id of the duty.',
    volunteer_id         CHAR(36)                                                                     NOT NULL COMMENT 'The volunteer given the duty.',
    duty_type            ENUM('team_leader', 'attendance_staff')                                      NOT NULL COMMENT 'team_leader or attendance_staff.',
    activity_id          CHAR(36)                                                                     NOT NULL COMMENT 'The approved activity the duty belongs to.',
    session_id           CHAR(36)                                                                     NULL COMMENT 'The session it covers.',
    team_id              CHAR(36)                                                                     NULL COMMENT 'The team, for a Team Leader duty.',
    station              VARCHAR(100)                                                                 NULL COMMENT 'The check-in station, for Attendance Staff, for example Main gate.',
    supervisor_id        CHAR(36)                                                                     NULL COMMENT 'The coordinator supervising the duty.',
    start_at             DATETIME                                                                     NOT NULL COMMENT 'Date and time the duty begins.',
    end_at               DATETIME                                                                     NOT NULL COMMENT 'Date and time the duty ends.',
    grace_minutes        INT                                                                          NULL COMMENT 'Extra minutes after end_at in which the volunteer can still submit an unfinished team report or attendance batch, for example 30 (suggested, to be...',
    status               ENUM('pending', 'acknowledged', 'active', 'expired', 'revoked', 'replaced')  NOT NULL DEFAULT 'pending' COMMENT 'pending, acknowledged, active, expired, revoked or replaced.',
    assigned_by          CHAR(36)                                                                     NOT NULL COMMENT 'The program coordinator who appointed them.',
    acknowledged_at      DATETIME                                                                     NULL COMMENT 'When the volunteer accepted the duty.',
    revoked_by           CHAR(36)                                                                     NULL COMMENT 'Who cancelled it early.',
    revoked_at           DATETIME                                                                     NULL COMMENT 'Date and time it was cancelled.',
    revoke_reason        VARCHAR(300)                                                                 NULL COMMENT 'Why it was cancelled.',
    replaced_by_duty_id  CHAR(36)                                                                     NULL COMMENT 'The new duty that took over, if replaced.',
    created_at           DATETIME                                                                     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME                                                                     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (duty_id),
    CONSTRAINT fk_duty_appointment_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_duty_appointment_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_duty_appointment_session_id FOREIGN KEY (session_id) REFERENCES activity_session (session_id),
    CONSTRAINT fk_duty_appointment_team_id FOREIGN KEY (team_id) REFERENCES team (team_id),
    CONSTRAINT fk_duty_appointment_supervisor_id FOREIGN KEY (supervisor_id) REFERENCES user_account (user_id),
    CONSTRAINT fk_duty_appointment_assigned_by FOREIGN KEY (assigned_by) REFERENCES user_account (user_id),
    CONSTRAINT fk_duty_appointment_revoked_by FOREIGN KEY (revoked_by) REFERENCES user_account (user_id),
    CONSTRAINT fk_duty_appointment_replaced_by_duty_id FOREIGN KEY (replaced_by_duty_id) REFERENCES duty_appointment (duty_id),
    CONSTRAINT chk_duty_appointment_window_order CHECK (end_at > start_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A temporary Team Leader or Attendance Staff duty given to a volunteer.';


-- ---------------------------------------------------------------------
--  GROUP 8. ATTENDANCE AND SERVICE HOURS
-- ---------------------------------------------------------------------

CREATE TABLE event_pass (
    pass_id           CHAR(36)                                          NOT NULL COMMENT 'Unique id of the pass.',
    participant_id    CHAR(36)                                          NOT NULL COMMENT 'The rostered volunteer the pass belongs to.',
    session_id        CHAR(36)                                          NOT NULL COMMENT 'The session the pass is valid for.',
    qr_token_hash     VARCHAR(255)                                      NOT NULL COMMENT 'Secure hash of the random code inside the QR image.',
    issued_at         DATETIME                                          NOT NULL COMMENT 'Date and time the pass was created.',
    expires_at        DATETIME                                          NOT NULL COMMENT 'Date and time the pass stops working.',
    status            ENUM('active', 'reissued', 'revoked', 'expired')  NOT NULL DEFAULT 'active' COMMENT 'active, reissued (replaced by a new pass), revoked or expired.',
    reissued_from_id  CHAR(36)                                          NULL COMMENT 'The earlier pass this one replaced.',
    created_at        DATETIME                                          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME                                          NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (pass_id),
    UNIQUE KEY uq_event_pass_qr_token_hash (qr_token_hash),
    CONSTRAINT fk_event_pass_participant_id FOREIGN KEY (participant_id) REFERENCES activity_participant (participant_id),
    CONSTRAINT fk_event_pass_session_id FOREIGN KEY (session_id) REFERENCES activity_session (session_id),
    CONSTRAINT fk_event_pass_reissued_from_id FOREIGN KEY (reissued_from_id) REFERENCES event_pass (pass_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The QR pass a volunteer shows at check-in.';

CREATE TABLE scanner_device (
    device_id         CHAR(36)                             NOT NULL COMMENT 'Unique id of the device.',
    label             VARCHAR(80)                          NOT NULL COMMENT 'Name of the device, for example Scanner 1 - Main gate.',
    assigned_user_id  CHAR(36)                             NULL COMMENT 'The staff member currently using it.',
    platform          VARCHAR(40)                          NULL COMMENT 'Android, iOS or browser.',
    last_sync_at      DATETIME                             NULL COMMENT 'Date and time it last sent data to the server.',
    status            ENUM('active', 'faulty', 'retired')  NOT NULL DEFAULT 'active' COMMENT 'active, faulty or retired.',
    created_at        DATETIME                             NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME                             NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id),
    CONSTRAINT fk_scanner_device_assigned_user_id FOREIGN KEY (assigned_user_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Phones or scanners used by Attendance Staff to read QR passes.';

CREATE TABLE attendance_record (
    attendance_id  CHAR(36)                                                                  NOT NULL COMMENT 'Unique id of the event.',
    session_id     CHAR(36)                                                                  NOT NULL COMMENT 'The session.',
    volunteer_id   CHAR(36)                                                                  NULL COMMENT 'The matched volunteer.',
    pass_id        CHAR(36)                                                                  NULL COMMENT 'The pass that was scanned.',
    event_type     ENUM('check_in', 'check_out')                                             NOT NULL COMMENT 'check_in or check_out.',
    method         ENUM('qr', 'manual')                                                      NOT NULL COMMENT 'qr (scanned) or manual (typed in by staff).',
    recorded_at    DATETIME                                                                  NOT NULL COMMENT 'The exact date and time of the check-in or check-out.',
    operator_id    CHAR(36)                                                                  NOT NULL COMMENT 'The Attendance Staff member who recorded it.',
    duty_id        CHAR(36)                                                                  NOT NULL COMMENT 'The duty the operator was acting under, which proves they were allowed to record it.',
    device_id      CHAR(36)                                                                  NULL COMMENT 'The scanner used.',
    scan_result    ENUM('success', 'duplicate', 'invalid', 'wrong_event', 'offline_queued')  NOT NULL COMMENT 'success, duplicate, invalid, wrong_event or offline_queued.',
    manual_reason  VARCHAR(300)                                                              NULL COMMENT 'Why it was entered by hand, for example Volunteer''s phone battery died.',
    record_status  ENUM('valid', 'superseded', 'rejected')                                   NOT NULL DEFAULT 'valid' COMMENT 'valid, superseded (replaced by a correction) or rejected.',
    batch_id       CHAR(36)                                                                  NULL COMMENT 'The batch it was submitted in.',
    created_at     DATETIME                                                                  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME                                                                  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (attendance_id),
    CONSTRAINT fk_attendance_record_session_id FOREIGN KEY (session_id) REFERENCES activity_session (session_id),
    CONSTRAINT fk_attendance_record_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_attendance_record_pass_id FOREIGN KEY (pass_id) REFERENCES event_pass (pass_id),
    CONSTRAINT fk_attendance_record_operator_id FOREIGN KEY (operator_id) REFERENCES user_account (user_id),
    CONSTRAINT fk_attendance_record_duty_id FOREIGN KEY (duty_id) REFERENCES duty_appointment (duty_id),
    CONSTRAINT fk_attendance_record_device_id FOREIGN KEY (device_id) REFERENCES scanner_device (device_id),
    CONSTRAINT fk_attendance_record_batch_id FOREIGN KEY (batch_id) REFERENCES attendance_batch (batch_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='One check-in or check-out event, kept as raw evidence exactly as recorded.';

CREATE TABLE attendance_correction (
    correction_id    CHAR(36)                                 NOT NULL COMMENT 'Unique id of the correction.',
    attendance_id    CHAR(36)                                 NOT NULL COMMENT 'The record being corrected.',
    correction_type  VARCHAR(60)                              NOT NULL COMMENT 'Kind of fix, for example Wrong time or Wrong person.',
    old_value        JSON                                     NOT NULL COMMENT 'What the record said before.',
    new_value        JSON                                     NOT NULL COMMENT 'What it should say.',
    reason           TEXT                                     NOT NULL COMMENT 'Why it needs fixing.',
    requested_by     CHAR(36)                                 NOT NULL COMMENT 'Who asked for it.',
    status           ENUM('pending', 'approved', 'rejected')  NOT NULL DEFAULT 'pending' COMMENT 'pending, approved or rejected.',
    reviewer_id      CHAR(36)                                 NULL COMMENT 'The reviewer.',
    decided_at       DATETIME                                 NULL COMMENT 'Date and time of the decision.',
    created_at       DATETIME                                 NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME                                 NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (correction_id),
    CONSTRAINT fk_attendance_correction_attendance_id FOREIGN KEY (attendance_id) REFERENCES attendance_record (attendance_id),
    CONSTRAINT fk_attendance_correction_requested_by FOREIGN KEY (requested_by) REFERENCES user_account (user_id),
    CONSTRAINT fk_attendance_correction_reviewer_id FOREIGN KEY (reviewer_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A fix to an attendance record.';

CREATE TABLE attendance_exception (
    exception_id              CHAR(36)                                                                       NOT NULL COMMENT 'Unique id of the exception.',
    session_id                CHAR(36)                                                                       NOT NULL COMMENT 'The session.',
    attendance_id             CHAR(36)                                                                       NULL COMMENT 'The related record.',
    volunteer_id              CHAR(36)                                                                       NULL COMMENT 'The volunteer involved, if known.',
    exception_type            ENUM('unmatched', 'duplicate', 'missing_checkout', 'wrong_event', 'mismatch')  NOT NULL COMMENT 'unmatched, duplicate, missing_checkout, wrong_event or mismatch.',
    status                    ENUM('open', 'resolved', 'disputed', 'escalated')                              NOT NULL DEFAULT 'open' COMMENT 'open, resolved, disputed or escalated.',
    resolved_by               CHAR(36)                                                                       NULL COMMENT 'Who resolved it.',
    resolution_note           VARCHAR(300)                                                                   NULL COMMENT 'How it was resolved.',
    escalated_to_coordinator  BOOLEAN                                                                        NOT NULL DEFAULT FALSE COMMENT 'True when it is an identity dispute that must go to the VACP Coordinator.',
    created_at                DATETIME                                                                       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                DATETIME                                                                       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (exception_id),
    CONSTRAINT fk_attendance_exception_session_id FOREIGN KEY (session_id) REFERENCES activity_session (session_id),
    CONSTRAINT fk_attendance_exception_attendance_id FOREIGN KEY (attendance_id) REFERENCES attendance_record (attendance_id),
    CONSTRAINT fk_attendance_exception_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_attendance_exception_resolved_by FOREIGN KEY (resolved_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Problems found when comparing scans with the roster, such as a person who scanned but is not on the list.';

CREATE TABLE attendance_batch (
    batch_id           CHAR(36)                                            NOT NULL COMMENT 'Unique id of the batch.',
    session_id         CHAR(36)                                            NOT NULL COMMENT 'The session.',
    duty_id            CHAR(36)                                            NOT NULL COMMENT 'The duty of the person who submitted it.',
    submitted_at       DATETIME                                            NULL COMMENT 'Date and time of submission.',
    clean_count        INT                                                 NOT NULL DEFAULT 0 COMMENT 'Number of records with no problems.',
    exception_count    INT                                                 NOT NULL DEFAULT 0 COMMENT 'Number of records with problems.',
    status             ENUM('draft', 'submitted', 'returned', 'verified')  NOT NULL DEFAULT 'draft' COMMENT 'draft, submitted, returned (needs correction) or verified.',
    reviewer_id        CHAR(36)                                            NULL COMMENT 'The reviewer.',
    reviewer_notes     TEXT                                                NULL COMMENT 'Notes or questions from the reviewer.',
    receipt_reference  VARCHAR(30)                                         NULL COMMENT 'Receipt number shown to the submitter, for example ATT-2026-0301.',
    created_at         DATETIME                                            NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME                                            NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (batch_id),
    UNIQUE KEY uq_attendance_batch_receipt_reference (receipt_reference),
    CONSTRAINT fk_attendance_batch_session_id FOREIGN KEY (session_id) REFERENCES activity_session (session_id),
    CONSTRAINT fk_attendance_batch_duty_id FOREIGN KEY (duty_id) REFERENCES duty_appointment (duty_id),
    CONSTRAINT fk_attendance_batch_reviewer_id FOREIGN KEY (reviewer_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The attendance list that Attendance Staff submit for review after a session.';

CREATE TABLE offline_sync_log (
    sync_id              CHAR(36)                              NOT NULL COMMENT 'Unique id of the sync.',
    device_id            CHAR(36)                              NOT NULL COMMENT 'The device.',
    operator_id          CHAR(36)                              NOT NULL COMMENT 'The operator.',
    events_received      INT                                   NOT NULL COMMENT 'How many scans were uploaded.',
    events_accepted      INT                                   NOT NULL COMMENT 'How many were kept.',
    duplicates_rejected  INT                                   NOT NULL COMMENT 'How many repeated scans were dropped.',
    synced_at            DATETIME                              NOT NULL COMMENT 'Date and time of the upload.',
    status               ENUM('success', 'partial', 'failed')  NOT NULL COMMENT 'success, partial (some scans rejected) or failed (nothing uploaded).',
    error_message        VARCHAR(300)                          NULL COMMENT 'Why the sync failed, for example Connection lost during upload.',
    created_at           DATETIME                              NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME                              NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (sync_id),
    CONSTRAINT fk_offline_sync_log_device_id FOREIGN KEY (device_id) REFERENCES scanner_device (device_id),
    CONSTRAINT fk_offline_sync_log_operator_id FOREIGN KEY (operator_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='What happened each time a scanner uploaded scans it recorded without internet.';

CREATE TABLE service_hour (
    hour_id            CHAR(36)                                                         NOT NULL COMMENT 'Unique id of the record.',
    volunteer_id       CHAR(36)                                                         NOT NULL COMMENT 'The volunteer.',
    activity_id        CHAR(36)                                                         NOT NULL COMMENT 'The activity.',
    session_id         CHAR(36)                                                         NOT NULL COMMENT 'The session.',
    check_in_id        CHAR(36)                                                         NULL COMMENT 'The check-in used for the calculation.',
    check_out_id       CHAR(36)                                                         NULL COMMENT 'The check-out used for the calculation.',
    computed_hours     DECIMAL(5,2)                                                     NOT NULL COMMENT 'Hours calculated from the scans, for example 3.50.',
    verified_hours     DECIMAL(5,2)                                                     NULL COMMENT 'The official hours after a reviewer verifies them.',
    status             ENUM('pending', 'verified', 'adjusted', 'reopened', 'disputed')  NOT NULL DEFAULT 'pending' COMMENT 'pending, verified, adjusted, reopened or disputed.',
    verified_by        CHAR(36)                                                         NULL COMMENT 'The reviewer who verified the hours.',
    verified_at        DATETIME                                                         NULL COMMENT 'Date and time of verification.',
    adjustment_reason  VARCHAR(300)                                                     NULL COMMENT 'Why the hours were changed, if they were.',
    created_at         DATETIME                                                         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME                                                         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (hour_id),
    CONSTRAINT fk_service_hour_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_service_hour_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_service_hour_session_id FOREIGN KEY (session_id) REFERENCES activity_session (session_id),
    CONSTRAINT fk_service_hour_check_in_id FOREIGN KEY (check_in_id) REFERENCES attendance_record (attendance_id),
    CONSTRAINT fk_service_hour_check_out_id FOREIGN KEY (check_out_id) REFERENCES attendance_record (attendance_id),
    CONSTRAINT fk_service_hour_verified_by FOREIGN KEY (verified_by) REFERENCES user_account (user_id),
    CONSTRAINT chk_service_hour_hours_non_negative CHECK (computed_hours >= 0 AND (verified_hours IS NULL OR verified_hours >= 0))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The official service hours of one volunteer for one session.';

CREATE TABLE hour_dispute (
    dispute_id     CHAR(36)                                                   NOT NULL COMMENT 'Unique id of the dispute.',
    volunteer_id   CHAR(36)                                                   NOT NULL COMMENT 'The volunteer.',
    attendance_id  CHAR(36)                                                   NULL COMMENT 'The attendance record they dispute.',
    hour_id        CHAR(36)                                                   NULL COMMENT 'The hours they dispute.',
    description    TEXT                                                       NOT NULL COMMENT 'What the volunteer says is wrong, for example I stayed until 5 PM but checkout shows 3 PM.',
    status         ENUM('submitted', 'under_review', 'accepted', 'rejected')  NOT NULL DEFAULT 'submitted' COMMENT 'submitted, under_review, accepted or rejected.',
    reviewer_id    CHAR(36)                                                   NULL COMMENT 'The reviewer.',
    resolution     TEXT                                                       NULL COMMENT 'The outcome and explanation.',
    decided_at     DATETIME                                                   NULL COMMENT 'Date and time of the decision.',
    created_at     DATETIME                                                   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME                                                   NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (dispute_id),
    CONSTRAINT fk_hour_dispute_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_hour_dispute_attendance_id FOREIGN KEY (attendance_id) REFERENCES attendance_record (attendance_id),
    CONSTRAINT fk_hour_dispute_hour_id FOREIGN KEY (hour_id) REFERENCES service_hour (hour_id),
    CONSTRAINT fk_hour_dispute_reviewer_id FOREIGN KEY (reviewer_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A volunteer''s complaint that their attendance or hours are wrong.';


-- ---------------------------------------------------------------------
--  GROUP 9. OUTCOMES, EVIDENCE AND CERTIFICATES
-- ---------------------------------------------------------------------

CREATE TABLE file_attachment (
    file_id       CHAR(36)                                NOT NULL COMMENT 'Unique id of the file.',
    owner_type    VARCHAR(60)                             NOT NULL COMMENT 'Which table the file belongs to, for example volunteer_qualification.',
    owner_id      CHAR(36)                                NOT NULL COMMENT 'The row in that table the file belongs to.',
    file_name     VARCHAR(255)                            NOT NULL COMMENT 'The original file name, for example BLS-certificate.pdf.',
    mime_type     VARCHAR(100)                            NOT NULL COMMENT 'The file type, for example image/jpeg or application/pdf.',
    size_bytes    BIGINT                                  NOT NULL COMMENT 'File size in bytes.',
    storage_path  VARCHAR(500)                            NOT NULL COMMENT 'Where the file is stored on the server or cloud storage.',
    checksum      VARCHAR(100)                            NULL COMMENT 'A fingerprint used to detect a damaged or changed file.',
    visibility    ENUM('private', 'activity', 'program')  NOT NULL COMMENT 'private (owner and reviewers), activity (people on that activity) or program (program staff).',
    uploaded_by   CHAR(36)                                NOT NULL COMMENT 'Who uploaded it.',
    created_at    DATETIME                                NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME                                NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (file_id),
    CONSTRAINT fk_file_attachment_uploaded_by FOREIGN KEY (uploaded_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Any uploaded file in the system, such as photos, proposal attachments or proof of a qualification.';

CREATE TABLE team_report (
    report_id        CHAR(36)                                            NOT NULL COMMENT 'Unique id of the report.',
    team_id          CHAR(36)                                            NOT NULL COMMENT 'The team.',
    session_id       CHAR(36)                                            NULL COMMENT 'The session reported on.',
    report_date      DATE                                                NOT NULL COMMENT 'The day the report covers.',
    completed_tasks  TEXT                                                NOT NULL COMMENT 'The tasks the team finished.',
    outputs          TEXT                                                NULL COMMENT 'What was produced, for example 120 sacks of trash collected.',
    issues           TEXT                                                NULL COMMENT 'Problems met during the day.',
    lessons          TEXT                                                NULL COMMENT 'What the team learned.',
    status           ENUM('draft', 'submitted', 'returned', 'accepted')  NOT NULL DEFAULT 'draft' COMMENT 'draft, submitted, returned or accepted.',
    submitted_by     CHAR(36)                                            NULL COMMENT 'The Team Leader who submitted it.',
    reviewer_id      CHAR(36)                                            NULL COMMENT 'The coordinator who reviewed it.',
    created_at       DATETIME                                            NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME                                            NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (report_id),
    CONSTRAINT fk_team_report_team_id FOREIGN KEY (team_id) REFERENCES team (team_id),
    CONSTRAINT fk_team_report_session_id FOREIGN KEY (session_id) REFERENCES activity_session (session_id),
    CONSTRAINT fk_team_report_submitted_by FOREIGN KEY (submitted_by) REFERENCES user_account (user_id),
    CONSTRAINT fk_team_report_reviewer_id FOREIGN KEY (reviewer_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A Team Leader''s daily report of what the team accomplished.';

CREATE TABLE incident_report (
    incident_id      CHAR(36)                                               NOT NULL COMMENT 'Unique id of the incident.',
    activity_id      CHAR(36)                                               NOT NULL COMMENT 'The activity.',
    session_id       CHAR(36)                                               NULL COMMENT 'The session.',
    team_id          CHAR(36)                                               NULL COMMENT 'The team involved.',
    reported_by      CHAR(36)                                               NOT NULL COMMENT 'Who reported it.',
    category         VARCHAR(60)                                            NOT NULL COMMENT 'Type of concern, for example Safety, Logistics or Conduct.',
    description      TEXT                                                   NOT NULL COMMENT 'What happened.',
    reported_at      DATETIME                                               NOT NULL COMMENT 'Date and time it was reported.',
    status           ENUM('open', 'acknowledged', 'escalated', 'resolved')  NOT NULL DEFAULT 'open' COMMENT 'open, acknowledged, escalated or resolved.',
    escalated_to     CHAR(36)                                               NULL COMMENT 'The person it was escalated to.',
    resolved_by      CHAR(36)                                               NULL COMMENT 'Who resolved it.',
    resolution_note  TEXT                                                   NULL COMMENT 'How it was resolved.',
    created_at       DATETIME                                               NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME                                               NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (incident_id),
    CONSTRAINT fk_incident_report_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_incident_report_session_id FOREIGN KEY (session_id) REFERENCES activity_session (session_id),
    CONSTRAINT fk_incident_report_team_id FOREIGN KEY (team_id) REFERENCES team (team_id),
    CONSTRAINT fk_incident_report_reported_by FOREIGN KEY (reported_by) REFERENCES user_account (user_id),
    CONSTRAINT fk_incident_report_escalated_to FOREIGN KEY (escalated_to) REFERENCES user_account (user_id),
    CONSTRAINT fk_incident_report_resolved_by FOREIGN KEY (resolved_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A report of an operational or safety concern during an activity.';

CREATE TABLE activity_completion (
    completion_id         CHAR(36)                                            NOT NULL COMMENT 'Unique id of the report.',
    activity_id           CHAR(36)                                            NOT NULL COMMENT 'The activity.',
    prepared_by           CHAR(36)                                            NOT NULL COMMENT 'The event coordinator who wrote it.',
    outputs_summary       TEXT                                                NOT NULL COMMENT 'What the activity actually produced.',
    challenges            TEXT                                                NULL COMMENT 'Problems faced.',
    lessons               TEXT                                                NULL COMMENT 'Lessons learned.',
    applied_count         INT                                                 NOT NULL DEFAULT 0 COMMENT 'How many volunteers applied.',
    accepted_count        INT                                                 NOT NULL DEFAULT 0 COMMENT 'How many were accepted.',
    attended_count        INT                                                 NOT NULL DEFAULT 0 COMMENT 'How many actually attended.',
    total_verified_hours  DECIMAL(8,2)                                        NULL COMMENT 'Total verified hours of all participants, once available.',
    status                ENUM('draft', 'submitted', 'returned', 'approved')  NOT NULL DEFAULT 'draft' COMMENT 'draft, submitted, returned or approved.',
    approved_by           CHAR(36)                                            NULL COMMENT 'The program coordinator who approved the completion.',
    approved_at           DATETIME                                            NULL COMMENT 'Date and time of approval.',
    created_at            DATETIME                                            NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME                                            NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (completion_id),
    CONSTRAINT fk_activity_completion_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_activity_completion_prepared_by FOREIGN KEY (prepared_by) REFERENCES user_account (user_id),
    CONSTRAINT fk_activity_completion_approved_by FOREIGN KEY (approved_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The completion report an event coordinator submits when an activity is finished.';

CREATE TABLE certificate_template (
    template_id      CHAR(36)                               NOT NULL COMMENT 'Unique id of the template.',
    name             VARCHAR(120)                           NOT NULL COMMENT 'Template name, for example Standard Volunteer Certificate.',
    version_no       INT                                    NOT NULL DEFAULT 1 COMMENT 'Version number.',
    signatory_name   VARCHAR(120)                           NULL COMMENT 'Name of the person who signs the certificate.',
    signatory_title  VARCHAR(120)                           NULL COMMENT 'That person''s title.',
    layout_file_id   CHAR(36)                               NULL COMMENT 'The design file.',
    status           ENUM('draft', 'published', 'retired')  NOT NULL DEFAULT 'draft' COMMENT 'draft, published or retired.',
    created_at       DATETIME                               NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME                               NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (template_id),
    CONSTRAINT fk_certificate_template_layout_file_id FOREIGN KEY (layout_file_id) REFERENCES file_attachment (file_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The designs used to print certificates.';

CREATE TABLE certificate (
    certificate_id        CHAR(36)                                                                    NOT NULL COMMENT 'Unique id of the certificate.',
    certificate_no        VARCHAR(30)                                                                 NOT NULL COMMENT 'The printed certificate number, for example CERT-2026-00045.',
    volunteer_id          CHAR(36)                                                                    NOT NULL COMMENT 'The recipient.',
    activity_id           CHAR(36)                                                                    NOT NULL COMMENT 'The activity it recognizes.',
    template_id           CHAR(36)                                                                    NOT NULL COMMENT 'The template used.',
    verified_hours        DECIMAL(5,2)                                                                NULL COMMENT 'The verified hours printed on the certificate.',
    validation_reference  VARCHAR(40)                                                                 NOT NULL COMMENT 'A code anyone can use to check that the certificate is genuine.',
    file_id               CHAR(36)                                                                    NULL COMMENT 'The generated certificate file.',
    status                ENUM('eligible', 'approved', 'issued', 'reissued', 'corrected', 'revoked')  NOT NULL DEFAULT 'eligible' COMMENT 'eligible, approved, issued, reissued, corrected or revoked.',
    issue_date            DATE                                                                        NULL COMMENT 'Date it was issued.',
    issued_by             CHAR(36)                                                                    NULL COMMENT 'The staff member who issued it.',
    created_at            DATETIME                                                                    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME                                                                    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (certificate_id),
    UNIQUE KEY uq_certificate_certificate_no (certificate_no),
    UNIQUE KEY uq_certificate_validation_reference (validation_reference),
    CONSTRAINT fk_certificate_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_certificate_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_certificate_template_id FOREIGN KEY (template_id) REFERENCES certificate_template (template_id),
    CONSTRAINT fk_certificate_file_id FOREIGN KEY (file_id) REFERENCES file_attachment (file_id),
    CONSTRAINT fk_certificate_issued_by FOREIGN KEY (issued_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A certificate given to a volunteer for an activity.';

CREATE TABLE certificate_event (
    event_id        CHAR(36)                                                  NOT NULL COMMENT 'Unique id of the event.',
    certificate_id  CHAR(36)                                                  NOT NULL COMMENT 'The certificate.',
    action          ENUM('approve', 'issue', 'reissue', 'correct', 'revoke')  NOT NULL COMMENT 'approve, issue, reissue, correct or revoke.',
    actor_id        CHAR(36)                                                  NOT NULL COMMENT 'Who did it.',
    reason          VARCHAR(300)                                              NOT NULL COMMENT 'Why it was done.',
    old_value       JSON                                                      NULL COMMENT 'What it said before.',
    new_value       JSON                                                      NULL COMMENT 'What it says now.',
    occurred_at     DATETIME                                                  NOT NULL COMMENT 'Date and time it happened.',
    created_at      DATETIME                                                  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME                                                  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (event_id),
    CONSTRAINT fk_certificate_event_certificate_id FOREIGN KEY (certificate_id) REFERENCES certificate (certificate_id),
    CONSTRAINT fk_certificate_event_actor_id FOREIGN KEY (actor_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The audit trail of everything done to a certificate.';


-- ---------------------------------------------------------------------
--  GROUP 10. COMMUNICATION AND SUPPORT
-- ---------------------------------------------------------------------

CREATE TABLE notification (
    notification_id    CHAR(36)      NOT NULL COMMENT 'Unique id of the notification.',
    recipient_id       CHAR(36)      NOT NULL COMMENT 'The person who receives it.',
    notification_type  VARCHAR(60)   NOT NULL COMMENT 'Kind of notice, for example registration_approved, application_result or schedule_change.',
    title              VARCHAR(150)  NOT NULL COMMENT 'Short heading, for example Registration approved.',
    body               VARCHAR(500)  NOT NULL COMMENT 'The message, for example You are now a verified volunteer.',
    related_type       VARCHAR(60)   NULL COMMENT 'The kind of record it is about, for example activity.',
    related_id         CHAR(36)      NULL COMMENT 'The specific record it is about, so tapping it opens the right screen.',
    is_read            BOOLEAN       NOT NULL DEFAULT FALSE COMMENT 'True once the person has opened it.',
    read_at            DATETIME      NULL COMMENT 'Date and time it was read.',
    created_at         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (notification_id),
    CONSTRAINT fk_notification_recipient_id FOREIGN KEY (recipient_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A notice for one person, shown in the app bell and optionally pushed to the phone.';

CREATE TABLE notification_preference (
    user_id     CHAR(36)                                NOT NULL COMMENT 'The person.',
    category    VARCHAR(60)                             NOT NULL COMMENT 'The kind of notice, for example reminders.',
    channel     ENUM('in_app', 'push', 'email', 'sms')  NOT NULL COMMENT 'in_app, push, email or sms.',
    is_enabled  BOOLEAN                                 NOT NULL DEFAULT TRUE COMMENT 'True if the person wants this notice on this channel.',
    created_at  DATETIME                                NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME                                NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, category, channel),
    CONSTRAINT fk_notification_preference_user_id FOREIGN KEY (user_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Which notices a person wants and where they want to get them.';

CREATE TABLE announcement (
    announcement_id    CHAR(36)                                                             NOT NULL COMMENT 'Unique id of the announcement.',
    announcement_type  ENUM('broadcast', 'event_notice', 'program_notice')                  NOT NULL COMMENT 'broadcast, event_notice or program_notice.',
    title              VARCHAR(200)                                                         NOT NULL COMMENT 'Heading.',
    body               TEXT                                                                 NOT NULL COMMENT 'The message.',
    audience_scope     ENUM('all', 'role', 'barangay', 'organization', 'activity', 'team')  NOT NULL COMMENT 'Who receives it: all, role, barangay, organization, activity or team.',
    audience_ref_id    CHAR(36)                                                             NULL COMMENT 'The specific role, barangay, organization, activity or team.',
    template_id        CHAR(36)                                                             NULL COMMENT 'The template it was built from.',
    scheduled_at       DATETIME                                                             NULL COMMENT 'When it should be sent.',
    sent_at            DATETIME                                                             NULL COMMENT 'When it was actually sent.',
    status             ENUM('draft', 'scheduled', 'sent', 'cancelled')                      NOT NULL DEFAULT 'draft' COMMENT 'draft, scheduled, sent or cancelled.',
    created_by         CHAR(36)                                                             NOT NULL COMMENT 'The author.',
    created_at         DATETIME                                                             NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME                                                             NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (announcement_id),
    CONSTRAINT fk_announcement_template_id FOREIGN KEY (template_id) REFERENCES message_template (template_id),
    CONSTRAINT fk_announcement_created_by FOREIGN KEY (created_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A broadcast or event notice written by staff for a chosen group.';

CREATE TABLE message_template (
    template_id  CHAR(36)                                NOT NULL COMMENT 'Unique id of the template.',
    name         VARCHAR(120)                            NOT NULL COMMENT 'Template name, for example Event reminder.',
    channel      ENUM('in_app', 'push', 'email', 'sms')  NOT NULL COMMENT 'in_app, push, email or sms.',
    subject      VARCHAR(200)                            NULL COMMENT 'Subject line, for emails.',
    body         TEXT                                    NOT NULL COMMENT 'The text with placeholders like the volunteer name and event title.',
    version_no   INT                                     NOT NULL DEFAULT 1 COMMENT 'Version number.',
    status       ENUM('draft', 'active', 'retired')      NOT NULL DEFAULT 'draft' COMMENT 'draft, active or retired.',
    created_at   DATETIME                                NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME                                NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (template_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Reusable message wording, for example the approval or reminder message.';

CREATE TABLE delivery_log (
    delivery_id      CHAR(36)                                                 NOT NULL COMMENT 'Unique id of the delivery.',
    announcement_id  CHAR(36)                                                 NULL COMMENT 'The announcement, if it came from one.',
    notification_id  CHAR(36)                                                 NULL COMMENT 'The notification, if it came from one.',
    recipient_id     CHAR(36)                                                 NOT NULL COMMENT 'The person it was sent to.',
    channel          ENUM('in_app', 'push', 'email', 'sms')                   NOT NULL COMMENT 'in_app, push, email or sms.',
    status           ENUM('queued', 'sent', 'delivered', 'failed', 'resent')  NOT NULL DEFAULT 'queued' COMMENT 'queued, sent, delivered, failed or resent.',
    error_message    VARCHAR(300)                                             NULL COMMENT 'Why it failed, for example Invalid email address.',
    attempt_no       INT                                                      NOT NULL DEFAULT 1 COMMENT 'Which attempt this was.',
    sent_at          DATETIME                                                 NULL COMMENT 'Date and time it was sent.',
    created_at       DATETIME                                                 NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME                                                 NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (delivery_id),
    CONSTRAINT fk_delivery_log_announcement_id FOREIGN KEY (announcement_id) REFERENCES announcement (announcement_id),
    CONSTRAINT fk_delivery_log_notification_id FOREIGN KEY (notification_id) REFERENCES notification (notification_id),
    CONSTRAINT fk_delivery_log_recipient_id FOREIGN KEY (recipient_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Whether each message actually reached each person.';

CREATE TABLE message_thread (
    thread_id    CHAR(36)                                       NOT NULL COMMENT 'Unique id of the thread.',
    thread_type  ENUM('office', 'activity', 'team', 'support')  NOT NULL COMMENT 'office, activity, team or support.',
    activity_id  CHAR(36)                                       NULL COMMENT 'The activity, for an activity thread.',
    team_id      CHAR(36)                                       NULL COMMENT 'The team, for a team thread.',
    barangay_id  CHAR(36)                                       NULL COMMENT 'The barangay, for a barangay office thread.',
    org_id       CHAR(36)                                       NULL COMMENT 'The organization, for an organization thread.',
    subject      VARCHAR(200)                                   NOT NULL COMMENT 'Topic of the conversation.',
    created_by   CHAR(36)                                       NOT NULL COMMENT 'Who started it.',
    created_at   DATETIME                                       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME                                       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (thread_id),
    CONSTRAINT fk_message_thread_activity_id FOREIGN KEY (activity_id) REFERENCES activity (activity_id),
    CONSTRAINT fk_message_thread_team_id FOREIGN KEY (team_id) REFERENCES team (team_id),
    CONSTRAINT fk_message_thread_barangay_id FOREIGN KEY (barangay_id) REFERENCES barangay (barangay_id),
    CONSTRAINT fk_message_thread_org_id FOREIGN KEY (org_id) REFERENCES partner_organization (org_id),
    CONSTRAINT fk_message_thread_created_by FOREIGN KEY (created_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A conversation, such as the office inbox, an activity chat or a team chat.';

CREATE TABLE message (
    message_id       CHAR(36)  NOT NULL COMMENT 'Unique id of the message.',
    thread_id        CHAR(36)  NOT NULL COMMENT 'The thread.',
    sender_id        CHAR(36)  NOT NULL COMMENT 'Who wrote it.',
    body             TEXT      NOT NULL COMMENT 'The message text.',
    requires_ack     BOOLEAN   NOT NULL DEFAULT FALSE COMMENT 'True if the reader has to confirm they read it.',
    acknowledged_at  DATETIME  NULL COMMENT 'When the reader confirmed.',
    created_at       DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (message_id),
    CONSTRAINT fk_message_thread_id FOREIGN KEY (thread_id) REFERENCES message_thread (thread_id),
    CONSTRAINT fk_message_sender_id FOREIGN KEY (sender_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='One message inside a thread.';

CREATE TABLE support_ticket (
    ticket_id     CHAR(36)                                                                                                                NOT NULL COMMENT 'Unique id of the ticket.',
    ticket_no     VARCHAR(20)                                                                                                             NOT NULL COMMENT 'Readable number, for example TKT-2026-0088.',
    requester_id  CHAR(36)                                                                                                                NOT NULL COMMENT 'Who asked for help.',
    topic         ENUM('profile_correction', 'account_access', 'duplicate_profile', 'deactivation', 'concern', 'scanner_fault', 'other')  NOT NULL COMMENT 'profile_correction, account_access, duplicate_profile, deactivation, concern, scanner_fault or other.',
    priority      ENUM('low', 'normal', 'high', 'urgent')                                                                                 NOT NULL COMMENT 'low, normal, high or urgent.',
    status        ENUM('open', 'assigned', 'in_progress', 'resolved', 'closed')                                                           NOT NULL DEFAULT 'open' COMMENT 'open, assigned, in_progress, resolved or closed.',
    assigned_to   CHAR(36)                                                                                                                NULL COMMENT 'The support staff member handling it.',
    related_type  VARCHAR(60)                                                                                                             NULL COMMENT 'The kind of record it is about.',
    related_id    CHAR(36)                                                                                                                NULL COMMENT 'The specific record it is about.',
    resolved_at   DATETIME                                                                                                                NULL COMMENT 'Date and time it was resolved.',
    created_at    DATETIME                                                                                                                NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME                                                                                                                NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (ticket_id),
    UNIQUE KEY uq_support_ticket_ticket_no (ticket_no),
    CONSTRAINT fk_support_ticket_requester_id FOREIGN KEY (requester_id) REFERENCES user_account (user_id),
    CONSTRAINT fk_support_ticket_assigned_to FOREIGN KEY (assigned_to) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A help request, such as a profile correction, a volunteer concern or a scanner problem.';

CREATE TABLE support_ticket_response (
    response_id  CHAR(36)  NOT NULL COMMENT 'Unique id of the reply.',
    ticket_id    CHAR(36)  NOT NULL COMMENT 'The ticket.',
    author_id    CHAR(36)  NOT NULL COMMENT 'Who wrote the reply.',
    body         TEXT      NOT NULL COMMENT 'The reply text.',
    is_internal  BOOLEAN   NOT NULL DEFAULT FALSE COMMENT 'True if only staff can see it.',
    created_at   DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (response_id),
    CONSTRAINT fk_support_ticket_response_ticket_id FOREIGN KEY (ticket_id) REFERENCES support_ticket (ticket_id),
    CONSTRAINT fk_support_ticket_response_author_id FOREIGN KEY (author_id) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The replies on a support ticket.';

CREATE TABLE help_article (
    article_id     CHAR(36)                                NOT NULL COMMENT 'Unique id of the article.',
    title          VARCHAR(200)                            NOT NULL COMMENT 'Question or topic, for example How do I complete my registration.',
    body           TEXT                                    NOT NULL COMMENT 'The answer or guide.',
    audience_role  VARCHAR(30)                             NULL COMMENT 'The role it is meant for.',
    category       VARCHAR(60)                             NULL COMMENT 'Topic group, for example Registration or Attendance.',
    status         ENUM('draft', 'published', 'archived')  NOT NULL DEFAULT 'draft' COMMENT 'draft, published or archived.',
    created_at     DATETIME                                NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME                                NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (article_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Help center and FAQ content.';


-- ---------------------------------------------------------------------
--  GROUP 11. REPORTS, AUDIT AND SYSTEM SETTINGS
-- ---------------------------------------------------------------------

CREATE TABLE audit_log (
    audit_id     BIGINT        NOT NULL AUTO_INCREMENT COMMENT 'A running number that increases with every event, so the order can never be faked.',
    event_time   DATETIME      NOT NULL COMMENT 'Exact date and time of the event.',
    actor_id     CHAR(36)      NULL COMMENT 'Who did it.',
    actor_role   VARCHAR(30)   NULL COMMENT 'The role they had at that moment.',
    action       VARCHAR(80)   NOT NULL COMMENT 'What happened, for example APPROVE_REGISTRATION or REVOKE_CERTIFICATE.',
    entity_type  VARCHAR(60)   NOT NULL COMMENT 'Which table was affected.',
    entity_id    CHAR(36)      NULL COMMENT 'Which record was affected.',
    old_value    JSON          NULL COMMENT 'The value before the change.',
    new_value    JSON          NULL COMMENT 'The value after the change.',
    reason       VARCHAR(300)  NULL COMMENT 'The reason given.',
    ip_address   VARCHAR(45)   NULL COMMENT 'Internet address the action came from.',
    session_id   CHAR(36)      NULL COMMENT 'The login session used.',
    PRIMARY KEY (audit_id),
    CONSTRAINT fk_audit_log_actor_id FOREIGN KEY (actor_id) REFERENCES user_account (user_id),
    CONSTRAINT fk_audit_log_session_id FOREIGN KEY (session_id) REFERENCES user_session (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A permanent log of important events, such as approvals, role changes and overrides.';

CREATE TABLE sensitive_access_log (
    access_id      CHAR(36)                                                       NOT NULL COMMENT 'Unique id of this entry.',
    user_id        CHAR(36)                                                       NOT NULL COMMENT 'The person who opened the data.',
    volunteer_id   CHAR(36)                                                       NOT NULL COMMENT 'The volunteer whose data was opened.',
    data_category  ENUM('medical', 'food', 'emergency_contact', 'date_of_birth')  NOT NULL COMMENT 'medical, food, emergency_contact or date_of_birth.',
    access_type    ENUM('view', 'export')                                         NOT NULL COMMENT 'view (opened the Restricted Safety section) or export (included the data in a download).',
    purpose        VARCHAR(300)                                                   NULL COMMENT 'Optional reason for the view, for example Preparing first aid for the river clean-up.',
    ticket_id      CHAR(36)                                                       NULL COMMENT 'The support ticket that justified it, if any.',
    accessed_at    DATETIME                                                       NOT NULL COMMENT 'Date and time it was opened.',
    PRIMARY KEY (access_id),
    CONSTRAINT fk_sensitive_access_log_user_id FOREIGN KEY (user_id) REFERENCES user_account (user_id),
    CONSTRAINT fk_sensitive_access_log_volunteer_id FOREIGN KEY (volunteer_id) REFERENCES volunteer (volunteer_id),
    CONSTRAINT fk_sensitive_access_log_ticket_id FOREIGN KEY (ticket_id) REFERENCES support_ticket (ticket_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A log that records every time restricted volunteer data (medical, food, emergency contact) is viewed or exported.';

CREATE TABLE report_definition (
    report_id               CHAR(36)      NOT NULL COMMENT 'Unique id of the report.',
    report_code             VARCHAR(40)   NOT NULL COMMENT 'Short code, for example VOL_MASTER_LIST.',
    name                    VARCHAR(150)  NOT NULL COMMENT 'Report name, for example Volunteer Master List.',
    category                VARCHAR(60)   NOT NULL COMMENT 'Group, for example Registration, Activities, Hours, SDG or Certificates.',
    includes_personal_data  BOOLEAN       NOT NULL DEFAULT FALSE COMMENT 'True if the report shows names or other personal details.',
    allowed_roles           JSON          NOT NULL COMMENT 'The roles allowed to run this report.',
    created_at              DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (report_id),
    UNIQUE KEY uq_report_definition_report_code (report_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='The list of reports the system can produce.';

CREATE TABLE saved_report_filter (
    filter_id    CHAR(36)      NOT NULL COMMENT 'Unique id of the saved filter.',
    user_id      CHAR(36)      NOT NULL COMMENT 'The owner.',
    report_id    CHAR(36)      NOT NULL COMMENT 'The report.',
    name         VARCHAR(100)  NOT NULL COMMENT 'Name the user gave it, for example Q3 hours by barangay.',
    filter_json  JSON          NOT NULL COMMENT 'The saved filter choices, for example date range and barangay.',
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (filter_id),
    CONSTRAINT fk_saved_report_filter_user_id FOREIGN KEY (user_id) REFERENCES user_account (user_id),
    CONSTRAINT fk_saved_report_filter_report_id FOREIGN KEY (report_id) REFERENCES report_definition (report_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A filter a user saved so they can rerun a report quickly.';

CREATE TABLE report_export (
    export_id     CHAR(36)            NOT NULL COMMENT 'Unique id of the export.',
    report_id     CHAR(36)            NOT NULL COMMENT 'The report.',
    requested_by  CHAR(36)            NOT NULL COMMENT 'Who generated it.',
    format        ENUM('pdf', 'csv')  NOT NULL COMMENT 'pdf or csv.',
    filter_json   JSON                NULL COMMENT 'The filters used.',
    row_count     INT                 NULL COMMENT 'Number of rows in the file.',
    purpose       VARCHAR(300)        NULL COMMENT 'The stated reason, important when personal data is included.',
    file_id       CHAR(36)            NULL COMMENT 'The generated file.',
    generated_at  DATETIME            NOT NULL COMMENT 'Date and time it was generated.',
    created_at    DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (export_id),
    CONSTRAINT fk_report_export_report_id FOREIGN KEY (report_id) REFERENCES report_definition (report_id),
    CONSTRAINT fk_report_export_requested_by FOREIGN KEY (requested_by) REFERENCES user_account (user_id),
    CONSTRAINT fk_report_export_file_id FOREIGN KEY (file_id) REFERENCES file_attachment (file_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='A history of every PDF or CSV that was generated.';

CREATE TABLE system_setting (
    setting_id     CHAR(36)                                     NOT NULL COMMENT 'Unique id of the setting.',
    setting_key    VARCHAR(80)                                  NOT NULL COMMENT 'Name of the setting, for example TIMEZONE, QR_TOKEN_TTL_MINUTES or REPORT_MIN_COUNT (counts below this number, default 5, are shown as fewer than 5).',
    setting_value  VARCHAR(500)                                 NOT NULL COMMENT 'The current value, for example Asia/Manila or 720.',
    value_type     ENUM('string', 'number', 'boolean', 'json')  NOT NULL COMMENT 'string, number, boolean or json.',
    description    VARCHAR(300)                                 NULL COMMENT 'What the setting controls.',
    updated_by     CHAR(36)                                     NOT NULL COMMENT 'Who last changed it.',
    created_at     DATETIME                                     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME                                     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (setting_id),
    UNIQUE KEY uq_system_setting_setting_key (setting_key),
    CONSTRAINT fk_system_setting_updated_by FOREIGN KEY (updated_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Configuration values the administrator can change, such as timezone or the QR code lifetime.';

CREATE TABLE retention_policy (
    policy_id         CHAR(36)                                NOT NULL COMMENT 'Unique id of the policy.',
    data_category     VARCHAR(80)                             NOT NULL COMMENT 'The kind of data, for example Inactive volunteer profiles.',
    retention_months  INT                                     NOT NULL COMMENT 'Number of months to keep it.',
    action_after      ENUM('archive', 'anonymize', 'delete')  NOT NULL COMMENT 'archive, anonymize or delete.',
    is_active         BOOLEAN                                 NOT NULL DEFAULT TRUE COMMENT 'True if the policy is in force.',
    approved_by       CHAR(36)                                NOT NULL COMMENT 'Who approved the policy.',
    created_at        DATETIME                                NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME                                NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (policy_id),
    CONSTRAINT fk_retention_policy_approved_by FOREIGN KEY (approved_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='How long each kind of data is kept before it is archived, anonymized or deleted.';

CREATE TABLE profile_field_policy (
    policy_id      CHAR(36)     NOT NULL COMMENT 'Unique id of the policy.',
    field_code     VARCHAR(80)  NOT NULL COMMENT 'The profile field, for example date_of_birth.',
    is_protected   BOOLEAN      NOT NULL DEFAULT FALSE COMMENT 'True if changing it needs reviewer approval.',
    is_restricted  BOOLEAN      NOT NULL DEFAULT FALSE COMMENT 'True if it is hidden from lists, search and reports and shown only in the Restricted Safety section to allowed roles, such as medical data.',
    updated_by     CHAR(36)     NOT NULL COMMENT 'Who last changed the rule.',
    created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (policy_id),
    UNIQUE KEY uq_profile_field_policy_field_code (field_code),
    CONSTRAINT fk_profile_field_policy_updated_by FOREIGN KEY (updated_by) REFERENCES user_account (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Rules about each profile field: whether changes need review and whether the field is hidden from lists and reports.';

SET FOREIGN_KEY_CHECKS = 1;

-- ---------------------------------------------------------------------
--  EXTRA INDEXES (for the screens and counts that are used most)
-- ---------------------------------------------------------------------
CREATE INDEX idx_volunteer_barangay_status ON volunteer (barangay_id, profile_status);
CREATE INDEX idx_volunteer_status          ON volunteer (profile_status);
CREATE INDEX idx_activity_status_start     ON activity (status, start_date);
CREATE INDEX idx_application_status        ON activity_application (status);
CREATE INDEX idx_attendance_session_time   ON attendance_record (session_id, recorded_at);
CREATE INDEX idx_notification_unread       ON notification (recipient_id, is_read);
CREATE INDEX idx_audit_time                ON audit_log (event_time);
CREATE INDEX idx_audit_entity              ON audit_log (entity_type, entity_id);
CREATE INDEX idx_registration_queue        ON volunteer_registration (status, review_due_at);
CREATE INDEX idx_exception_status          ON attendance_exception (status);
CREATE INDEX idx_ticket_status_priority    ON support_ticket (status, priority);
CREATE INDEX idx_duty_status_end           ON duty_appointment (status, end_at);

-- ---------------------------------------------------------------------
--  TRIGGERS (rules that must hold even if the application has a bug)
-- ---------------------------------------------------------------------
DELIMITER $$

-- The audit log and the sensitive-access log can only grow. No edits, no deletes.
CREATE TRIGGER trg_audit_log_no_update BEFORE UPDATE ON audit_log FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log is append-only';
END$$
CREATE TRIGGER trg_audit_log_no_delete BEFORE DELETE ON audit_log FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log is append-only';
END$$
CREATE TRIGGER trg_sensitive_access_log_no_update BEFORE UPDATE ON sensitive_access_log FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'sensitive_access_log is append-only';
END$$
CREATE TRIGGER trg_sensitive_access_log_no_delete BEFORE DELETE ON sensitive_access_log FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'sensitive_access_log is append-only';
END$$

-- A volunteer can choose at most three skills.
CREATE TRIGGER trg_volunteer_skill_max_three BEFORE INSERT ON volunteer_skill FOR EACH ROW
BEGIN
    IF (SELECT COUNT(*) FROM volunteer_skill WHERE volunteer_id = NEW.volunteer_id) >= 3 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'A volunteer can choose at most 3 skills';
    END IF;
END$$

-- The person who reviews an attendance batch cannot be the person who submitted it.
CREATE TRIGGER trg_attendance_batch_reviewer_not_submitter BEFORE UPDATE ON attendance_batch FOR EACH ROW
BEGIN
    DECLARE submitter_user CHAR(36);
    IF NEW.reviewer_id IS NOT NULL THEN
        SELECT v.user_id INTO submitter_user
          FROM duty_appointment d
          JOIN volunteer v ON v.volunteer_id = d.volunteer_id
         WHERE d.duty_id = NEW.duty_id;
        IF submitter_user = NEW.reviewer_id THEN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Reviewer cannot be the submitter of the batch';
        END IF;
    END IF;
END$$

DELIMITER ;

-- ---------------------------------------------------------------------
--  VIEWS (numbers worked out when a screen asks for them)
-- ---------------------------------------------------------------------

-- Volunteers per barangay: used by the admin hotspot map, the admin Dashboard
-- card, and the Barangay Focal Person dashboard and reports. Counts only.
CREATE VIEW v_barangay_volunteer_counts AS
SELECT b.barangay_id,
       b.name AS barangay_name,
       b.latitude,
       b.longitude,
       COALESCE(SUM(v.profile_status = 'approved'), 0) AS verified_count,
       COALESCE(SUM(v.profile_status IN ('draft','submitted','under_review','needs_correction')), 0) AS registered_not_verified_count,
       COALESCE(SUM(v.profile_status IN ('approved','draft','submitted','under_review','needs_correction')), 0) AS total_count
  FROM barangay b
  LEFT JOIN volunteer v ON v.barangay_id = b.barangay_id
 GROUP BY b.barangay_id, b.name, b.latitude, b.longitude;

-- Registrations waiting for review, with age in days and an overdue flag.
CREATE VIEW v_registration_review_queue AS
SELECT r.registration_id,
       r.volunteer_id,
       v.volunteer_code,
       r.status,
       r.submitted_at,
       DATEDIFF(NOW(), r.submitted_at) AS age_days,
       r.review_due_at,
       (r.review_due_at IS NOT NULL AND NOW() > r.review_due_at) AS is_overdue,
       r.assigned_reviewer_id
  FROM volunteer_registration r
  JOIN volunteer v ON v.volunteer_id = r.volunteer_id
 WHERE r.status IN ('submitted','under_review');

-- Attendance problems that are not yet resolved.
CREATE VIEW v_attendance_open_exceptions AS
SELECT * FROM attendance_exception WHERE status <> 'resolved';

-- Support tickets that are still open.
CREATE VIEW v_support_open_tickets AS
SELECT * FROM support_ticket WHERE status NOT IN ('resolved','closed');

-- The system health block on the admin Dashboard.
CREATE VIEW v_system_health AS
SELECT (SELECT COUNT(*) FROM delivery_log   WHERE status = 'failed')           AS failed_deliveries,
       (SELECT COUNT(*) FROM user_account   WHERE account_status = 'locked')   AS locked_accounts,
       (SELECT COUNT(*) FROM offline_sync_log WHERE status = 'failed')         AS failed_scanner_syncs;

-- Event Coordinator safety brief: foods to cater for and a yes/no medical-note
-- flag per activity. No names and no counts.
CREATE VIEW v_event_safety_brief AS
SELECT ap.activity_id,
       GROUP_CONCAT(DISTINCT ro.label ORDER BY ro.label SEPARATOR ', ') AS foods_to_cater_for,
       MAX(CASE WHEN rs.medical_considerations IS NOT NULL AND rs.medical_considerations <> '' THEN 1 ELSE 0 END) AS has_medical_note
  FROM activity_participant ap
  LEFT JOIN volunteer_food_restriction vf ON vf.volunteer_id = ap.volunteer_id
  LEFT JOIN reference_option ro ON ro.option_id = vf.option_id AND ro.option_code <> 'NONE'
  LEFT JOIN volunteer_restricted_safety rs ON rs.volunteer_id = ap.volunteer_id
 WHERE ap.assignment_status IN ('assigned','reassigned')
 GROUP BY ap.activity_id;


-- =====================================================================
--  SEED DATA
-- =====================================================================

-- Roles -----------------------------------------------------------------
INSERT INTO `role` (role_id, role_code, role_name, is_temporary_duty, description) VALUES
(UUID(), 'ADMIN',               'System Administrator',                 FALSE, 'Controls accounts, roles, settings, audit and the whole program.'),
(UUID(), 'PROGRAM_COORDINATOR', 'VACP Program Coordinator',             FALSE, 'Reviews registrations and activities and runs program operations.'),
(UUID(), 'ACTIVITY_COORDINATOR','Activity / Event Coordinator',         FALSE, 'Runs the assigned events from preparation to completion.'),
(UUID(), 'BARANGAY_FOCAL',      'Barangay Focal Person',                FALSE, 'Requests and coordinates volunteer activities for one barangay.'),
(UUID(), 'ORG_REP',             'Partner Organization Representative',  FALSE, 'Proposes and coordinates activities for one partner organization.'),
(UUID(), 'VOLUNTEER',           'Volunteer',                            FALSE, 'A person who registers, applies to activities and serves.'),
(UUID(), 'TEAM_LEADER',         'Volunteer Team Leader',                TRUE,  'Temporary duty to lead a team during one activity or session.'),
(UUID(), 'ATTENDANCE_STAFF',    'Attendance and Monitoring Staff',      TRUE,  'Temporary duty to record attendance during one session.');

-- Sustainable Development Goals ---------------------------------------
INSERT INTO sdg (sdg_id, sdg_no, title) VALUES
(UUID(), 1, 'No Poverty'),
(UUID(), 2, 'Zero Hunger'),
(UUID(), 3, 'Good Health and Well-Being'),
(UUID(), 4, 'Quality Education'),
(UUID(), 5, 'Gender Equality'),
(UUID(), 6, 'Clean Water and Sanitation'),
(UUID(), 7, 'Affordable and Clean Energy'),
(UUID(), 8, 'Decent Work and Economic Growth'),
(UUID(), 9, 'Industry, Innovation and Infrastructure'),
(UUID(), 10, 'Reduced Inequalities'),
(UUID(), 11, 'Sustainable Cities and Communities'),
(UUID(), 12, 'Responsible Consumption and Production'),
(UUID(), 13, 'Climate Action'),
(UUID(), 14, 'Life Below Water'),
(UUID(), 15, 'Life on Land'),
(UUID(), 16, 'Peace, Justice and Strong Institutions'),
(UUID(), 17, 'Partnerships for the Goals');

-- Sectors -----------------------------------------------------------
INSERT INTO sector (sector_id, name, requires_school_details, is_active) VALUES
(UUID(), 'In-School Youth', TRUE, TRUE),
(UUID(), 'Out-of-School Youth', FALSE, TRUE),
(UUID(), 'Young Professional / Entrepreneur / Formal Sector', FALSE, TRUE),
(UUID(), 'Person with Disability', FALSE, TRUE),
(UUID(), 'Solo Parent / Young Parent', FALSE, TRUE),
(UUID(), 'Farmer / Fisherfolk', FALSE, TRUE),
(UUID(), 'Indigenous People', FALSE, TRUE),
(UUID(), 'Transport / Tourism', FALSE, TRUE),
(UUID(), 'Other Informal Sector (vendors etc)', FALSE, TRUE);

-- Skills (a volunteer picks at most three) ---------------------------
INSERT INTO skill (skill_id, skill_code, name, is_active) VALUES
(UUID(), 'ADMINISTRATIVE', 'Administrative', TRUE),
(UUID(), 'COMMUNICATION_NEGOTIATION_WRITTEN_VERBAL', 'Communication / Negotiation (written, verbal)', TRUE),
(UUID(), 'CREATIVE_TALENT_FOR_EVENTS_HOSTING_PERFO', 'Creative talent for events (hosting, performing, etc)', TRUE),
(UUID(), 'EDUCATING_TEACHING', 'Educating / Teaching', TRUE),
(UUID(), 'EVENTS_MANAGEMENT', 'Events Management', TRUE),
(UUID(), 'FINANCE_ACCOUNTING', 'Finance / Accounting', TRUE),
(UUID(), 'GRAPHICS_DESIGN', 'Graphics Design', TRUE),
(UUID(), 'LOGISTICS', 'Logistics', TRUE),
(UUID(), 'MARKETING_MANAGEMENT', 'Marketing Management', TRUE),
(UUID(), 'MEDIA', 'Media', TRUE),
(UUID(), 'PRODUCTION_MANAGEMENT_FOR_EVENTS', 'Production Management for Events', TRUE),
(UUID(), 'PROJECT_BUSINESS_DEVELOPMENT', 'Project / Business Development', TRUE),
(UUID(), 'PHOTOGRAPHY_AND_VIDEO', 'Photography and Video', TRUE),
(UUID(), 'RESEARCH_AND_DOCUMENTATION', 'Research and Documentation', TRUE),
(UUID(), 'SOCIAL_MEDIA', 'Social Media', TRUE),
(UUID(), 'SOFTWARE_WEB_MOBILE_PROGRAMMING', 'Software / Web / Mobile Programming', TRUE),
(UUID(), 'VIDEO_EDITING', 'Video Editing', TRUE);

-- Fields of interest (the repeated Peer Counseling is kept once; Human
-- Rights and Human Rights and Advocacy overlap and can be merged later
-- with interest_field.merged_into_id) ---------------------------------
INSERT INTO interest_field (interest_id, name, is_active) VALUES
(UUID(), 'Agriculture and Fisheries', TRUE),
(UUID(), 'Animal Welfare', TRUE),
(UUID(), 'Anti-Illegal Drugs', TRUE),
(UUID(), 'Arts and Culture', TRUE),
(UUID(), 'Basic Life Support', TRUE),
(UUID(), 'Blood Donation (Voluntary)', TRUE),
(UUID(), 'Child Protection', TRUE),
(UUID(), 'Computers and Technology', TRUE),
(UUID(), 'Crisis Support', TRUE),
(UUID(), 'Disaster Risk Reduction & Management', TRUE),
(UUID(), 'Driving and Modes of Transportation', TRUE),
(UUID(), 'Education and Literacy', TRUE),
(UUID(), 'Emergency Response', TRUE),
(UUID(), 'Engineering and Architecture', TRUE),
(UUID(), 'Environment and Natural Resources', TRUE),
(UUID(), 'Events and Community Organizing', TRUE),
(UUID(), 'Food and Culinary Services', TRUE),
(UUID(), 'Food Security', TRUE),
(UUID(), 'Good Governance', TRUE),
(UUID(), 'Health and Medicine', TRUE),
(UUID(), 'Homeless and Housing', TRUE),
(UUID(), 'Human Rights', TRUE),
(UUID(), 'Human Rights and Advocacy', TRUE),
(UUID(), 'Human Trafficking', TRUE),
(UUID(), 'Immigrants and Refugees', TRUE),
(UUID(), 'Indigenous People, Race and Ethnicity', TRUE),
(UUID(), 'Information Database Systems', TRUE),
(UUID(), 'International Volunteering', TRUE),
(UUID(), 'Justice and Legal', TRUE),
(UUID(), 'Juvenile Justice and Welfare', TRUE),
(UUID(), 'LGBT Rights and Welfare', TRUE),
(UUID(), 'Media and Broadcasting', TRUE),
(UUID(), 'Organizational/Board Development', TRUE),
(UUID(), 'Parenting and Family Planning', TRUE),
(UUID(), 'Peace and Order', TRUE),
(UUID(), 'Peer Counseling', TRUE),
(UUID(), 'Persons with Special Needs', TRUE),
(UUID(), 'Politics', TRUE),
(UUID(), 'Psychosocial Interventions', TRUE),
(UUID(), 'Senior Citizens', TRUE),
(UUID(), 'Social Media and Advocacy', TRUE),
(UUID(), 'Solid Waste Management', TRUE),
(UUID(), 'Sports and Recreation', TRUE),
(UUID(), 'Tourism', TRUE),
(UUID(), 'Veterans and Military Families', TRUE),
(UUID(), 'Volunteering Advocacy', TRUE),
(UUID(), 'Women Development', TRUE),
(UUID(), 'Youth Employment & Entrepreneurship', TRUE),
(UUID(), 'Zoning and Urban Development', TRUE);

-- Approved option lists taken from the current Google Form. The lists for
-- Sex, Civil Status, Education and Availability are NOT seeded because the
-- client has not confirmed their values. EVO-only answers are loaded but
-- switched off (is_client_approved and is_active are FALSE).
INSERT INTO reference_option (option_id, list_code, option_code, label, sort_order, is_client_approved, is_active) VALUES
(UUID(), 'SUFFIX', 'JR', 'Jr.', 1, TRUE, TRUE),
(UUID(), 'SUFFIX', 'SR', 'Sr.', 2, TRUE, TRUE),
(UUID(), 'SUFFIX', 'I', 'I', 3, TRUE, TRUE),
(UUID(), 'SUFFIX', 'II', 'II', 4, TRUE, TRUE),
(UUID(), 'SUFFIX', 'III', 'III', 5, TRUE, TRUE),
(UUID(), 'SUFFIX', 'NONE', 'None', 6, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'NONE', 'None', 1, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'ALCOHOLIC_BEVERAGES', 'Alcoholic Beverages', 2, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'BEEF', 'Beef', 3, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'BEER_MALTED_PRODUCTS', 'Beer (Malted products)', 4, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'BUTTER', 'Butter', 5, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'CHEESE', 'Cheese', 6, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'CHICKEN_POULTRY', 'Chicken (Poultry)', 7, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'COFFEE', 'Coffee', 8, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'CRABS', 'Crabs', 9, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'EGGS', 'Eggs', 10, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'GELATIN_JELLY', 'Gelatin (Jelly)', 11, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'LARD', 'Lard', 12, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'MARGARINE', 'Margarine', 13, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'MILK', 'Milk', 14, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'PEANUT', 'Peanut', 15, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'PORK', 'Pork', 16, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'PRAWN_SHRIMPS', 'Prawn (Shrimps)', 17, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'SHELLFISH', 'Shellfish', 18, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'SOFT_DRINKS_COLA', 'Soft drinks (Cola)', 19, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'SOY', 'Soy', 20, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'SPICY_FOOD', 'Spicy Food', 21, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'TEA', 'Tea', 22, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'TREE_NUTS_CASHEWS_WALNUTS', 'Tree Nuts (Cashews, walnuts)', 23, TRUE, TRUE),
(UUID(), 'FOOD_RESTRICTION', 'WHEAT', 'Wheat', 24, TRUE, TRUE),
(UUID(), 'REFERRAL', 'XU_NSTP_EVO_COMMUNITY_SERVICE', 'XU-NSTP - EVO Community Service', 1, TRUE, TRUE),
(UUID(), 'REFERRAL', 'FRIEND_RELATIVE', 'Friend / Relative', 2, TRUE, TRUE),
(UUID(), 'REFERRAL', 'SOCIAL_MEDIA', 'Social Media', 3, TRUE, TRUE),
(UUID(), 'REFERRAL', 'RADIO', 'Radio', 4, TRUE, TRUE),
(UUID(), 'REFERRAL', 'TELEVISION', 'Television', 5, TRUE, TRUE),
(UUID(), 'REFERRAL', 'PRINTED_MEDIA_NEWSPAPER_TABLOID', 'Printed Media - Newspaper / Tabloid', 6, TRUE, TRUE),
(UUID(), 'REFERRAL', 'PRINTED_MEDIA_MAGAZINE', 'Printed Media - Magazine', 7, TRUE, TRUE),
(UUID(), 'REFERRAL', 'PRINTED_MEDIA_NEWSLETTER', 'Printed Media - Newsletter', 8, TRUE, TRUE),
(UUID(), 'REFERRAL', 'PHONE_CALL', 'Phone Call', 9, TRUE, TRUE),
(UUID(), 'REFERRAL', 'TEXT_SMS', 'Text / SMS', 10, TRUE, TRUE),
(UUID(), 'REFERRAL', 'E_MAIL', 'E-mail', 11, TRUE, TRUE),
(UUID(), 'REFERRAL', 'MAIL_POSTAL_COMMUNICATION', 'Mail / Postal Communication', 12, TRUE, TRUE),
(UUID(), 'PROGRAM_RESPONSE', 'YES_DEFINITELY', 'Yes, definitely!', 1, FALSE, FALSE),
(UUID(), 'PROGRAM_RESPONSE', 'THANK_YOU_I_LL_LET_YOU_KNOW', 'Thank you! I''ll let you know', 2, FALSE, FALSE),
(UUID(), 'PROGRAM_RESPONSE', 'YES_I_AM_OPEN_TO_FORM_A_CHAPTER_AND_WILL', 'Yes, I am open to form a chapter and willing to take up interim leadership', 3, FALSE, FALSE),
(UUID(), 'PROGRAM_RESPONSE', 'YES_I_AM_OPEN_TO_FORM_A_CHAPTER_BUT_I_RE', 'Yes, I am open to form a chapter but I require more information', 4, FALSE, FALSE),
(UUID(), 'PROGRAM_RESPONSE', 'I_AM_WILLING_TO_JOIN_AN_EXISTING_EVO_CHA', 'I am willing to join an existing EVO chapter near me', 5, FALSE, FALSE),
(UUID(), 'PROGRAM_RESPONSE', 'I_AM_UNDECIDED_AS_OF_THE_MOMENT', 'I am undecided as of the moment', 6, FALSE, FALSE);

-- Registration routes ---------------------------------------------------
INSERT INTO registration_route (route_id, route_code, label, is_enabled, is_client_confirmed) VALUES
(UUID(), 'NEW_REGISTRATION',   'New Registration',          TRUE,  TRUE),
(UUID(), 'UPDATE_PAST_ENTRY',  'Update Past Entry',         TRUE,  TRUE),
(UUID(), 'VILLAGE_VOLUNTEER',  'Sonampat Village Volunteer',FALSE, FALSE);

-- First administrator --------------------------------------------------
-- Created as "invited" with no password, so there is no default login.
-- Change the email, then send the invitation to set a password.
SET @admin_id = UUID();
INSERT INTO user_account (user_id, email, display_name, account_status)
VALUES (@admin_id, 'admin@example.com', 'System Administrator', 'invited');

INSERT INTO user_role (user_role_id, user_id, role_id, granted_by, granted_at)
SELECT UUID(), @admin_id, role_id, @admin_id, NOW() FROM `role` WHERE role_code = 'ADMIN';


INSERT INTO system_setting (setting_id, setting_key, setting_value, value_type, description, updated_by) VALUES
(UUID(), 'TIMEZONE',             'Asia/Manila', 'string', 'Time zone used for all dates and times.', @admin_id),
(UUID(), 'REPORT_MIN_COUNT',     '5',           'number', 'Counts below this number are shown as fewer than 5 in reports.', @admin_id),
(UUID(), 'QR_TOKEN_TTL_MINUTES', '720',         'number', 'How long an event pass QR code stays valid (suggested default).', @admin_id),
(UUID(), 'DUTY_GRACE_MINUTES',   '30',          'number', 'Minutes after a duty ends when unfinished reports or batches can still be submitted (suggested default).', @admin_id);
