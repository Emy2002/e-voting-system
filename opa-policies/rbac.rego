package rbac

default allow = false

roles = {
    "voter": [
        "vote",
        "view_own_status",
        "update_address"
    ],
    "aec_employee": [
        "register_voters",
        "view_voter_list",
        "view_own_status"
    ],
    "administrator": [
        "manage_users",
        "view_audit_logs",
        "configure_system",
        "register_voters",
        "view_voter_list"
    ],
    "commissioner": [
        "manage_candidates",
        "manage_elections",
        "view_results",
        "view_audit_logs"
    ]
}

allow {
    input.role != null
    input.permission != null
    roles[input.role][_] == input.permission
}
