rule anonymous_user_changed_machine_password {
    meta:
        description = "Identifies anon user changing machine password. Need to combine with 4624/5829"
        reference = "https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc"
       
    events:
        $selection2.metadata.product_log_id = "4742"
        re.regex($selection2.src.user.userid, `S-1-0`)
        re.regex($selection2.target.user.user_display_name, `$`)

    condition:
        $selection2
}
