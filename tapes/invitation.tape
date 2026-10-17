Output "/Users/alukach/.claude/jobs/7cb421d2/tmp/demo/out/invitation.gif"
Source "/Users/alukach/.claude/jobs/7cb421d2/tmp/demo/tapes/header.tape"
Hide
Type "export PATH=/Users/alukach/.claude/jobs/7cb421d2/tmp/demo/bin:$PATH SOURCE_API_URL=http://127.0.0.1:4108 SOURCE_TOKEN=demo PAGER=cat PS1='$ ' && cd /Users/alukach/.claude/jobs/7cb421d2/tmp/demo/work && clear"
Enter
Sleep 300ms
Show
Type "source-coop invitation list"
Enter
Sleep 1.5s
Type "source-coop invitation accept geo-commons"
Enter
Sleep 1.5s
Type "source-coop invitation reject river-sensors"
Enter
Sleep 1.5s
Type "source-coop invitation list --json | jq -c '.[] | {membership_account_id, repository_id, role}'"
Enter
Sleep 2.5s
Sleep 3s
