Output "/Users/alukach/.claude/jobs/7cb421d2/tmp/demo/out/member-list.gif"
Source "/Users/alukach/.claude/jobs/7cb421d2/tmp/demo/tapes/header.tape"
Hide
Type "export PATH=/Users/alukach/.claude/jobs/7cb421d2/tmp/demo/bin:$PATH SOURCE_API_URL=http://127.0.0.1:4101 SOURCE_TOKEN=demo PAGER=cat PS1='$ ' && cd /Users/alukach/.claude/jobs/7cb421d2/tmp/demo/work && clear"
Enter
Sleep 300ms
Show
Type "source-coop member list acme-lab"
Enter
Sleep 1.5s
Type "source-coop member list acme-lab/climate-data"
Enter
Sleep 1.5s
Type "source-coop member list acme-lab --state invited"
Enter
Sleep 1.5s
Type "source-coop member list acme-lab --json | jq -c '.[] | {account_id, role, state}'"
Enter
Sleep 2s
Sleep 3s
