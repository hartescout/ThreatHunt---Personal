rule BDS_TEST_XMRminingPools {
  
  meta:    
    author = "@is_henderson"
    date = "25 October 2021"
    description = "Monero has few mining pools available for cryptominers such as XMRrig to use. Included are various and not all known XMR mining binaries."
    reference = "https://www.nextron-systems.com/2021/10/24/monero-mining-pool-fqdns/"
    severity = "High - Traffic is targeted."

  events:    
    $e.metadata.event_type = "NETWORK_CONNECTION" or
    $e.metadata.event_type = "NETWORK_DNS"
    (
        $e.target.url = /^.*\.minexmr\.com.*$/ nocase or
        $e.target.url = /^.*\.supporminexmr\.com.*$/ nocase or
        $e.target.url = /^.*\.c3pool\.com.*$/ nocase or
        $e.target.url = /^.*\.nanopool\.org.*$/ nocase or
        $e.target.url = /^.*\.2miners\.com.*$/ nocase or
        $e.target.url = /^.*\.hashcity\.org.*$/ nocase or
        $e.target.url = /^.*\.f2pool\.com.*$/ nocase or
        $e.target.url = /^.*\.xmrpool\.eu.*$/ nocase or
        $e.target.url = /^.*\.hashvault\.pro.*$/ nocase
    )
    or
    $e.metadata.event_type = "PROCESS_LAUNCH"
    (        
        $e.target.process.file.full_path = /^nanominer.*$/ nocase or
        $e.target.process.command_line = /^nanominer.*$/ nocase or 
        $e.target.process.file.full_path = /^xmrig.*$/ nocase or
        $e.target.process.command_line = /^xmrig.*$/ nocase or
        $e.target.process.file.full_path = /^excavator.*$/ nocase or
        $e.target.process.command_line = /^excavator.*$/ nocase or
        $e.target.process.file.full_path = /^NiceHashQuickMiner.*$/ nocase or
        $e.target.process.command_line = /^NiceHashQuickMiner.*$/ nocase or
        $e.target.process.file.full_path = /^SRBMiner.*$/ nocase or
        $e.target.process.command_line = /^SRBMiner.*$/ nocase or
        $e.target.process.file.full_path = /^xmr-stak-rx.*$/ nocase or
        $e.target.process.command_line = /^xmr-stak-rx.*$/
    )    

  condition:
    $e
}
