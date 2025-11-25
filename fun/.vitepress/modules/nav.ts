export const nav = [
  { text: 'Home', link: '/' },
  {
    text: 'cyber',
    items: [
      {
        items: [
          { text: 'Web', link: '/cyber/web.md' },
          { text: 'network', link: '/cyber/network.md' },
          { text: 'networkpro', link: '/cyber/networkpro.md' },
        ]
      },
      {
        items: [
          { text: 'webapp', link: '/cyber/WebApplication.md' },
          { text: 'Authentication', link: '/webapp/Authentication.md' },
          { text: 'Injection Attacks', link: '/webapp/InjectionAttacks.md' },
          { text: 'Advanced Server-Side Attacks', link: '/webapp/ServerSideAttacks.md' },
          { text: 'Advanced Client-Side Attacks', link: '/webapp/ClientSideAttacks.md' },
          { text: 'HTTP Request Smuggling', link: '/webapp/HTTPRequestSmuggling.md' },
        ]
      },
    ]
  },
  {
    text: 'security',
    items: [
      {
        items: [
          { text: 'Tools', link: '/cyber/tools.md' },
          { text: 'metasploit', link: '/security/Metasploit.md' },
          { text: 'burpSuite', link: '/security/BurpSuite.md' },
          { text: 'wireshark', link: '/security/wireshark.md' },
          { text: 'tcpdump', link: '/security/tcpdump.md' },
          { text: 'bruteforcingtools', link: '/security/bruteforcingtools.md' },
          { text: 'offensivetools', link: '/security/offensivetools.md' },
          { text: 'defensivetools', link: '/security/defensivetools.md' },
        ]
      },
      {
        items: [
          { text: 'Crypto', link: '/cyber/cryptography.md' },
          { text: 'john the Ripper', link: '/security/john.md' },
        ]
      },
    ]
  },
  {
    text: 'with',
    items: [
      {
        items: [
          { text: 'Skills', link: '/cyber/skills.md' },
          { text: 'SRC', link: '/srcdiary/srcskills.md' },
          { text: 'shells', link: '/cyber/shells.md' },
          { text: 'web pentesting', link: '/security/webpentesting.md' },
          { text: 'network security', link: '/cyber/networksecurity.md' },
          { text: 'vulnerability research', link: '/security/vulnerabilityResearch.md' },
          {
            text: 'privilege escalation', link: '/security/privilegeEscalation.md'
          }
        ]
      },
      {
        items: [
          { text: 'Red', link: '/Red/Red.md' },
          { text: 'Initial Access', link: '/Red/InitialAccess.md' },
          { text: 'Post Compromise', link: '/Red/PostCompromise.md' },
          { text: 'Host Evasions', link: '/Red/HostEvasions.md' },
          { text: 'Network Security Evasion', link: '/Red/NetworkSecurityEvasion.md' },
          { text: 'Compromising Active Directory', link: '/Red/CompromisingActiveDirectory.md' },
        ]
      },
    ]
  },
  {
    text: 'linux',
    items: [
      { text: 'commands', link: '/linux/linuxCommands.md' },
      { text: 'kali', link: '/linux/kali.md' },
      { text: 'shells', link: '/linux/LinuxShell.md' },
      { text: 'arch', link: '/linux/archlinuxApp.md' },
    ]
  },
  // {
  //   text: 'go',
  //   items: [
  //     { text: 'go issues', link: '/go/goIssues.md' },
  //     { text: 'go algo', link: '/go/goAlgo.md' },
  //     { text: 'goBasics', link: '/go/go基础.md' },
  //     { text: 'goPro', link: '/go/go进阶.md' },
  //   ]
  // },
  {
    component: 'MusicPlayer',
    // 可选的 props 传递给组件
    props: {
      title: 'MusicPlayer'
    }
  },
]