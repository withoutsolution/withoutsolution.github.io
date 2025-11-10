export const sidebar = {
  '/linux/': [
    {
      text: 'linux',
      collapsed: true,
      items: [
        { text: 'linuxCommands', link: '/linux/linuxCommands.md' },
        { text: 'vscode相关命令', link: '/linux/vscode相关命令.md' },
        { text: 'go linux相关操作', link: '/linux/golinux相关操作.md' },
        { text: 'Git相关命令操作', link: '/linux/Git相关命令操作.md' },
        { text: 'archlinux应用', link: '/linux/archlinuxApp.md' },
        { text: 'linux基础', link: '/linux/LinuxFundamentals.md' },
        { text: 'linux shells', link: '/linux/LinuxShell.md' },
      ]
    }
  ],
  '/docker/': [
    {
      text: 'docker',
      collapsed: false,
      items: [
        { text: 'docker基础', link: '/docker/docker基础.md' },
        { text: 'docker进阶', link: '/docker/docker进阶.md' },
        { text: 'docker应用', link: '/docker/dockerApp.md' },
      ]
    }
  ],
  '/go/': [
    {
      text: 'go',
      collapsed: true,
      items: [
        { text: 'go issues', link: '/go/goIssues.md' },
        { text: 'go algo', link: '/go/goAlgo.md' },
        { text: 'goBasics', link: '/go/go基础.md' },
        { text: 'goPro', link: '/go/go进阶.md' },
      ]
    }
  ],
  '/windows/': [
    {
      text: 'windows',
      collapsed: true,
      items: [
        { text: 'windows常用命令', link: '/windows/WindowsCommand.md' },
        { text: 'windows基础', link: '/windows/WindowsFundamentals.md' },
      ]
    }
  ]
}