export const QUICK_SITES = [
  { label: '百度', host: 'www.baidu.com' },
  { label: '淘宝', host: 'www.taobao.com' },
  { label: '腾讯', host: 'www.qq.com' },
] as const

export type QuickHost = (typeof QUICK_SITES)[number]['host']

/** A chip only fills the existing site field. Unknown hosts, including Google, are refused. */
export function quickHost(host: string): QuickHost | null {
  const found = QUICK_SITES.find((site) => site.host === host)
  return found ? found.host : null
}

/** Empty input still means the default sample, www.baidu.com. */
export function chipSelected(site: string, host: QuickHost): boolean {
  const value = site.trim().toLowerCase()
  if (value === host) return true
  return value === '' && host === 'www.baidu.com'
}
