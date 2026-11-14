import { useEffect, useRef, useState } from 'react'
import { invoke } from '@tauri-apps/api/core'

type Hop = {
  id: string
  name: string
  mark: string
  number: number
  unit: string
  detail: string
}

type WanHop = {
  ttl: number
  ip: string
  ms: number
  loss: number
  kind: string
  asn: string
  asn_name: string
  note: string
}

type WanCard = {
  hops: WanHop[]
  nat: string
  https: string
  https_kind: string
  path: string
}

type Playbook = {
  id: string
  look_at: string[]
  check_first: string
  never_auto: string[]
}

type Chain = {
  hops: Hop[]
  conclusion: string
  next: string
  problem_id: string
  wan: WanCard
  playbook: Playbook | null
}

const ORDER: Hop[] = [
  { id: 'computer', name: '这台电脑', mark: '', number: 0, unit: '', detail: '' },
  { id: 'nic', name: '网卡', mark: '', number: 0, unit: '', detail: '' },
  { id: 'router', name: '路由器', mark: '', number: 0, unit: '', detail: '' },
  { id: 'dns', name: 'DNS', mark: '', number: 0, unit: '', detail: '' },
  { id: 'proxy', name: '代理', mark: '', number: 0, unit: '', detail: '' },
  { id: 'wan', name: '外网', mark: '', number: 0, unit: '', detail: '' },
]

const KEEP = 16
const GAP_MS = 6000
const SITE_KEY = 'lanwatch.wan.site'

function noteKey(id: string) {
  return `lanwatch.note.${id}`
}

function hopTitle(hop: WanHop) {
  return [hop.ip, hop.asn, hop.asn_name].filter(Boolean).join(' ')
}

function watchedLabel(ms: number) {
  const total = Math.max(0, Math.floor(ms / 1000))
  if (total < 60) return `已看 ${total} 秒`
  const minutes = Math.floor(total / 60)
  if (minutes < 60) {
    const seconds = total % 60
    return seconds === 0 ? `已看 ${minutes} 分钟` : `已看 ${minutes} 分 ${seconds} 秒`
  }
  const hours = Math.floor(minutes / 60)
  const rest = minutes % 60
  return rest === 0 ? `已看 ${hours} 小时` : `已看 ${hours} 小时 ${rest} 分`
}

export default function App() {
  const [chain, setChain] = useState<Chain | null>(null)
  const [failed, setFailed] = useState(false)
  const [dim, setDim] = useState(true)
  const [note, setNote] = useState('')
  const [ticks, setTicks] = useState<Record<string, string[]>>({})
  const [startedAt, setStartedAt] = useState<number | null>(null)
  const [now, setNow] = useState(() => Date.now())
  const [site, setSite] = useState('')
  const hadResult = useRef(false)
  const running = useRef(false)
  const again = useRef(false)
  const timer = useRef<number | null>(null)
  const history = useRef<Record<string, string[]>>({})
  const siteRef = useRef('')

  function clearTimer() {
    if (timer.current != null) {
      window.clearTimeout(timer.current)
      timer.current = null
    }
  }

  function remember(next: Chain) {
    const map = { ...history.current }
    for (const hop of next.hops) {
      const prev = map[hop.id] ?? []
      map[hop.id] = [...prev, hop.mark].slice(-KEEP)
    }
    history.current = map
    setTicks(map)
  }

  function schedule() {
    clearTimer()
    timer.current = window.setTimeout(() => {
      void run(false)
    }, GAP_MS)
  }

  async function run(manual: boolean) {
    if (running.current) {
      if (manual) again.current = true
      return
    }
    running.current = true
    clearTimer()
    if (manual || !hadResult.current) setDim(true)
    try {
      const next = await invoke<Chain>('read_chain', { site: siteRef.current })
      hadResult.current = true
      setStartedAt((at) => at ?? Date.now())
      setFailed(false)
      setChain(next)
      remember(next)
    } catch {
      if (!hadResult.current) setFailed(true)
    } finally {
      running.current = false
      setDim(false)
      if (again.current) {
        again.current = false
        void run(true)
      } else {
        schedule()
      }
    }
  }

  function rememberSite(value: string) {
    const next = value.trim()
    siteRef.current = next
    setSite(next)
    try {
      localStorage.setItem(SITE_KEY, next)
    } catch {
      /* the field still shows what was typed */
    }
  }

  useEffect(() => {
    try {
      const saved = localStorage.getItem(SITE_KEY) ?? ''
      setSite(saved)
      siteRef.current = saved.trim()
    } catch {
      siteRef.current = ''
    }
    void run(true)
    const clock = window.setInterval(() => setNow(Date.now()), 1000)
    return () => {
      clearTimer()
      window.clearInterval(clock)
    }
  }, [])

  const problemId = chain?.problem_id ?? ''

  useEffect(() => {
    if (!problemId) {
      setNote('')
      return
    }
    try {
      setNote(localStorage.getItem(noteKey(problemId)) ?? '')
    } catch {
      setNote('')
    }
  }, [problemId])

  function onNote(value: string) {
    setNote(value)
    if (!problemId) return
    try {
      localStorage.setItem(noteKey(problemId), value)
    } catch {
      /* the slip still shows what was typed */
    }
  }

  const hops = chain?.hops?.length ? chain.hops : ORDER
  const conclusion = failed ? '这次没测成。' : (chain?.conclusion ?? '正在从这台电脑往外看。')
  const next = failed ? '再测一次。' : (chain?.next ?? '')

  return (
    <main aria-busy={dim}>
      <header className="verdict">
        <h1 className="conclusion">{conclusion}</h1>
        {startedAt != null ? <p className="watched">{watchedLabel(now - startedAt)}</p> : null}
      </header>
      <ol className="chain" data-busy={dim && chain ? 'true' : 'false'}>
        {hops.map((hop) => {
          const problem = hop.id === problemId && problemId !== ''
          const marks = ticks[hop.id] ?? []
          return (
            <li
              className="hop"
              key={hop.id}
              data-mark={hop.mark || undefined}
              data-problem={problem ? 'true' : 'false'}
            >
              <span className="dot" />
              <span className="name">{hop.name}</span>
              {chain && hop.detail ? <span className="detail">{hop.detail}</span> : null}
              <span className="trend" aria-hidden="true">
                {marks.map((mark, index) => (
                  <i key={`${hop.id}-${index}`} data-mark={mark} />
                ))}
              </span>
              <span className="mark">{hop.mark}</span>
              <span className="num">
                {chain && hop.mark ? (
                  <>
                    {hop.number}
                    {hop.unit ? <span className="unit">{hop.unit}</span> : null}
                  </>
                ) : null}
              </span>
              {hop.id === 'wan' && chain?.wan ? (
                <div className="wan-block">
                  {chain.wan.hops.length > 0 ? (
                    <div className="wan-strip">
                      {chain.wan.path ? <span className="scope">{chain.wan.path}</span> : null}
                      <ol className="wan-path" aria-label="每一跳的时间和丢包">
                        {chain.wan.hops.map((step) => {
                          const title = hopTitle(step)
                          const answered = step.kind === 'ok' || step.kind === 'loss'
                          return (
                            <li
                              className="wan-hop"
                              key={`${step.ttl}-${step.ip}`}
                              data-kind={step.kind}
                              title={title || undefined}
                            >
                              <span className="ttl">{step.ttl}</span>
                              <span className="ms">{answered ? step.ms : '—'}</span>
                              {step.note ? <span className="hop-note">{step.note}</span> : null}
                            </li>
                          )
                        })}
                      </ol>
                    </div>
                  ) : null}
                  {chain.wan.nat ? <p className="wan-fact">{chain.wan.nat}</p> : null}
                  {chain.wan.https ? (
                    <p className="wan-fact" data-kind={chain.wan.https_kind}>
                      {chain.wan.https}
                    </p>
                  ) : null}
                  <input
                    className="note site"
                    value={site}
                    maxLength={253}
                    placeholder="打不开的网址"
                    aria-label="要核对证书的网址"
                    autoComplete="off"
                    spellCheck={false}
                    onChange={(event) => setSite(event.target.value)}
                    onBlur={(event) => {
                      const next = event.currentTarget.value.trim()
                      const changed = next !== siteRef.current
                      const button = (event.relatedTarget as HTMLElement | null)?.id === 'again'
                      rememberSite(event.currentTarget.value)
                      if (changed && !button) void run(true)
                    }}
                    onKeyDown={(event) => {
                      if (event.key !== 'Enter') return
                      event.preventDefault()
                      rememberSite(event.currentTarget.value)
                      event.currentTarget.blur()
                      void run(true)
                    }}
                  />
                </div>
              ) : null}
              {problem ? (
                <input
                  className="note"
                  value={note}
                  maxLength={48}
                  placeholder="补一句"
                  aria-label="补在这一段上的一句话"
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(event) => onNote(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter') event.currentTarget.blur()
                  }}
                />
              ) : null}
            </li>
          )
        })}
      </ol>
      <div className="action">
        <p className="next">{next}</p>
        {chain?.playbook ? (
          <section className="playbook" aria-label="这一步怎么看">
            <p>
              <span>看</span>
              {chain.playbook.look_at.join('，')}
            </p>
            <p>
              <span>不要</span>
              {chain.playbook.never_auto.join('，')}
            </p>
          </section>
        ) : null}
        <button
          id="again"
          type="button"
          onClick={() => {
            rememberSite(site)
            void run(true)
          }}
          disabled={dim}
        >
          {dim ? '正在测' : '再测一次'}
        </button>
        <p className="domains">lanwatch.cn · lanwatch.net</p>
      </div>
    </main>
  )
}
