export interface Env {
  SUBSCRIBE_KV: KVNamespace
  RESEND_API_KEY: string
  TURNSTILE_SECRET_KEY: string
}

const RESEND_FROM = 'Devmini <noreply@devmini.space>'
const CODE_EXPIRE_SEC = 300
const RATE_LIMIT_SEC = 300
const MAX_VERIFY_ATTEMPTS = 3

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  }
}

function json(status: number, body: object) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() }
  })
}

async function verifyTurnstile(token: string, secretKey: string): Promise<boolean> {
  try {
    const params = new URLSearchParams({ secret: secretKey, response: token })
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: params
    })
    const data = await res.json() as { success: boolean }
    return data.success === true
  } catch {
    return false
  }
}

function generateCode(): string {
  return Math.floor(100000 + Math.random() * 900000).toString()
}

async function sendVerificationEmail(email: string, code: string, apiKey: string): Promise<void> {
  const { Resend } = await import('resend')
  const resend = new Resend(apiKey)

  const html = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif">
  <div style="max-width:480px;margin:40px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)">
    <div style="background:linear-gradient(135deg,#F5A623,#FF8C00);padding:24px 32px;text-align:center">
      <div style="font-size:28px;font-weight:bold;color:#fff;letter-spacing:2px">📬 devmini</div>
    </div>
    <div style="padding:28px 32px">
      <p style="font-size:16px;color:#333;margin:0 0 20px">你好，</p>
      <p style="font-size:16px;color:#333;margin:0 0 24px">你的订阅验证码是：</p>
      <div style="text-align:center;margin:24px 0">
        <span style="display:inline-block;font-size:36px;font-weight:bold;color:#F5A623;letter-spacing:8px;border:2px dashed #F5A623;border-radius:8px;padding:12px 24px">${code}</span>
      </div>
      <p style="font-size:13px;color:#999;margin:0">验证码 5 分钟内有效，请勿泄露给他人。</p>
      <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
      <p style="font-size:12px;color:#bbb;margin:0">如果你没有请求验证码，请忽略此邮件。</p>
    </div>
  </div>
</body>
</html>`

  await resend.emails.send({
    from: RESEND_FROM,
    to: email,
    subject: '📬 你的 devmini 订阅验证码',
    html,
  })
}

async function handleRequestCode(req: Request, env: Env): Promise<Response> {
  let body: { email?: string; turnstileToken?: string }
  try {
    body = await req.json()
  } catch {
    return json(400, { success: false, error: '请求格式错误' })
  }

  const { email, turnstileToken } = body

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json(400, { success: false, error: '邮箱格式不正确' })
  }

  if (!turnstileToken) {
    return json(403, { success: false, error: '人机验证未通过' })
  }

  const turnstileValid = await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET_KEY)
  if (!turnstileValid) {
    return json(403, { success: false, error: '人机验证失败，请刷新页面重试' })
  }

  const kv = env.SUBSCRIBE_KV
  const rateKey = `rate:${email}`

  try {
    const existing = await kv.get(rateKey)
    if (existing) {
      const meta = await kv.getWithMetadata(rateKey)
      const ttl = meta.metadata?.expiry ? Number(meta.metadata.expiry) : 0
      const left = Math.ceil((ttl - Date.now()) / 1000)
      return json(429, { success: false, error: `请 ${Math.max(1, left)} 秒后再试`, retryAfter: Math.max(1, left) })
    }
  } catch (e) {
    console.error('KV get rate error:', e)
    return json(500, { success: false, error: '服务暂不可用，请稍后重试' })
  }

  const code = generateCode()

  try {
    await Promise.all([
      kv.put(`code:${email}`, code, { expirationTtl: CODE_EXPIRE_SEC }),
      kv.put(`attempts:${email}`, '0', { expirationTtl: CODE_EXPIRE_SEC }),
      kv.put(rateKey, '1', { expirationTtl: RATE_LIMIT_SEC }),
    ])
  } catch (e) {
    console.error('KV put error:', e)
    return json(500, { success: false, error: '服务暂不可用，请稍后重试' })
  }

  try {
    await sendVerificationEmail(email, code, env.RESEND_API_KEY)
  } catch (e) {
    console.error('Resend error:', e)
    return json(500, { success: false, error: '邮件发送失败，请稍后重试' })
  }

  return json(200, { success: true, message: '验证码已发送，请查收邮件' })
}

async function handleSubscribe(req: Request, env: Env): Promise<Response> {
  let body: { email?: string; code?: string }
  try {
    body = await req.json()
  } catch {
    return json(400, { success: false, error: '请求格式错误' })
  }

  // Only accept email + code, no turnstile token needed (already verified at request-code step)
  const { email, code } = body

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json(400, { success: false, error: '邮箱格式不正确' })
  }

  if (!code || code.length !== 6) {
    return json(400, { success: false, error: '验证码格式错误' })
  }

  const kv = env.SUBSCRIBE_KV
  const codeKey = `code:${email}`
  const attemptsKey = `attempts:${email}`

  let stored: string | null
  try {
    stored = await kv.get(codeKey)
  } catch (e) {
    console.error('KV read code error:', e)
    return json(500, { success: false, error: '服务暂不可用，请稍后重试' })
  }

  if (!stored) {
    return json(400, { success: false, error: '验证码已过期，请重新获取' })
  }

  if (stored !== code) {
    let attempts = 0
    try {
      const attemptsStr = await kv.get(attemptsKey)
      attempts = parseInt(attemptsStr || '0', 10)
    } catch { /* ignore */ }

    const newAttempts = attempts + 1
    if (newAttempts >= MAX_VERIFY_ATTEMPTS) {
      try {
        await Promise.all([kv.delete(codeKey), kv.delete(attemptsKey)])
      } catch { /* ignore */ }
      return json(400, { success: false, error: '验证失败次数过多，请重新获取验证码' })
    }
    try {
      await kv.put(attemptsKey, String(newAttempts), { expirationTtl: CODE_EXPIRE_SEC })
    } catch { /* ignore */ }
    return json(400, { success: false, error: `验证码错误，剩余 ${MAX_VERIFY_ATTEMPTS - newAttempts} 次` })
  }

  try {
    await Promise.all([kv.delete(codeKey), kv.delete(attemptsKey)])
  } catch { /* ignore */ }

  // Add to Resend segment
  try {
    const { Resend } = await import('resend')
    const resend = new Resend(env.RESEND_API_KEY)
    await resend.contacts.create({
      email: email,
      segments: [{ id: '0d91d539-9540-4cba-8554-c80cfd443b2e' }],
      unsubscribed: false,
    })
  } catch (e: any) {
    // Silently ignore duplicate contact (409) — user is already subscribed
    const msg = e?.message || ''
    if (!msg.includes('409') && !msg.includes('already exists')) {
      console.error('Resend contact create error:', e)
    }
  }

  // Send welcome email directly from Worker
  try {
    const { Resend } = await import('resend')
    const resend = new Resend(env.RESEND_API_KEY)
    const html = `<!DOCTYPE html>
<html><body style="font-family:-apple-system,BlinkMacSystemFont,sans-serif;max-width:600px;margin:0 auto;background:#f5f5f5;">
  <div style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);padding:32px 24px;text-align:center;">
    <div style="font-size:28px;margin-bottom:8px;">🌟</div>
    <h1 style="color:#ffffff;margin:0;font-size:24px;font-weight:700;">欢迎订阅 devmini</h1>
    <p style="color:rgba(255,255,255,0.75);margin:8px 0 0;font-size:14px;">免费优质资源推荐 · 每周一更新</p>
  </div>
  <div style="padding:28px 24px;background:#ffffff;">
    <p style="margin:0 0 20px;font-size:18px;font-weight:600;color:#2d2d2d;line-height:1.6;">你好呀 👋 感谢订阅！</p>
    <p style="margin:0 0 20px;font-size:15px;color:#555;line-height:1.85;">我们持续挖掘真正好用、免费、有价值的资源——工具网站、学习课程，开发资源，以及各种稀奇古怪但超实用的好东西。</p>
    <p style="margin:0 0 28px;font-size:15px;color:#555;line-height:1.85;">📅 <strong>每周一（北京时间）</strong>整理本周精选资源推送给你，欢迎常来看看 👇</p>
    <a href="https://pan.devmini.space" style="display:block;text-align:center;background:#F5A623;color:#fff;text-decoration:none;padding:15px;border-radius:10px;font-weight:600;font-size:15px;margin-bottom:24px;">→ 探索 devmini 全部资源</a>
    <p style="margin:0;font-size:14px;color:#555;line-height:1.7;">使用中遇到问题或有想看的资源主题，欢迎联系我们：<br>📧 <a href="mailto:xi7ang@devmini.space" style="color:#4A90E2;text-decoration:none;">xi7ang@devmini.space</a></p>
  </div>
  <div style="padding:20px;background:#f0f2f5;text-align:center;border-top:1px solid #e0e0e0;">
    <p style="margin:0 0 6px;font-size:12px;color:#999;">devmini · 专注免费优质资源推荐</p>
    <div><a href="https://pan.devmini.space" style="color:#4A90E2;font-size:12px;text-decoration:none;">访问网站</a><span style="color:#ccc;margin:0 8px;">|</span><a href="https://t.me/xi7ang" style="color:#4A90E2;font-size:12px;text-decoration:none;">Telegram社群</a><span style="color:#ccc;margin:0 8px;">|</span><a href="https://qm.qq.com/q/EkPkbcVMaY" style="color:#4A90E2;font-size:12px;text-decoration:none;">QQ群</a></div>
  </div>
</body></html>`
    await resend.emails.send({
      from: 'Devmini <noreply@devmini.space>',
      to: email,
      subject: '欢迎来到 devmini 🌟',
      html,
    })
    console.log('Welcome email sent to:', email)
  } catch (e) {
    console.error('Welcome email send error:', e)
    // Don't fail the subscription if welcome email fails
  }

  return json(200, { success: true, message: '订阅成功！🎉' })
}

const worker = {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url)

    if (req.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() })
    }

    if (req.method !== 'POST') {
      return json(405, { success: false, error: 'Method not allowed' })
    }

    try {
      if (url.pathname === '/request-code') {
        return await handleRequestCode(req, env)
      } else if (url.pathname === '/subscribe') {
        return await handleSubscribe(req, env)
      } else {
        return json(404, { success: false, error: 'Not found' })
      }
    } catch (e) {
      console.error('Worker error:', e)
      return json(500, { success: false, error: '服务器内部错误' })
    }
  }
}

export default worker
