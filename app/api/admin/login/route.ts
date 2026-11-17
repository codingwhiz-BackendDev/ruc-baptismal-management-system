import { createServerClient } from '@supabase/ssr'
import { createClient as createSupabaseAdmin } from '@supabase/supabase-js'
import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'

const adminEmail = 'admin@ruc.training'
const initialPassword = process.env.RUC_INITIAL_ADMIN_PASSWORD ?? 'admin1234'

export async function POST(request: Request) {
  const payload = await request.json().catch(() => null) as { password?: unknown } | null
  if (typeof payload?.password !== 'string' || payload.password.length < 1 || payload.password.length > 256) {
    return NextResponse.json({ error: 'Enter the administrator password.' }, { status: 400 })
  }

  const adminClient = createSupabaseAdmin(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    { auth: { autoRefreshToken: false, persistSession: false } },
  )

  let createdUserId: string | null = null
  if (payload.password === initialPassword) {
    const { data, error } = await adminClient.auth.admin.createUser({
      email: adminEmail,
      password: initialPassword,
      email_confirm: true,
      user_metadata: { display_name: 'RUC Administrator' },
    })
    if (!error && data.user) createdUserId = data.user.id
  }

  if (createdUserId) {
    const { error } = await adminClient.from('staff_profiles').insert({
      user_id: createdUserId,
      display_name: 'RUC Administrator',
      role: 'admin',
    })
    if (error) {
      await adminClient.auth.admin.deleteUser(createdUserId)
      return NextResponse.json({ error: 'Administrator account could not be initialized.' }, { status: 500 })
    }
  }

  const cookieStore = await cookies()
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!,
    {
      cookies: {
        getAll: () => cookieStore.getAll(),
        setAll: (values) => values.forEach(({ name, value, options }) => cookieStore.set(name, value, options)),
      },
    },
  )
  const { data, error } = await supabase.auth.signInWithPassword({ email: adminEmail, password: payload.password })
  if (error || !data.user) return NextResponse.json({ error: 'The administrator password is incorrect.' }, { status: 401 })

  const { data: profile } = await adminClient.from('staff_profiles').select('role').eq('user_id', data.user.id).maybeSingle()
  if (profile?.role !== 'admin') {
    await supabase.auth.signOut()
    return NextResponse.json({ error: 'This account is not authorized as an administrator.' }, { status: 403 })
  }

  return NextResponse.json({ success: true })
}
