import { useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'

import { AppShell, type Screen } from '@/components/AppShell'
import { fetchAppInfo } from '@/lib/api'
import { usePreferences } from '@/lib/preferences'
import { Analyze } from '@/pages/Analyze'
import { Details } from '@/pages/Details'
import { QuickLookup } from '@/pages/QuickLookup'
import { Setup } from '@/pages/Setup'
import { WhatToCheck } from '@/pages/WhatToCheck'

// Screens in migration order (PRODUCT_PLAN, DEC-101). Screens that stay in
// Streamlit are reached through the "Open in Streamlit" link in the header.
const SCREENS: Screen[] = [
  { id: 'review', title: 'What to check' },
  { id: 'details', title: 'Details' },
  { id: 'lookup', title: 'Quick lookup' },
  { id: 'analyze', title: 'Analyze telemetry' },
]
const SETUP: Screen = { id: 'setup', title: 'Setup & CTI updates' }

export default function App() {
  const { t } = usePreferences()
  const app = useQuery({ queryKey: ['app'], queryFn: fetchAppInfo, staleTime: Infinity })
  const screens = app.data?.setup_available ? [...SCREENS, SETUP] : SCREENS
  const [chosen, setChosen] = useState<string | null>(null)
  // As in Streamlit: Setup opens first until real CTI has been downloaded once.
  const current = chosen ?? (app.data?.first_setup ? SETUP.id : SCREENS[0].id)
  const title = t(screens.find((screen) => screen.id === current)?.title ?? 'What to check')
  useEffect(() => {
    document.title = `ThreatFusion · ${title}`
  }, [title])
  return (
    <AppShell screens={screens} current={current} onSelect={setChosen}>
      {current === 'review' && <WhatToCheck />}
      {current === 'details' && <Details />}
      {current === 'lookup' && <QuickLookup />}
      {current === 'analyze' && <Analyze />}
      {current === 'setup' && <Setup />}
    </AppShell>
  )
}
