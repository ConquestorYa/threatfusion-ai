import { useEffect, useState } from 'react'

import { AppShell, type Screen } from '@/components/AppShell'
import { usePreferences } from '@/lib/preferences'
import { Details } from '@/pages/Details'
import { QuickLookup } from '@/pages/QuickLookup'
import { WhatToCheck } from '@/pages/WhatToCheck'

// Screens in migration order (PRODUCT_PLAN, DEC-101). Screens that stay in
// Streamlit are reached through the "Open in Streamlit" link in the header.
const SCREENS: Screen[] = [
  { id: 'review', title: 'What to check' },
  { id: 'details', title: 'Details' },
  { id: 'lookup', title: 'Quick lookup' },
]

export default function App() {
  const [current, setCurrent] = useState(SCREENS[0].id)
  const { t } = usePreferences()
  const title = t(SCREENS.find((screen) => screen.id === current)?.title ?? 'What to check')
  useEffect(() => {
    document.title = `ThreatFusion · ${title}`
  }, [title])
  return (
    <AppShell screens={SCREENS} current={current} onSelect={setCurrent}>
      {current === 'review' && <WhatToCheck />}
      {current === 'details' && <Details />}
      {current === 'lookup' && <QuickLookup />}
    </AppShell>
  )
}
