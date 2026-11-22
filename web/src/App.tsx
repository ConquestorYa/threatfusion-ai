import { useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'

import { AppShell, type Screen } from '@/components/AppShell'
import { fetchAppInfo } from '@/lib/api'
import { usePreferences } from '@/lib/preferences'
import { Analyze } from '@/pages/Analyze'
import { Behavior } from '@/pages/Behavior'
import { Details } from '@/pages/Details'
import { Evaluation } from '@/pages/Evaluation'
import { History } from '@/pages/History'
import { QuickLookup } from '@/pages/QuickLookup'
import { Setup } from '@/pages/Setup'
import { WhatToCheck } from '@/pages/WhatToCheck'

// Screens in the order of the former Streamlit navigation (DEC-101, DEC-111).
const SCREENS: Screen[] = [
  { id: 'review', title: 'What to check' },
  { id: 'details', title: 'Details' },
  { id: 'behavior', title: 'Experimental ML' },
  { id: 'lookup', title: 'Quick lookup' },
  { id: 'analyze', title: 'Analyze telemetry' },
]
const HISTORY: Screen = { id: 'history', title: 'Analysis history' }
const EVALUATION: Screen = { id: 'evaluation', title: 'Model evaluation' }
const SETUP: Screen = { id: 'setup', title: 'Setup & CTI updates' }

export default function App() {
  const { t } = usePreferences()
  const app = useQuery({ queryKey: ['app'], queryFn: fetchAppInfo, staleTime: Infinity })
  // Same order and visibility rules as the former Streamlit navigation.
  const screens = [
    ...SCREENS,
    ...(app.data?.history_available ? [HISTORY] : []),
    ...(app.data?.evaluation_available ? [EVALUATION] : []),
    ...(app.data?.setup_available ? [SETUP] : []),
  ]
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
      {current === 'behavior' && <Behavior />}
      {current === 'lookup' && <QuickLookup />}
      {current === 'analyze' && <Analyze />}
      {current === 'history' && <History />}
      {current === 'evaluation' && <Evaluation />}
      {current === 'setup' && <Setup />}
    </AppShell>
  )
}
