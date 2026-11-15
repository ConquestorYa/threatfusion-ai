import { useState } from 'react'

import { AppShell, type Screen } from '@/components/AppShell'
import { WhatToCheck } from '@/pages/WhatToCheck'

// Screens in migration order (PRODUCT_PLAN, DEC-101). Screens that stay in
// Streamlit are reached through the "Open in Streamlit" link in the header.
const SCREENS: Screen[] = [{ id: 'review', title: 'What to check' }]

export default function App() {
  const [current, setCurrent] = useState(SCREENS[0].id)
  return (
    <AppShell screens={SCREENS} current={current} onSelect={setCurrent}>
      {current === 'review' && <WhatToCheck />}
    </AppShell>
  )
}
