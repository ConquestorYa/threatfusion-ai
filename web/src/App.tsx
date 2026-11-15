import { Moon, Sun } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'
import { usePreferences } from '@/lib/preferences'
import { WhatToCheck } from '@/pages/WhatToCheck'

export default function App() {
  const { lang, setLang, dark, toggleDark, t, chrome } = usePreferences()
  return (
    <div className="min-h-svh">
      <header className="border-b bg-card">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
          <span className="font-semibold">ThreatFusion</span>
          <nav className="text-sm">
            <span aria-current="page" className="border-b-2 border-foreground pb-[13px] font-medium">
              {t('What to check')}
            </span>
          </nav>
          <div className="ml-auto flex items-center gap-2">
            <ToggleGroup
              type="single"
              size="sm"
              variant="outline"
              value={lang}
              aria-label={chrome('language')}
              onValueChange={(value) => (value === 'en' || value === 'tr') && setLang(value)}
            >
              <ToggleGroupItem value="tr">TR</ToggleGroupItem>
              <ToggleGroupItem value="en">EN</ToggleGroupItem>
            </ToggleGroup>
            <Button variant="ghost" size="icon-sm" aria-label={chrome('theme')} title={chrome('theme')} onClick={toggleDark}>
              {dark ? <Sun /> : <Moon />}
            </Button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
        <h1 className="mb-1 text-2xl font-semibold tracking-tight">{t('What to check')}</h1>
        <WhatToCheck />
      </main>
    </div>
  )
}
