import { useQuery } from '@tanstack/react-query'
import { ExternalLink, Moon, Sun } from 'lucide-react'
import type { ReactNode } from 'react'

import { Button } from '@/components/ui/button'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'
import { fetchAppInfo } from '@/lib/api'
import { usePreferences } from '@/lib/preferences'

export interface Screen {
  id: string
  /** English UI string, translated through the shared dictionary. */
  title: string
}

export function AppShell({
  screens,
  current,
  onSelect,
  children,
}: {
  screens: Screen[]
  current: string
  onSelect: (id: string) => void
  children: ReactNode
}) {
  const { lang, setLang, dark, toggleDark, t, chrome } = usePreferences()
  const app = useQuery({ queryKey: ['app'], queryFn: fetchAppInfo, staleTime: Infinity })
  const themeLabel = dark ? chrome('themeToLight') : chrome('themeToDark')

  return (
    <div className="min-h-svh">
      <header className="border-b bg-card">
        <div className="mx-auto flex max-w-[1280px] flex-wrap items-center gap-x-5 px-4 lg:px-5">
          <span className="py-2.5 font-semibold tracking-tight">ThreatFusion</span>
          <nav aria-label={chrome('nav')} className="order-last -mx-1 flex w-full overflow-x-auto sm:order-none sm:w-auto">
            {screens.map((screen) => (
              <button
                key={screen.id}
                type="button"
                aria-current={screen.id === current ? 'page' : undefined}
                onClick={() => onSelect(screen.id)}
                className="border-b-2 border-transparent px-2.5 py-2.5 text-[13px] whitespace-nowrap text-muted-foreground hover:text-foreground aria-[current=page]:border-foreground aria-[current=page]:text-foreground"
              >
                {t(screen.title)}
              </button>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-1.5 py-2">
            {app.data?.streamlit_url && (
              <a
                href={app.data.streamlit_url}
                target="_blank"
                rel="noopener noreferrer"
                title={chrome('streamlitScreens')}
                className="mr-1 inline-flex items-center gap-1 rounded-sm px-1.5 py-1 text-xs text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              >
                {chrome('openInStreamlit')}
                <ExternalLink className="size-3.5" aria-hidden />
              </a>
            )}
            <ToggleGroup
              type="single"
              size="sm"
              variant="outline"
              spacing={0}
              value={lang}
              aria-label={chrome('language')}
              onValueChange={(value) => (value === 'en' || value === 'tr') && setLang(value)}
            >
              <ToggleGroupItem value="tr" className="h-7 px-2 text-xs">
                TR
              </ToggleGroupItem>
              <ToggleGroupItem value="en" className="h-7 px-2 text-xs">
                EN
              </ToggleGroupItem>
            </ToggleGroup>
            <Button variant="outline" size="icon-sm" aria-label={themeLabel} title={themeLabel} onClick={toggleDark}>
              {dark ? <Sun aria-hidden /> : <Moon aria-hidden />}
            </Button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-[1280px] px-4 py-4 lg:px-5">{children}</main>
    </div>
  )
}
