import { useQuery } from '@tanstack/react-query'
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

import { fetchStrings, type Language } from './api'

// Remembered per browser only; the page works the same without storage.
function readStored(key: string): string | null {
  try {
    return window.localStorage.getItem(key)
  } catch {
    return null
  }
}

function store(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value)
  } catch {
    // Private window or blocked storage: keep the choice for this visit only.
  }
}

// Page chrome that the shared Python dictionary does not cover.
const CHROME: Record<Language, Record<string, string>> = {
  en: {
    language: 'Language',
    theme: 'Switch between light and dark',
    loading: 'Loading the list…',
    offline: 'The local API is not answering. Start it with: python -m threatfusion.api',
    retry: 'Try again',
    updated: 'Updated',
  },
  tr: {
    language: 'Dil',
    theme: 'Açık ve koyu tema arasında geç',
    loading: 'Liste yükleniyor…',
    offline: 'Yerel API yanıt vermiyor. Şununla başlat: python -m threatfusion.api',
    retry: 'Tekrar dene',
    updated: 'Güncellendi',
  },
}

interface Preferences {
  lang: Language
  setLang: (lang: Language) => void
  dark: boolean
  toggleDark: () => void
  /** Translate an English UI string via the server dictionary, then fill {placeholders}. */
  t: (text: string, values?: Record<string, string | number>) => string
  chrome: (key: keyof (typeof CHROME)['en']) => string
}

const PreferencesContext = createContext<Preferences | null>(null)

export function PreferencesProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Language>(() => (readStored('tf-lang') === 'tr' ? 'tr' : 'en'))
  const [dark, setDark] = useState<boolean>(() => {
    const stored = readStored('tf-theme')
    if (stored) return stored === 'dark'
    return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-color-scheme: dark)').matches
  })
  const strings = useQuery({ queryKey: ['strings', lang], queryFn: () => fetchStrings(lang), staleTime: Infinity })

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
  }, [dark])
  useEffect(() => {
    document.documentElement.lang = lang
  }, [lang])

  const setLang = useCallback((next: Language) => {
    setLangState(next)
    store('tf-lang', next)
  }, [])
  const toggleDark = useCallback(() => {
    setDark((current) => {
      store('tf-theme', current ? 'light' : 'dark')
      return !current
    })
  }, [])

  const value = useMemo<Preferences>(() => {
    const dictionary = strings.data ?? {}
    return {
      lang,
      setLang,
      dark,
      toggleDark,
      t: (text, values) => {
        let result = dictionary[text] ?? text
        for (const [name, replacement] of Object.entries(values ?? {})) {
          result = result.replaceAll(`{${name}}`, String(replacement))
        }
        return result
      },
      chrome: (key) => CHROME[lang][key],
    }
  }, [lang, setLang, dark, toggleDark, strings.data])

  return <PreferencesContext.Provider value={value}>{children}</PreferencesContext.Provider>
}

export function usePreferences(): Preferences {
  const value = useContext(PreferencesContext)
  if (!value) throw new Error('usePreferences needs PreferencesProvider')
  return value
}
