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
const CHROME = {
  en: {
    language: 'Language',
    themeToLight: 'Switch to light theme',
    themeToDark: 'Switch to dark theme',
    loading: 'Loading the list…',
    offline: 'The local API is not answering. Start it with: python -m threatfusion.api',
    retry: 'Try again',
    updated: 'updated {time}',
    target: 'Target',
    reason: 'Reason',
    deviceTarget: 'Device → target',
    owner: 'Network owner',
    time: 'Time',
    mark: 'Mark',
    marksLegendKnown: 'I know this: hidden next time',
    marksLegendUnsure: 'Not sure',
    marksLegendSuspicious: 'Suspicious: kept on top',
    details: 'Show why and what to do',
    hideDetails: 'Hide explanation',
    openInStreamlit: 'Open in Streamlit',
    streamlitScreens: 'Analyze telemetry, Experimental ML, Model evaluation and Analysis history are in the Streamlit workspace.',
    nav: 'Screens',
    table: 'table',
    mlInStreamlit: 'The experimental ML score column for DNS names is shown in Streamlit (Open in Streamlit → Collected connections).',
  },
  tr: {
    language: 'Dil',
    themeToLight: 'Açık temaya geç',
    themeToDark: 'Koyu temaya geç',
    loading: 'Liste yükleniyor…',
    offline: 'Yerel API yanıt vermiyor. Şununla başlat: python -m threatfusion.api',
    retry: 'Tekrar dene',
    updated: '{time} güncellendi',
    target: 'Hedef',
    reason: 'Neden',
    deviceTarget: 'Cihaz → hedef',
    owner: 'Ağ sahibi',
    time: 'Zaman',
    mark: 'İşaret',
    marksLegendKnown: 'Tanıyorum: bir dahakine gizler',
    marksLegendUnsure: 'Emin değilim',
    marksLegendSuspicious: 'Şüpheli: en üstte tutar',
    details: 'Nedenini ve ne yapılacağını göster',
    hideDetails: 'Açıklamayı gizle',
    openInStreamlit: "Streamlit'te aç",
    streamlitScreens: "Telemetri analizi, Deneysel ML, Model değerlendirme ve Analiz geçmişi Streamlit çalışma alanında.",
    nav: 'Ekranlar',
    table: 'tablo',
    mlInStreamlit: "DNS adları için deneysel ML puanı sütunu Streamlit'te gösterilir (Streamlit'te aç → Toplanan bağlantılar).",
  },
} satisfies Record<Language, Record<string, string>>

export type ChromeKey = keyof (typeof CHROME)['en']

interface Preferences {
  lang: Language
  setLang: (lang: Language) => void
  dark: boolean
  toggleDark: () => void
  /** Translate an English UI string via the server dictionary, then fill {placeholders}. */
  t: (text: string, values?: Record<string, string | number>) => string
  chrome: (key: ChromeKey) => string
}

const PreferencesContext = createContext<Preferences | null>(null)

export function PreferencesProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Language>(() => (readStored('tf-lang') === 'en' ? 'en' : 'tr'))
  // Turkish is the default; English only after the analyst picks EN (remembered).
  // public/theme-init.js already applied the theme before the first paint:
  // dark unless the analyst chose light. Read it back instead of deciding again.
  const [dark, setDark] = useState<boolean>(() => document.documentElement.classList.contains('dark'))
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
