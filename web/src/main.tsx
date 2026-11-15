import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import App from './App.tsx'
import { TooltipProvider } from './components/ui/tooltip.tsx'
import { PreferencesProvider } from './lib/preferences.tsx'
import './index.css'

const queryClient = new QueryClient({ defaultOptions: { queries: { refetchOnWindowFocus: true } } })

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <PreferencesProvider>
        <TooltipProvider delayDuration={300}>
          <App />
        </TooltipProvider>
      </PreferencesProvider>
    </QueryClientProvider>
  </StrictMode>,
)
