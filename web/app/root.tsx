import React, {useEffect, useState} from 'react'
import {Links, Meta, Outlet, Scripts, ScrollRestoration} from 'react-router'

import './app.css'

type Theme = 'system' | 'light' | 'dark'
const THEME_KEY = 'pam_web:theme'

/// Sets data-theme on <html> : the stored choice, else the system's. Inline in <head>, so it runs before the first
/// paint (no light flash in dark mode). Same logic as apply_theme.
const THEME_SCRIPT = `try {
  const t = localStorage.getItem('${THEME_KEY}')
  const dark = t === 'dark' || (t !== 'light' && matchMedia('(prefers-color-scheme: dark)').matches)
  document.documentElement.dataset.theme = dark ? 'dark' : 'light'
} catch {}`

function apply_theme(theme: Theme) {
  const dark = theme === 'dark' || (theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches)
  document.documentElement.dataset.theme = dark ? 'dark' : 'light'
}

function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>('system')

  useEffect(() => {
    try {
      const stored = localStorage.getItem(THEME_KEY)
      if (stored === 'light' || stored === 'dark') setTheme(stored)
    } catch {
      // Storage blocked : system theme
    }
  }, [])

  useEffect(() => {
    apply_theme(theme)
    if (theme !== 'system') return
    // Follow the system while it changes
    const media = matchMedia('(prefers-color-scheme: dark)')
    const changed = () => apply_theme('system')
    media.addEventListener('change', changed)
    return () => media.removeEventListener('change', changed)
  }, [theme])

  const choose = (next: Theme) => {
    setTheme(next)
    try {
      if (next === 'system') localStorage.removeItem(THEME_KEY)
      else localStorage.setItem(THEME_KEY, next)
    } catch {
      // Storage blocked : kept until the page closes
    }
  }

  return (
    <div className='text-muted flex gap-3 text-xs'>
      {(['system', 'light', 'dark'] as const).map(option => (
        <button
          key={option}
          onClick={() => choose(option)}
          aria-pressed={theme === option}
          className={theme === option ? 'text-fg font-medium' : 'hover:text-fg'}
        >
          {option[0].toUpperCase() + option.slice(1)}
        </button>
      ))}
    </div>
  )
}

export function Layout({children}: {children: React.ReactNode}) {
  return (
    // data-theme is set by THEME_SCRIPT before React hydrates
    <html lang='en' suppressHydrationWarning>
      <head>
        <title>pam_web</title>
        <meta charSet='utf-8' />
        <meta name='viewport' content='width=device-width, initial-scale=1' />
        <script dangerouslySetInnerHTML={{__html: THEME_SCRIPT}} />
        <Meta />
        <Links />
      </head>
      <body>
        <main className='mx-auto max-w-xl px-4 pt-10'>{children}</main>
        <footer className='border-line mx-auto mt-16 flex max-w-xl justify-end border-t px-4 py-6'>
          <ThemeToggle />
        </footer>
        <ScrollRestoration />
        <Scripts />
      </body>
    </html>
  )
}

export default function App() {
  return <Outlet />
}
