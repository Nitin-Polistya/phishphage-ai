'use client';

import { MouseEvent, useEffect, useState } from 'react';

import { cn } from '@/lib/utils';

const sections = [
  { id: 'methods', label: 'Methods' },
  { id: 'capabilities', label: 'Capabilities' },
  { id: 'privacy', label: 'Privacy' },
] as const;

type SectionId = (typeof sections)[number]['id'];

export function LandingSectionNavigation() {
  const [activeSection, setActiveSection] = useState<SectionId | null>(null);

  useEffect(() => {
    let frame: number | null = null;

    const updateActiveSection = () => {
      frame = null;
      const probe = Math.min(window.innerHeight * 0.32, 280) + 64;
      const active = sections.find(({ id }) => {
        const bounds = document.getElementById(id)?.getBoundingClientRect();
        return bounds ? bounds.top <= probe && bounds.bottom > probe : false;
      });
      setActiveSection(active?.id ?? null);
    };

    const scheduleUpdate = () => {
      if (frame === null) frame = window.requestAnimationFrame(updateActiveSection);
    };

    scheduleUpdate();
    window.addEventListener('scroll', scheduleUpdate, { passive: true });
    window.addEventListener('resize', scheduleUpdate);
    window.addEventListener('load', scheduleUpdate);
    window.addEventListener('hashchange', scheduleUpdate);
    window.addEventListener('popstate', scheduleUpdate);

    return () => {
      if (frame !== null) window.cancelAnimationFrame(frame);
      window.removeEventListener('scroll', scheduleUpdate);
      window.removeEventListener('resize', scheduleUpdate);
      window.removeEventListener('load', scheduleUpdate);
      window.removeEventListener('hashchange', scheduleUpdate);
      window.removeEventListener('popstate', scheduleUpdate);
    };
  }, []);

  const navigateToSection = (event: MouseEvent<HTMLAnchorElement>, id: SectionId) => {
    event.preventDefault();
    if (activeSection === id) return;

    const target = document.getElementById(id);
    if (!target) return;
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    target.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
    window.history.pushState(null, '', `#${id}`);
  };

  return (
    <nav aria-label="Landing page sections" className="hidden items-center gap-7 text-sm md:flex">
      {sections.map(({ id, label }) => {
        const active = activeSection === id;
        return (
          <a
            key={id}
            href={`#${id}`}
            aria-current={active ? 'location' : undefined}
            onClick={(event) => navigateToSection(event, id)}
            className={cn('rounded-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500', active ? 'theme-active-link' : 'theme-link')}
          >
            {label}
          </a>
        );
      })}
    </nav>
  );
}
