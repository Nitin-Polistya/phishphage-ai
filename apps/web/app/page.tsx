import type { Metadata } from 'next';
import Link from 'next/link';
import {
  ArrowRight,
  BadgeCheck,
  BookOpen,
  BrainCircuit,
  Check,
  ChevronRight,
  ClipboardPaste,
  FileCode2,
  FileSearch,
  FileUp,
  Gauge,
  Link2,
  LockKeyhole,
  MailSearch,
  Paperclip,
  ScanText,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { LandingSectionNavigation } from '@/components/landing/section-navigation';

export const metadata: Metadata = {
  title: {
    absolute: 'PhishPhage AI — Explainable phishing detection',
  },
  description: 'Analyze email content, headers, URLs, and attachment metadata with explainable phishing-risk scoring.',
};

const analysisMethods = [
  {
    name: 'Quick Paste',
    description: 'Paste the visible parts of an email for a fast, focused assessment.',
    detail: 'Subject, sender, body',
    icon: ClipboardPaste,
  },
  {
    name: 'Raw Email',
    description: 'Submit complete message source to include delivery and authentication headers.',
    detail: 'Full message source',
    icon: FileCode2,
  },
  {
    name: '.eml Upload',
    description: 'Inspect an exported email with its structure and attachment metadata intact.',
    detail: 'Up to 2 MB',
    icon: FileUp,
  },
];

const capabilities = [
  { name: 'Email content analysis', description: 'Detect urgency, credential requests, and social-engineering language.', icon: ScanText },
  { name: 'Header analysis', description: 'Inspect sender identity, reply-to mismatches, and authentication results.', icon: FileSearch },
  { name: 'URL inspection', description: 'Evaluate link structure and suspicious patterns without visiting the destination.', icon: Link2 },
  { name: 'Attachment metadata analysis', description: 'Review filenames, types, sizes, and extension risk without execution.', icon: Paperclip },
  { name: 'Explainable risk scoring', description: 'Connect every classification to observable signals and clear recommendations.', icon: Gauge },
  { name: 'Rule-based and optional ML detection', description: 'Combine deterministic checks with transparent local model availability.', icon: BrainCircuit },
];

const workflow = [
  { step: 'Submit', description: 'Choose the input that matches the evidence you have.' },
  { step: 'Parse', description: 'Normalize message content, headers, links, and metadata.' },
  { step: 'Analyze', description: 'Evaluate signals with rules and optional local ML.' },
  { step: 'Explain', description: 'See the verdict, score, confidence, and evidence.' },
  { step: 'Act', description: 'Follow practical recommendations for the next step.' },
];

const howToUseSteps = [
  { title: 'Open Analyze Email', description: 'Start a new investigation from the Analyze Email workspace.', icon: MailSearch },
  { title: 'Choose an input method', description: 'Select Quick Paste, Raw Email, or .eml Upload for the evidence you have.', icon: ClipboardPaste },
  { title: 'Submit the email', description: 'Provide the available message data and begin the analysis.', icon: ArrowRight },
  { title: 'Review the AI verdict', description: 'Check the final classification, risk score, and confidence.', icon: Gauge },
  { title: 'Review detected indicators', description: 'Inspect the evidence and signals that contributed to the result.', icon: FileSearch },
  { title: 'Follow recommended actions', description: 'Use the suggested next steps to respond safely and consistently.', icon: ShieldCheck },
  { title: 'Save to Scan History', description: 'Successful analyses are retained locally when scan saving is enabled.', icon: ScanText },
  { title: 'Export a report if needed', description: 'Open Reports to preview, download, print, or save the investigation.', icon: FileUp },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen overflow-x-clip bg-slate-950 text-slate-100">
      <header className="sticky top-0 z-50 border-b border-slate-800/80 bg-slate-950/95 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          <Link href="/" className="flex items-center gap-2.5 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
            <span className="flex h-8 w-8 items-center justify-center rounded-md bg-blue-600 text-white">
              <ShieldAlert size={19} aria-hidden="true" />
            </span>
            <span className="font-semibold tracking-tight text-slate-50">PhishPhage AI</span>
          </Link>

          <LandingSectionNavigation />

          <Button asChild size="sm" className="bg-blue-600 text-white hover:bg-blue-500">
            <Link href="/analyze">
              Analyze email
              <ArrowRight aria-hidden="true" />
            </Link>
          </Button>
        </div>
      </header>

      <main>
        <section className="relative border-b border-slate-800/80">
          <div className="absolute inset-0 -z-0 bg-[radial-gradient(circle_at_78%_20%,rgba(37,99,235,0.12),transparent_34%)]" aria-hidden="true" />
          <div className="relative mx-auto grid max-w-7xl gap-14 px-4 py-20 sm:px-6 sm:py-28 lg:grid-cols-[1.15fr_0.85fr] lg:items-center lg:px-8 lg:py-32">
            <div className="max-w-3xl">
              <Badge variant="outline" className="mb-6 border-blue-500/30 bg-blue-500/5 px-3 py-1 text-blue-300">
                <span className="mr-2 h-1.5 w-1.5 rounded-full bg-blue-400" aria-hidden="true" />
                Explainable email threat analysis
              </Badge>
              <h1 className="text-4xl font-semibold tracking-[-0.035em] text-white sm:text-5xl lg:text-6xl lg:leading-[1.08]">
                Stop phishing before it becomes an incident.
              </h1>
              <p className="mt-6 max-w-2xl text-base leading-7 text-slate-400 sm:text-lg sm:leading-8">
                PhishPhage AI turns suspicious emails into clear, evidence-backed risk assessments—so you can understand the threat and act with confidence.
              </p>
              <div className="mt-9 flex flex-col gap-3 sm:flex-row">
                <Button asChild size="lg" className="bg-blue-600 px-6 text-white hover:bg-blue-500">
                  <Link href="/analyze">
                    Analyze an email
                    <ArrowRight aria-hidden="true" />
                  </Link>
                </Button>
                <Button asChild size="lg" variant="outline" className="border-slate-700 bg-slate-950 px-6 text-slate-200 hover:bg-slate-900 hover:text-white">
                  <Link href="/dashboard">View dashboard</Link>
                </Button>
              </div>
              <div className="mt-9 flex flex-wrap gap-x-6 gap-y-3 text-xs font-medium text-slate-500">
                <span className="flex items-center gap-2"><Check size={14} className="text-emerald-400" aria-hidden="true" />No account required</span>
                <span className="flex items-center gap-2"><Check size={14} className="text-emerald-400" aria-hidden="true" />Evidence-first results</span>
                <span className="flex items-center gap-2"><Check size={14} className="text-emerald-400" aria-hidden="true" />Local ML support</span>
              </div>
            </div>

            <div className="border border-slate-800 bg-slate-950/80 shadow-2xl shadow-black/20">
              <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">
                  <MailSearch size={15} className="text-blue-400" aria-hidden="true" />
                  Analysis preview
                </div>
                <span className="flex items-center gap-2 text-xs text-emerald-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden="true" /> Ready
                </span>
              </div>
              <div className="p-5 sm:p-6">
                <div className="flex items-start justify-between gap-6 border-b border-slate-800 pb-6">
                  <div>
                    <p className="text-xs uppercase tracking-[0.14em] text-slate-500">Final classification</p>
                    <p className="mt-2 text-2xl font-semibold text-amber-300">Suspicious</p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs uppercase tracking-[0.14em] text-slate-500">Risk score</p>
                    <p className="mt-2 text-2xl font-semibold tabular-nums text-slate-100">67<span className="text-sm text-slate-500">/100</span></p>
                  </div>
                </div>
                <div className="space-y-4 py-6">
                  {[
                    ['Sender identity', 'Reply-to mismatch', 'medium'],
                    ['Content signals', 'Credential request', 'high'],
                    ['URL structure', 'Obfuscated destination', 'high'],
                    ['Attachment', 'No executable content', 'clear'],
                  ].map(([label, finding, tone]) => (
                    <div key={label} className="grid grid-cols-[1fr_auto] items-center gap-4 text-sm">
                      <div>
                        <p className="text-slate-500">{label}</p>
                        <p className="mt-0.5 text-slate-200">{finding}</p>
                      </div>
                      <span className={tone === 'clear' ? 'text-xs font-medium text-emerald-400' : tone === 'medium' ? 'text-xs font-medium text-amber-400' : 'text-xs font-medium text-rose-400'}>
                        {tone}
                      </span>
                    </div>
                  ))}
                </div>
                <div className="flex items-center justify-between border-t border-slate-800 pt-5 text-xs text-slate-500">
                  <span>4 explainable findings</span>
                  <span className="flex items-center gap-1 text-blue-400">Review evidence <ChevronRight size={13} aria-hidden="true" /></span>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section id="methods" className="scroll-mt-20 border-b border-slate-800/80 py-20 sm:py-24">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="grid gap-8 lg:grid-cols-[0.8fr_1.2fr] lg:gap-16">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-blue-400">Flexible input</p>
                <h2 className="mt-4 text-3xl font-semibold tracking-tight text-white">Analyze the evidence you actually have.</h2>
                <p className="mt-4 max-w-md text-sm leading-6 text-slate-400">Start with a quick copy-and-paste or provide complete message data for deeper inspection.</p>
              </div>
              <div className="border-t border-slate-800">
                {analysisMethods.map((method, index) => (
                  <div key={method.name} className="grid gap-4 border-b border-slate-800 py-6 sm:grid-cols-[48px_1fr_auto] sm:items-center">
                    <span className="flex h-10 w-10 items-center justify-center rounded-md border border-slate-800 bg-slate-900 text-blue-400">
                      <method.icon size={19} aria-hidden="true" />
                    </span>
                    <div>
                      <div className="flex items-baseline gap-3">
                        <span className="text-xs tabular-nums text-slate-600">0{index + 1}</span>
                        <h3 className="font-semibold text-slate-100">{method.name}</h3>
                      </div>
                      <p className="mt-2 text-sm leading-6 text-slate-400">{method.description}</p>
                    </div>
                    <span className="text-xs font-medium text-slate-500 sm:text-right">{method.detail}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section id="capabilities" className="scroll-mt-20 border-b border-slate-800/80 bg-slate-900/25 py-20 sm:py-24">
          <div className="mx-auto grid max-w-7xl gap-10 px-4 sm:px-6 lg:grid-cols-[0.7fr_1.3fr] lg:gap-20 lg:px-8">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-blue-400">Core capabilities</p>
              <h2 className="mt-4 text-3xl font-semibold tracking-tight text-white">Every verdict should show its work.</h2>
              <p className="mt-4 max-w-sm text-sm leading-6 text-slate-400">Layered analysis surfaces the signals behind a classification instead of asking you to trust a black box.</p>
            </div>
            <div className="grid border-l border-t border-slate-800 sm:grid-cols-2">
              {capabilities.map((capability) => (
                <div key={capability.name} className="border-b border-r border-slate-800 p-6">
                  <capability.icon size={20} className="text-blue-400" aria-hidden="true" />
                  <h3 className="mt-5 font-semibold text-slate-100">{capability.name}</h3>
                  <p className="mt-2 text-sm leading-6 text-slate-400">{capability.description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="border-b border-slate-800/80 py-20 sm:py-24">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="max-w-2xl">
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-blue-400">How it works</p>
              <h2 className="mt-4 text-3xl font-semibold tracking-tight text-white">From suspicious message to informed action.</h2>
            </div>
            <div className="mt-12 grid border-l border-t border-slate-800 sm:grid-cols-5">
              {workflow.map((item, index) => (
                <div key={item.step} className="min-h-48 border-b border-r border-slate-800 p-5 sm:p-6">
                  <span className="text-xs font-semibold tabular-nums text-blue-400">0{index + 1}</span>
                  <h3 className="mt-8 text-lg font-semibold text-slate-100">{item.step}</h3>
                  <p className="mt-3 text-sm leading-6 text-slate-500">{item.description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="how-to-use" className="scroll-mt-20 border-b border-slate-800/80 bg-slate-900/25 py-20 sm:py-24">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="max-w-2xl">
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-blue-400">How to use</p>
              <h2 className="mt-4 text-3xl font-semibold tracking-tight text-white">Move from email submission to a documented decision.</h2>
              <p className="mt-4 text-sm leading-6 text-slate-400">Follow the same practical workflow for every suspicious message, from choosing the right input to exporting the final report.</p>
            </div>
            <ol className="mt-12 grid border-l border-t border-slate-800 md:grid-cols-2">
              {howToUseSteps.map((item, index) => (
                <li key={item.title} className="grid min-h-36 grid-cols-[44px_1fr] gap-4 border-b border-r border-slate-800 p-5 sm:p-6">
                  <div>
                    <span className="flex h-10 w-10 items-center justify-center rounded-md border border-slate-800 bg-slate-950 text-blue-400"><item.icon size={18} aria-hidden="true" /></span>
                    <span className="mt-3 block text-xs font-semibold tabular-nums text-slate-600">{String(index + 1).padStart(2, '0')}</span>
                  </div>
                  <div><h3 className="font-semibold text-slate-100">{item.title}</h3><p className="mt-2 text-sm leading-6 text-slate-400">{item.description}</p></div>
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section id="privacy" className="scroll-mt-20 py-20 sm:py-24">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="border border-slate-700 bg-slate-900 px-6 py-8 sm:px-10 sm:py-10">
              <div className="grid gap-8 lg:grid-cols-[0.8fr_1.2fr] lg:items-center">
                <div>
                  <div className="flex items-center gap-3 text-emerald-400">
                    <LockKeyhole size={22} aria-hidden="true" />
                    <span className="text-xs font-semibold uppercase tracking-[0.2em]">Privacy by design</span>
                  </div>
                  <h2 className="mt-4 text-2xl font-semibold tracking-tight text-white">Inspect safely. Retain control.</h2>
                </div>
                <div className="grid gap-4 sm:grid-cols-3">
                  {['No attachment execution', 'No URL fetching', 'Files are not stored by default'].map((statement) => (
                    <div key={statement} className="flex items-start gap-3 text-sm leading-6 text-slate-300">
                      <ShieldCheck size={17} className="mt-1 shrink-0 text-emerald-400" aria-hidden="true" />
                      <span>{statement}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="border-t border-slate-800/80 py-16">
          <div className="mx-auto flex max-w-7xl flex-col items-start justify-between gap-8 px-4 sm:px-6 md:flex-row md:items-center lg:px-8">
            <div>
              <p className="text-2xl font-semibold tracking-tight text-white">Ready to inspect a suspicious email?</p>
              <p className="mt-2 text-sm text-slate-400">Get an explainable assessment without creating an account.</p>
            </div>
            <Button asChild size="lg" className="bg-blue-600 text-white hover:bg-blue-500">
              <Link href="/analyze">
                Start analysis
                <ArrowRight aria-hidden="true" />
              </Link>
            </Button>
          </div>
        </section>
      </main>

      <footer className="border-t border-slate-800 bg-slate-950">
        <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6 lg:px-8">
          <div className="flex flex-col justify-between gap-8 md:flex-row md:items-center">
            <div className="flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-md border border-slate-800 text-blue-400">
                <ShieldAlert size={18} aria-hidden="true" />
              </span>
              <div>
                <p className="text-sm font-semibold text-slate-200">PhishPhage AI</p>
                <p className="mt-0.5 text-xs text-slate-600">Explainable phishing detection</p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-x-6 gap-y-3 text-sm text-slate-500">
              <a href="https://github.com/Nitin-Polistya/phishphage-ai" target="_blank" rel="noreferrer" className="theme-link rounded-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">GitHub repository</a>
              <span className="flex items-center gap-1.5" title="Documentation coming soon"><BookOpen size={14} aria-hidden="true" />Documentation · Coming soon</span>
              <span className="flex items-center gap-1.5"><BadgeCheck size={14} aria-hidden="true" />Internship MVP</span>
            </div>
          </div>
          <Separator className="my-8 bg-slate-800" />
          <div className="flex flex-col justify-between gap-2 text-xs text-slate-600 sm:flex-row">
            <p>Built for transparent, evidence-led email security analysis.</p>
            <p>PhishPhage AI · Project information</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
