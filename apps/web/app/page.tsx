import type { Metadata } from 'next';
import Link from 'next/link';
import {
  ArrowRight,
  BadgeCheck,
  BookOpen,
  BrainCircuit,
  Check,
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
    absolute: 'PhishShield AI — Explainable phishing detection',
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
  { title: 'Review the assessment', description: 'Use the result dashboard to understand score, confidence, and signal families.', icon: ScanText },
  { title: 'Use human judgment', description: 'Follow practical recommendations and verify sensitive requests independently.', icon: FileUp },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen overflow-x-clip bg-background text-foreground">
      <header data-landing-header className="sticky top-0 z-50 border-b border-border/80 bg-background/95 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          <Link href="/" className="flex items-center gap-2.5 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
            <span className="flex h-8 w-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
              <ShieldAlert size={19} aria-hidden="true" />
            </span>
            <span className="font-semibold tracking-tight text-foreground">PhishShield AI</span>
          </Link>

          <LandingSectionNavigation />

          <Button asChild size="sm" className="bg-primary text-primary-foreground hover:bg-primary">
            <Link href="/analyze">
              Analyze email
              <ArrowRight aria-hidden="true" />
            </Link>
          </Button>
        </div>
      </header>

      <main>
        <section className="relative border-b border-border/80">
          <div className="absolute inset-0 -z-0 bg-[radial-gradient(circle_at_78%_20%,rgba(37,99,235,0.12),transparent_34%)]" aria-hidden="true" />
          <div className="relative mx-auto grid max-w-7xl gap-14 px-4 py-20 sm:px-6 sm:py-28 lg:grid-cols-[1.15fr_0.85fr] lg:items-center lg:px-8 lg:py-32">
            <div className="max-w-3xl">
              <Badge variant="outline" className="mb-6 border-primary/30 bg-primary/5 px-3 py-1 text-primary">
                <span className="mr-2 h-1.5 w-1.5 rounded-full bg-primary" aria-hidden="true" />
                Explainable email threat analysis
              </Badge>
              <h1 className="text-4xl font-semibold tracking-[-0.035em] text-foreground sm:text-5xl lg:text-6xl lg:leading-[1.08]">
                Stop phishing before it becomes an incident.
              </h1>
              <p className="mt-6 max-w-2xl text-base leading-7 text-muted-foreground sm:text-lg sm:leading-8">
                PhishShield AI turns suspicious emails into clear, evidence-backed risk assessments—so you can understand the threat and act with confidence.
              </p>
              <div className="mt-9 flex flex-col gap-3 sm:flex-row">
                <Button asChild size="lg" className="bg-primary px-6 text-primary-foreground hover:bg-primary">
                  <Link href="/analyze">
                    Analyze an email
                    <ArrowRight aria-hidden="true" />
                  </Link>
                </Button>
                <Button asChild size="lg" variant="outline" className="border-input bg-background px-6 text-foreground hover:bg-surface hover:text-foreground">
                  <Link href="/dashboard">View dashboard</Link>
                </Button>
              </div>
              <div className="mt-9 flex flex-wrap gap-x-6 gap-y-3 text-xs font-medium text-foreground0">
                <span className="flex items-center gap-2"><Check size={14} className="text-success" aria-hidden="true" />No account required</span>
                <span className="flex items-center gap-2"><Check size={14} className="text-success" aria-hidden="true" />Evidence-first results</span>
                <span className="flex items-center gap-2"><Check size={14} className="text-success" aria-hidden="true" />Local ML support</span>
              </div>
            </div>

            <div className="border border-border bg-background/80 shadow-2xl shadow-black/20">
              <div className="flex items-center justify-between border-b border-border px-5 py-4">
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                  <MailSearch size={15} className="text-primary" aria-hidden="true" />
                  Analysis workflow
                </div>
                  <span className="flex items-center gap-2 text-xs text-primary">
                  <span className="h-1.5 w-1.5 rounded-full bg-primary" aria-hidden="true" /> In memory
                </span>
              </div>
              <div className="p-5 sm:p-6">
                <div className="space-y-3 py-6">
                  {[['01', 'Parse locally', 'Normalize headers, body text, links, and attachment metadata.'], ['02', 'Evaluate signals', 'Combine deterministic indicators with the calibrated local candidate model.'], ['03', 'Explain safely', 'Return risk, confidence, signal families, and recommendations without retaining the email.']].map(([number, title, description]) => (
                    <div key={number} className="grid grid-cols-[32px_1fr] gap-3 rounded-lg border border-border bg-surface/50 p-3"><span className="text-xs font-semibold tabular-nums text-primary">{number}</span><div><p className="text-sm font-semibold text-foreground">{title}</p><p className="mt-1 text-xs leading-5 text-foreground0">{description}</p></div></div>
                  ))}
                </div>
                <div className="flex items-center gap-2 border-t border-border pt-5 text-xs text-foreground0"><LockKeyhole size={14} className="text-success" aria-hidden="true" />No persistence, URL fetching, or attachment execution.</div>
              </div>
            </div>
          </div>
        </section>

        <section id="methods" className="border-b border-border/80 py-20 sm:py-24">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="grid gap-8 lg:grid-cols-[0.8fr_1.2fr] lg:gap-16">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-primary">Flexible input</p>
                <h2 className="mt-4 text-3xl font-semibold tracking-tight text-foreground">Analyze the evidence you actually have.</h2>
                <p className="mt-4 max-w-md text-sm leading-6 text-muted-foreground">Start with a quick copy-and-paste or provide complete message data for deeper inspection.</p>
              </div>
              <div className="border-t border-border">
                {analysisMethods.map((method, index) => (
                  <div key={method.name} className="grid gap-4 border-b border-border py-6 sm:grid-cols-[48px_1fr_auto] sm:items-center">
                    <span className="flex h-10 w-10 items-center justify-center rounded-md border border-border bg-surface text-primary">
                      <method.icon size={19} aria-hidden="true" />
                    </span>
                    <div>
                      <div className="flex items-baseline gap-3">
                        <span className="text-xs tabular-nums text-muted-foreground">0{index + 1}</span>
                        <h3 className="font-semibold text-foreground">{method.name}</h3>
                      </div>
                      <p className="mt-2 text-sm leading-6 text-muted-foreground">{method.description}</p>
                    </div>
                    <span className="text-xs font-medium text-foreground0 sm:text-right">{method.detail}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section id="capabilities" className="border-b border-border/80 bg-surface/25 py-20 sm:py-24">
          <div className="mx-auto grid max-w-7xl gap-10 px-4 sm:px-6 lg:grid-cols-[0.7fr_1.3fr] lg:gap-20 lg:px-8">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-primary">Core capabilities</p>
              <h2 className="mt-4 text-3xl font-semibold tracking-tight text-foreground">Every verdict should show its work.</h2>
              <p className="mt-4 max-w-sm text-sm leading-6 text-muted-foreground">Layered analysis surfaces the signals behind a classification instead of asking you to trust a black box.</p>
            </div>
            <div className="grid border-l border-t border-border sm:grid-cols-2">
              {capabilities.map((capability) => (
                <div key={capability.name} className="border-b border-r border-border p-6">
                  <capability.icon size={20} className="text-primary" aria-hidden="true" />
                  <h3 className="mt-5 font-semibold text-foreground">{capability.name}</h3>
                  <p className="mt-2 text-sm leading-6 text-muted-foreground">{capability.description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="how-it-works" className="border-b border-border/80 py-20 sm:py-24">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="max-w-2xl">
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-primary">How it works</p>
              <h2 className="mt-4 text-3xl font-semibold tracking-tight text-foreground">From suspicious message to informed action.</h2>
            </div>
            <div className="mt-12 grid border-l border-t border-border sm:grid-cols-5">
              {workflow.map((item, index) => (
                <div key={item.step} className="min-h-48 border-b border-r border-border p-5 sm:p-6">
                  <span className="text-xs font-semibold tabular-nums text-primary">0{index + 1}</span>
                  <h3 className="mt-8 text-lg font-semibold text-foreground">{item.step}</h3>
                  <p className="mt-3 text-sm leading-6 text-foreground0">{item.description}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="architecture" className="border-b border-border/80 bg-surface/25 py-20 sm:py-24">
          <div className="mx-auto grid max-w-7xl gap-10 px-4 sm:px-6 lg:grid-cols-[0.7fr_1.3fr] lg:gap-20 lg:px-8">
            <div><p className="text-xs font-semibold uppercase tracking-[0.2em] text-primary">Technical foundation</p><h2 className="mt-4 text-3xl font-semibold tracking-tight text-foreground">Local-first by design.</h2><p className="mt-4 max-w-sm text-sm leading-6 text-muted-foreground">A small, inspectable path keeps the privacy boundary clear: browser to API, parser to rules and calibrated model, then back to a structured explanation.</p></div>
            <div className="grid gap-3 sm:grid-cols-2"><div className="border border-border bg-background/50 p-5"><p className="text-xs font-semibold uppercase tracking-[0.16em] text-foreground0">Frontend</p><p className="mt-3 text-lg font-semibold text-foreground">Next.js + TypeScript</p><p className="mt-2 text-sm leading-6 text-foreground0">Responsive workspace, typed API client, accessible status and result states.</p></div><div className="border border-border bg-background/50 p-5"><p className="text-xs font-semibold uppercase tracking-[0.16em] text-foreground0">Backend</p><p className="mt-3 text-lg font-semibold text-foreground">FastAPI inference API</p><p className="mt-2 text-sm leading-6 text-foreground0">RFC822 parsing, deterministic indicators, model registry verification, and health reporting.</p></div><div className="border border-border bg-background/50 p-5 sm:col-span-2"><p className="text-xs font-semibold uppercase tracking-[0.16em] text-foreground0">Privacy boundary</p><p className="mt-3 text-lg font-semibold text-foreground">No raw-email persistence</p><p className="mt-2 text-sm leading-6 text-foreground0">The analysis workflow does not render HTML, follow URLs, execute attachments, or store submitted content. Results are for human review, not a guarantee of safety.</p></div></div>
          </div>
        </section>

        <section id="how-to-use" className="border-b border-border/80 bg-surface/25 py-20 sm:py-24">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="max-w-2xl">
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-primary">How to use</p>
              <h2 className="mt-4 text-3xl font-semibold tracking-tight text-foreground">Move from email submission to a documented decision.</h2>
              <p className="mt-4 text-sm leading-6 text-muted-foreground">Follow the same practical workflow for every suspicious message, from choosing the right input to exporting the final report.</p>
            </div>
            <ol className="mt-12 grid border-l border-t border-border md:grid-cols-2">
              {howToUseSteps.map((item, index) => (
                <li key={item.title} className="grid min-h-36 grid-cols-[44px_1fr] gap-4 border-b border-r border-border p-5 sm:p-6">
                  <div>
                    <span className="flex h-10 w-10 items-center justify-center rounded-md border border-border bg-background text-primary"><item.icon size={18} aria-hidden="true" /></span>
                    <span className="mt-3 block text-xs font-semibold tabular-nums text-muted-foreground">{String(index + 1).padStart(2, '0')}</span>
                  </div>
                  <div><h3 className="font-semibold text-foreground">{item.title}</h3><p className="mt-2 text-sm leading-6 text-muted-foreground">{item.description}</p></div>
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section id="privacy" className="py-20 sm:py-24">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="border border-input bg-surface px-6 py-8 sm:px-10 sm:py-10">
              <div className="grid gap-8 lg:grid-cols-[0.8fr_1.2fr] lg:items-center">
                <div>
                  <div className="flex items-center gap-3 text-success">
                    <LockKeyhole size={22} aria-hidden="true" />
                    <span className="text-xs font-semibold uppercase tracking-[0.2em]">Privacy by design</span>
                  </div>
                  <h2 className="mt-4 text-2xl font-semibold tracking-tight text-foreground">Inspect safely. Retain control.</h2>
                </div>
                <div className="grid gap-4 sm:grid-cols-3">
                  {['No attachment execution', 'No URL fetching', 'Files are not stored by default'].map((statement) => (
                    <div key={statement} className="flex items-start gap-3 text-sm leading-6 text-muted-foreground">
                      <ShieldCheck size={17} className="mt-1 shrink-0 text-success" aria-hidden="true" />
                      <span>{statement}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="border-t border-border/80 py-16">
          <div className="mx-auto flex max-w-7xl flex-col items-start justify-between gap-8 px-4 sm:px-6 md:flex-row md:items-center lg:px-8">
            <div>
              <p className="text-2xl font-semibold tracking-tight text-foreground">Ready to inspect a suspicious email?</p>
              <p className="mt-2 text-sm text-muted-foreground">Get an explainable assessment without creating an account.</p>
            </div>
            <Button asChild size="lg" className="bg-primary text-primary-foreground hover:bg-primary">
              <Link href="/analyze">
                Start analysis
                <ArrowRight aria-hidden="true" />
              </Link>
            </Button>
          </div>
        </section>
      </main>

      <footer className="border-t border-border bg-background">
        <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6 lg:px-8">
          <div className="flex flex-col justify-between gap-8 md:flex-row md:items-center">
            <div className="flex items-center gap-2.5">
              <span className="flex h-8 w-8 items-center justify-center rounded-md border border-border text-primary">
                <ShieldAlert size={18} aria-hidden="true" />
              </span>
              <div>
              <p className="text-sm font-semibold text-foreground">PhishShield AI</p>
                <p className="mt-0.5 text-xs text-muted-foreground">Explainable phishing detection</p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-x-6 gap-y-3 text-sm text-foreground0">
              <a href="https://github.com/Nitin-Polistya/phishphage-ai" target="_blank" rel="noreferrer" className="theme-link rounded-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">GitHub repository</a>
              <span className="flex items-center gap-1.5"><BookOpen size={14} aria-hidden="true" />Docs in repository</span>
              <span className="flex items-center gap-1.5"><BadgeCheck size={14} aria-hidden="true" />Release candidate</span>
            </div>
          </div>
          <Separator className="my-8 bg-surface-muted" />
          <div className="flex flex-col justify-between gap-2 text-xs text-muted-foreground sm:flex-row">
            <p>Built for transparent, evidence-led email security analysis.</p>
            <p>PhishShield AI · Project information</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
