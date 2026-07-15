import type { Metadata } from 'next';

import { SettingsWorkspace } from '@/components/settings/settings-workspace';
import packageMetadata from '@/package.json';

export const metadata: Metadata = { title: 'Settings' };

export default function SettingsPage() {
  return <SettingsWorkspace frontendVersion={packageMetadata.version} />;
}
