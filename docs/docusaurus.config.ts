import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'PySentry',
  tagline: 'Fast, reliable security vulnerability scanner for Python projects',
  favicon: 'img/favicon.ico',

  future: {
    v4: true,
  },

  url: 'https://docs.pysentry.com',
  baseUrl: '/',

  organizationName: 'nyudenkov',
  projectName: 'pysentry',
  trailingSlash: false,

  onBrokenLinks: 'throw',

  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  plugins: [
    [
      '@cmfcmf/docusaurus-search-local',
      {
        indexDocs: true,
        indexBlog: false,
        language: 'en',
      },
    ],
  ],

  presets: [
    [
      'classic',
      {
        docs: {
          routeBasePath: '/',
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/nyudenkov/pysentry/tree/main/docs/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: 'img/pysentry-social-card.jpg',
    colorMode: {
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'PySentry',
      logo: {
        alt: 'PySentry Logo',
        src: 'img/logo.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docs',
          position: 'left',
          label: 'Documentation',
        },
        {
          href: 'https://github.com/nyudenkov/pysentry',
          label: 'GitHub',
          position: 'right',
        },
        {
          href: 'https://pypi.org/project/pysentry-rs/',
          label: 'PyPI',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {
              label: 'Getting Started',
              to: '/getting-started/installation',
            },
            {
              label: 'Configuration',
              to: '/configuration/config-files',
            },
            {
              label: 'CLI Options',
              to: '/configuration/cli-options',
            },
          ],
        },
        {
          title: 'Resources',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/nyudenkov/pysentry',
            },
            {
              label: 'PyPI',
              href: 'https://pypi.org/project/pysentry-rs/',
            },
            {
              label: 'Crates.io',
              href: 'https://crates.io/crates/pysentry',
            },
          ],
        },
        {
          title: 'Community',
          items: [
            {
              label: 'Issues',
              href: 'https://github.com/nyudenkov/pysentry/issues',
            },
            {
              label: 'Discussions',
              href: 'https://github.com/nyudenkov/pysentry/discussions',
            },
          ],
        },
      ],
      copyright: `Copyright ${new Date().getFullYear()} PySentry. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['bash', 'toml', 'yaml', 'json', 'rust', 'python'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
